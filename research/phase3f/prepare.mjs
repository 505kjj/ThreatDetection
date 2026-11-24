import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { basename, dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { extractUrl, featureColumns, featureVersion, sha256 } from '../../evaluation/features.mjs';
import { detectImpersonation } from '../../extension/impersonation.mjs';
import { campaignProxy } from '../phase3d/partition.mjs';
import { domainDigest, priorIndex } from '../phase3e/prepare.mjs';

const previous = new URL('../../docs/experiments/phase3e/summary.json', import.meta.url);
const reference = new URL('../../docs/experiments/phase3d/summary.json', import.meta.url);
const spec = new URL('./protocol.json', import.meta.url);
const digestFormat = /^[a-f0-9]{64}$/;

async function json(path) {
  return JSON.parse(await readFile(path, 'utf8'));
}

async function digest(path) {
  const hash = createHash('sha256');
  for await (const part of createReadStream(path)) hash.update(part);
  return hash.digest('hex');
}

async function addPhase3e(index, dataPath) {
  const phase3e = await json(previous);
  const source = createReadStream(dataPath);
  const hash = createHash('sha256');
  const domains = new Set();
  let added = 0;
  source.on('data', bytes => hash.update(bytes));
  for await (const line of createInterface({ input: source })) {
    if (!line) continue;
    const { group, family } = JSON.parse(line);
    if (!digestFormat.test(group) || (family && !digestFormat.test(family))) throw new Error('Invalid 3E identity');
    domains.add(group);
    index.domains.add(group);
    if (family) index.families.add(family);
    added++;
  }
  const expected = phase3e.cohorts['india-control'].support;
  if (hash.digest('hex') !== phase3e.freeze.projection.sha256 || added !== expected.legitimate + expected.phishing ||
      domains.size !== expected.domains) throw new Error('Earlier 3E control identities failed integrity');
  return domains.size;
}

export function project(row, kind = 'real') {
  if (typeof row.id !== 'string' || !/^[a-z0-9-]{1,60}$/.test(row.id) ||
      typeof row.evidence !== 'string' || typeof row.license !== 'string' || !row.license) return null;
  const day = new Date(row.observedDay);
  if (!Number.isFinite(+day) || day.toISOString().slice(0, 10) !== row.observedDay) return null;
  const control = row.cohort === 'india-control' && row.label === 0 && row.source === 'official-india' &&
    typeof row.brand === 'string' && /^[a-z0-9-]{1,35}$/.test(row.brand) &&
    ['login', 'checkout', 'verification', 'security', 'payment', 'banking'].includes(row.kind);
  const verifiedArchive = row.cohort === 'general-transfer' && row.label === 1 &&
    /^phishtank-archive-\d+$/.test(row.source) && row.sourceVerdict === 'VALID PHISH' &&
    row.brand === null && row.campaign === null;
  if (!control && !verifiedArchive) return null;
  const parsed = extractUrl(row.url, kind);
  if (!parsed) return null;
  const address = new URL(row.url);
  if (address.username || address.password || (control && (address.protocol !== 'https:' || address.search || address.hash))) {
    return null;
  }
  const key = sha256(parsed.host.replace(/^www\./, '') + '\0' + address.port + '\0' + address.pathname);
  return {
    key, id: row.id, y: row.label, cohort: row.cohort, date: row.observedDay, brand: row.brand, kind: row.kind,
    source: row.source, group: domainDigest(parsed.group), family: campaignProxy(parsed.group),
    amber: detectImpersonation(parsed.host).length > 0, x: parsed.features,
  };
}

export function filter(rows, index, ceiling, kind = 'real') {
  const byCohort = Object.create(null);
  const collected = new Map();
  const conflicts = new Set();
  for (const row of rows) {
    const audit = byCohort[row.cohort] ??= { input: 0, rejected: 0, priorDomain: 0, priorFamily: 0, duplicate: 0,
      conflicting: 0, crossCohortDomain: 0, repeatedDomain: 0, repeatedLexicalFamily: 0, beyondCap: 0, retained: 0 };
    audit.input++;
    const record = project(row, kind);
    if (!record) {
      audit.rejected++;
      continue;
    }
    if (index.domains.has(record.group)) {
      audit.priorDomain++;
      continue;
    }
    if (record.family && index.families.has(record.family)) {
      audit.priorFamily++;
      continue;
    }
    if (conflicts.has(record.key)) {
      audit.duplicate++;
      continue;
    }
    const existing = collected.get(record.key);
    if (existing) {
      if (existing.y !== record.y) {
        byCohort[existing.cohort].conflicting++;
        audit.conflicting++;
        collected.delete(record.key);
        conflicts.add(record.key);
      } else {
        audit.duplicate++;
      }
      continue;
    }
    collected.set(record.key, record);
  }
  const controls = [...collected.values()].filter(row => row.cohort === 'india-control');
  const controlGroups = new Set(controls.map(row => row.group));
  const controlFamilies = new Set(controls.map(row => row.family).filter(Boolean));
  const archive = [...collected.values()].filter(row => row.cohort === 'general-transfer')
    .map(row => [sha256('phase3f-domain-selection\0' + row.key), row])
    .sort(([a], [b]) => a.localeCompare(b, 'en'));
  const selected = [];
  const domains = new Set();
  const lexicalFamilies = new Set();
  for (const [, row] of archive) {
    const audit = byCohort['general-transfer'];
    if (controlGroups.has(row.group) || (row.family && controlFamilies.has(row.family))) {
      audit.crossCohortDomain++;
    } else if (domains.has(row.group)) {
      audit.repeatedDomain++;
    } else if (row.family && lexicalFamilies.has(row.family)) {
      audit.repeatedLexicalFamily++;
    } else {
      domains.add(row.group);
      if (row.family) lexicalFamilies.add(row.family);
      if (selected.length < ceiling) selected.push(row);
      else audit.beyondCap++;
    }
  }
  const output = [...controls, ...selected].map(({ key, ...safe }) => safe);
  for (const row of output) byCohort[row.cohort].retained++;
  if (new Set(output.map(row => row.id)).size !== output.length) throw new Error('Duplicate selected evidence IDs');
  return { output, byCohort };
}

async function run(args) {
  if (process.env.THREAT_PHASE3D_GUARDED !== '1') throw new Error('Resource guard required');
  const [uci, phase3c, phase3d, phase3e, controls, archiveDir, output] = args;
  const folder = resolve(await realpath(dirname(resolve(output))), basename(output));
  const rel = relative(fileURLToPath(new URL('../../', import.meta.url)), folder);
  if (!isAbsolute(rel) && !rel.startsWith('..' + sep)) throw new Error('Out-of-worktree output required');
  const config = await json(spec);
  const original = await json(reference);
  if (featureVersion !== config.featureVersion ||
      JSON.stringify(featureColumns) !== JSON.stringify(original.dataset.featureColumns)) throw new Error('Schema differs');
  const earlier = await priorIndex(uci, phase3c, phase3d);
  const phase3eDomains = await addPhase3e(earlier, phase3e);
  const ledger = resolve(archiveDir, 'archive-ledger.jsonl');
  const archiveInventory = await json(resolve(archiveDir, 'inventory.json'));
  const archiveLedgerSha256 = await digest(ledger);
  if (archiveLedgerSha256 !== archiveInventory.ledgerSha256 ||
      Object.values(config.archive.files).some(file => archiveInventory.files[file.id]?.sha256 !== file.sha256)) {
    throw new Error('Archive ledger or workbook pin differs');
  }
  const rows = [];
  for (const path of [controls, ledger]) {
    for await (const line of createInterface({ input: createReadStream(path) })) {
      if (line.length > 18000 || rows.length >= 240000) throw new Error('Input limit exceeded');
      rows.push(JSON.parse(line));
    }
  }
  const { output: values, byCohort } = filter(rows, earlier, config.limits.archivalDomainLimit);
  if (!values.length) throw new Error('No eligible records');
  const payload = values.map(row => JSON.stringify(row)).join('\n') + '\n';
  const manifest = {
    protocolSha256: await digest(spec), phase3dSummarySha256: await digest(reference), phase3eSummarySha256: await digest(previous),
    priorDomains: earlier.domains.size, priorLexicalFamilies: earlier.families.size, phase3eDomains,
    controlsSha256: await digest(controls), archiveLedgerSha256,
    numericSha256: sha256(payload), featureVersion, featureColumns, archive: archiveInventory.files, byCohort,
  };
  await mkdir(folder);
  await writeFile(resolve(folder, 'numeric.jsonl'), payload, { flag: 'wx', mode: 0o600 });
  await writeFile(resolve(folder, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx' });
  console.log(JSON.stringify(byCohort));
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    await run(process.argv.slice(2));
  } catch {
    console.error('Private Phase 3F projection failed a source, identity, path or size check.');
    process.exitCode = 1;
  }
}
