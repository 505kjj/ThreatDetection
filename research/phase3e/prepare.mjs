import { createReadStream } from 'node:fs';
import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { extractUrl, featureColumns, featureVersion, sha256 } from '../../evaluation/features.mjs';
import { detectImpersonation } from '../../extension/impersonation.mjs';
import { official } from '../../extension/tests/impersonation-fixtures.mjs';
import { campaignProxy } from '../phase3d/partition.mjs';

export const domainDigest = group => sha256('phase3b-group\0' + group);
const digestPattern = /^[0-9a-f]{64}$/;
const phase3cReport = new URL('../../docs/experiments/phase3c/research.json', import.meta.url);
const phase3dReport = new URL('../../docs/experiments/phase3d/summary.json', import.meta.url);

async function json(path) {
  return JSON.parse(await readFile(path, 'utf8'));
}

async function addPrior(folder, name, spec, includeFamily, index) {
  const read = createReadStream(join(folder, name + '.tsv'));
  const hash = createHash('sha256');
  const groups = new Set();
  let rows = 0;
  read.on('data', bytes => hash.update(bytes));
  for await (const line of createInterface({ input: read })) {
    const domain = line.slice(2, 66);
    if (!digestPattern.test(domain) || line[66] !== '\t') throw new Error('Invalid prior domain digest');
    groups.add(domain);
    rows++;
    if (includeFamily) {
      const family = line.slice(67, line.indexOf('\t', 67));
      if (family) {
        if (!digestPattern.test(family)) throw new Error('Invalid prior family digest');
        index.families.add(family);
      }
    }
  }
  if (hash.digest('hex') !== spec.sha256 || spec.groups !== groups.size || rows !== spec.phishing + spec.legitimate) {
    throw new Error('Earlier private dataset does not match published metadata');
  }
  for (const group of groups) index.domains.add(group);
}

async function priorIndex(uci, phase3c, phase3d) {
  const index = { domains: new Set(), families: new Set() };
  for (const [folder, name] of [['development', 'train'], ['development', 'validation'], ['holdout', 'test']]) {
    const path = join(uci, folder);
    const manifest = await json(join(path, 'manifest.json'));
    if (manifest.dataset !== 'phiusiil-uci-967' || manifest.splitSeed !== 'phase3a-v1') {
      throw new Error('Unexpected original research export');
    }
    if (name === 'test' && manifest[name].sha256 !== 'dbcb0f0a28c788fdf16fefe6ae0d12d06b77bce4e2c952a3fc77c0c89bec6bfa') {
      throw new Error('Original holdout digest changed');
    }
    await addPrior(path, name, manifest[name], false, index);
  }
  const earlier = await json(phase3cReport);
  for (const [name, spec] of Object.entries(earlier.source.partitions)) {
    await addPrior(phase3c, name, spec, false, index);
  }
  const previous = await json(phase3dReport);
  for (const [name, spec] of Object.entries(previous.dataset.partitions)) {
    await addPrior(phase3d, name, spec, true, index);
  }
  // The Phase 3D financial-control path hosts are covered by the same official list.
  for (const host of official) {
    const parsed = extractUrl('https://' + host, 'real');
    if (!parsed) throw new Error('An earlier official control no longer parses');
    index.domains.add(domainDigest(parsed.group));
    const family = campaignProxy(parsed.group);
    if (family) index.families.add(family);
  }
  return index;
}

export function project(record, limits, kind = 'real') {
  const { id, url, label, observedDay, source, brand, evidence, campaign, cohort } = record;
  const parsed = extractUrl(url, kind);
  const date = new Date(observedDay);
  if (!parsed || !Number.isFinite(+date) || date.toISOString().slice(0, 10) !== observedDay ||
      observedDay < limits.firstDay || observedDay > limits.lastDay || ![0, 1].includes(label) ||
      typeof id !== 'string' || !/^[a-z0-9-]{1,60}$/.test(id) ||
      typeof brand !== 'string' || !/^[a-z0-9-]{1,35}$/.test(brand) || !['external', 'india-control'].includes(cohort) ||
      typeof evidence !== 'string' || !evidence || !['phishvn-ncsc', 'phishvn-trusted', 'official-india'].includes(source)) {
    return null;
  }
  const urlObject = new URL(url);
  if (urlObject.username || urlObject.password) return null;
  if (cohort === 'india-control' && (source !== 'official-india' || label !== 0 || urlObject.search || urlObject.hash)) return null;
  if (cohort === 'external' && (source === 'official-india' || label !== Number(source === 'phishvn-ncsc'))) return null;
  const queryless = new URL('https://' + parsed.host.replace(/^www\./, '') + (urlObject.port ? ':' + urlObject.port : '') + urlObject.pathname);
  return {
    candidate: { id, y: label, date: observedDay, source, cohort, brand,
      group: domainDigest(parsed.group), family: campaignProxy(parsed.group),
      campaign: campaign ? sha256('phase3e-campaign\0' + source + '\0' + campaign) : null,
      amber: detectImpersonation(parsed.host).length > 0, x: parsed.features },
    key: sha256(queryless.toString()),
  };
}

export function filterRows(rows, prior, window, kind = 'real') {
  const audit = { input: rows.length, invalid: 0, priorDomain: 0, priorFamily: 0, duplicates: 0, conflicting: 0, controlOverlap: 0 };
  const retained = new Map();
  const rejected = new Set();
  for (const raw of rows) {
    const row = project(raw, window, kind);
    if (!row) {
      audit.invalid++;
      continue;
    }
    const { candidate, key } = row;
    if (prior.domains.has(candidate.group)) {
      audit.priorDomain++;
      continue;
    }
    if (candidate.family && prior.families.has(candidate.family)) {
      audit.priorFamily++;
      continue;
    }
    const previous = retained.get(key);
    if (rejected.has(key) || previous) {
      audit.duplicates++;
      if (previous && previous.y !== candidate.y) {
        audit.conflicting++;
        retained.delete(key);
        rejected.add(key);
      }
      continue;
    }
    retained.set(key, candidate);
  }
  const values = [...retained.values()];
  const externalGroups = new Set(values.filter(row => row.cohort === 'external').map(row => row.group));
  const output = values.filter(row => {
    if (row.cohort === 'india-control' && externalGroups.has(row.group)) {
      audit.controlOverlap++;
      return false;
    }
    return true;
  });
  return { output, audit };
}

export async function prepare({ uci, phase3c, phase3d, ledger, outputPath, protocol }) {
  const previous = await priorIndex(uci, phase3c, phase3d);
  const raw = [];
  for await (const line of createInterface({ input: createReadStream(ledger) })) {
    if (line.length > 16_384 || raw.length >= 60_000) throw new Error('Private ledger exceeded its budget');
    raw.push(JSON.parse(line));
  }
  const { output, audit } = filterRows(raw, previous, protocol.window);
  const ids = new Set(output.map(row => row.id));
  if (ids.size !== output.length) throw new Error('Duplicate record identifiers');
  const content = output.map(row => JSON.stringify(row)).join('\n') + '\n';
  await writeFile(outputPath, content, { flag: 'wx', mode: 0o600 });
  return { sha256: sha256(content), counts: audit, priorDomains: previous.domains.size,
    priorLexicalFamilies: previous.families.size, featureColumns, featureVersion };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const [uci, phase3c, phase3d, ledger, outputPath, protocolFile] = process.argv.slice(2);
    const relativeOutput = relative(fileURLToPath(new URL('../../', import.meta.url)), resolve(outputPath));
    if (process.env.THREAT_PHASE3D_GUARDED !== '1' ||
        (!isAbsolute(relativeOutput) && !relativeOutput.startsWith('..' + sep))) {
      throw new Error('Projection requires a guarded worker and private output');
    }
    const result = await prepare({ uci, phase3c, phase3d, ledger, outputPath, protocol: await json(protocolFile) });
    process.stdout.write(JSON.stringify(result) + '\n');
  } catch {
    process.stderr.write('Could not verify the private cohort projection.\n');
    process.exitCode = 1;
  }
}
