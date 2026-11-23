import { createReadStream, createWriteStream } from 'node:fs';
import { mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { createInterface } from 'node:readline';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { extractUrl, featureColumns, featureVersion, sha256 } from '../../evaluation/features.mjs';
import { detectImpersonation } from '../../extension/impersonation.mjs';

const groupFor = group => sha256('phase3b-group\0' + group);
const oldReport = new URL('../../docs/experiments/phase3c/research.json', import.meta.url);

async function verifiedGroups(path, spec) {
  const source = createReadStream(path);
  const digest = createHash('sha256');
  const groups = new Set();
  source.on('data', bytes => digest.update(bytes));
  let rows = 0;
  for await (const row of createInterface({ input: source })) {
    // Prior holdouts contribute only domain digests and file integrity.
    const group = row.slice(2, 66);
    if (!/^[0-9a-f]{64}$/.test(group) || row[66] !== '\t') throw new Error('Bad group index');
    groups.add(group);
    rows++;
  }
  if (digest.digest('hex') !== spec.sha256 || rows !== spec.phishing + spec.legitimate || groups.size !== spec.groups) {
    throw new Error('Prior partition failed integrity');
  }
  return groups;
}

export function campaignProxy(group) {
  // A conservative cross-TLD lexical family, not a provider-assigned campaign.
  const name = group.split('.')[0].replace(/[-0-9]/g, '');
  return /^[a-z]{8,}$/.test(name) ? sha256('phase3d-family\0' + name) : '';
}

export function partition(records) {
  const test = records.filter(r => r.side === 'test');
  if (!test.length) throw new Error('No fresh test data');
  const firstTest = test.reduce((day, r) => r.date < day ? r.date : day, test[0].date);
  const testGroups = new Set(test.map(r => r.group));
  const testFamilies = new Set(test.map(r => r.family).filter(Boolean));
  const development = records.filter(r => r.side === 'train' && r.date < firstTest &&
    !testGroups.has(r.group) && (!r.family || !testFamilies.has(r.family)));
  const days = [...new Set(development.map(r => r.date))].sort();
  if (days.length < 2) throw new Error('No chronological development split');
  const cutoff = days[Math.floor(days.length * 0.75)];
  const validation = development.filter(r => r.date >= cutoff);
  const validationGroups = new Set(validation.map(r => r.group));
  const validationFamilies = new Set(validation.map(r => r.family).filter(Boolean));
  const train = development.filter(r => r.date < cutoff && !validationGroups.has(r.group) &&
    (!r.family || !validationFamilies.has(r.family)));
  return { train, validation, test };
}

async function writePartition(folder, name, rows) {
  if (!rows.some(r => r.label) || !rows.some(r => !r.label)) throw new Error('Partition lacks a class');
  const file = createWriteStream(join(folder, name + '.tsv'), { flags: 'wx', mode: 0o600 });
  const digest = createHash('sha256');
  let phishing = 0;
  let firstDay = rows[0].date;
  let lastDay = rows[0].date;
  for (const row of rows) {
    const line = [row.label, row.group, row.family, row.brand, ...row.vector].join('\t') + '\n';
    digest.update(line);
    if (!file.write(line)) await once(file, 'drain');
    phishing += row.label;
    if (row.date < firstDay) firstDay = row.date;
    if (row.date > lastDay) lastDay = row.date;
  }
  file.end();
  await once(file, 'finish');
  return {
    sha256: digest.digest('hex'), rows: rows.length, phishing, legitimate: rows.length - phishing,
    groups: new Set(rows.map(r => r.group)).size, firstDay, lastDay,
  };
}

async function main() {
  if (process.env.THREAT_PHASE3D_GUARDED !== '1') throw new Error('Projection needs the resource guard');
  const [uci, phase3c, destination] = process.argv.slice(2);
  const output = join(await realpath(dirname(resolve(destination))), resolve(destination).split(sep).at(-1));
  const repo = await realpath(fileURLToPath(new URL('../../', import.meta.url)));
  const link = relative(repo, output);
  if (!link || (!isAbsolute(link) && !link.startsWith('..' + sep))) throw new Error('Private output required');
  const uciGroups = new Set();
  for (const [folder, name] of [['development', 'train'], ['development', 'validation'], ['holdout', 'test']]) {
    const manifest = JSON.parse(await readFile(join(uci, folder, 'manifest.json'), 'utf8'));
    if (manifest.dataset !== 'phiusiil-uci-967' || manifest.splitSeed !== 'phase3a-v1') throw new Error('Bad UCI metadata');
    const expected = manifest[name];
    const groups = await verifiedGroups(join(uci, folder, name + '.tsv'), expected);
    for (const group of groups) uciGroups.add(group);
  }
  const prior = JSON.parse(await readFile(oldReport, 'utf8')).source.partitions;
  const oldGroups = new Set();
  for (const [name, spec] of Object.entries(prior)) {
    const groups = await verifiedGroups(join(phase3c, name + '.tsv'), spec);
    for (const group of groups) oldGroups.add(group);
  }
  const counts = { input: 0, invalid: 0, uciDomainRows: 0, phase3cDomainRows: 0, canonicalDuplicates: 0, conflictingUrls: 0 };
  const records = new Map();
  const brands = new Map();
  for await (const line of createInterface({ input: process.stdin })) {
    counts.input++;
    const [side, label, date, url] = JSON.parse(line);
    const parsed = extractUrl(url, 'real');
    const time = new Date(date);
    if (!parsed || !['train', 'test'].includes(side) || !['phish', 'benign'].includes(label) ||
        !/^\d{4}-\d{2}-\d{2}$/.test(date) || !Number.isFinite(+time) || time.toISOString().slice(0, 10) !== date) {
      counts.invalid++;
      continue;
    }
    const group = groupFor(parsed.group);
    if (uciGroups.has(group)) {
      counts.uciDomainRows++;
      continue;
    }
    if (oldGroups.has(group)) {
      counts.phase3cDomainRows++;
      continue;
    }
    if (!brands.has(parsed.host)) brands.set(parsed.host, Number(detectImpersonation(parsed.host).length > 0));
    const row = { side, date, label: Number(label === 'phish'), group, family: campaignProxy(parsed.group),
      brand: brands.get(parsed.host), vector: parsed.features };
    const previous = records.get(parsed.keyHash);
    if (previous) {
      counts.canonicalDuplicates++;
      if (previous.conflict || previous.label !== row.label) row.conflict = true;
      if (!row.conflict && (previous.side === 'test' || previous.side === side && previous.date <= date)) continue;
    }
    records.set(parsed.keyHash, row);
  }
  const rows = [...records.values()].filter(r => {
    if (r.conflict) counts.conflictingUrls++;
    return !r.conflict;
  });
  const splits = partition(rows);
  await mkdir(output);
  const partitions = {};
  for (const [name, members] of Object.entries(splits)) partitions[name] = await writePartition(output, name, members);
  const manifest = { featureVersion, featureColumns, counts, partitions, uciExcludedGroups: uciGroups.size,
    phase3cExcludedGroups: oldGroups.size,
    timeAndFamilyExcluded: rows.length - Object.values(splits).reduce((n, r) => n + r.length, 0) };
  await writeFile(join(output, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  console.log(JSON.stringify({ counts, partitions: Object.fromEntries(Object.entries(partitions).map(([key, value]) => [key, value.rows])) }));
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch(() => {
    process.stderr.write('Cannot validate or partition the private projection.\n');
    process.exitCode = 1;
  });
}
