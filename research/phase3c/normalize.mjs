import { createReadStream } from 'node:fs';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { join, relative, resolve, isAbsolute, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline';
import { extractUrl, featureColumns, featureVersion, sha256 } from '../../evaluation/features.mjs';
import { detectImpersonation } from '../../extension/impersonation.mjs';

const groupFor = group => sha256('phase3b-group\0' + group);

async function uciGroups(directory) {
  const files = [['development','train'], ['development','validation'], ['holdout','test']];
  const groups = new Set();
  for (const [folder, name] of files) {
    const meta = JSON.parse(await readFile(join(directory, folder, 'manifest.json'), 'utf8'));
    const expected = meta[name];
    if (meta.dataset !== 'phiusiil-uci-967' || meta.splitSeed !== 'phase3a-v1' || expected.file !== name + '.tsv') {
      throw new Error('Phase 3B partition metadata differs');
    }
    const input = createReadStream(join(directory, folder, expected.file));
    const hash = createHash('sha256');
    input.on('data', chunk => hash.update(chunk));
    for await (const row of createInterface({ input })) {
      // Read only the group column, including for the original holdout. No scoring or label use.
      groups.add(row.slice(2, 66));
    }
    if (hash.digest('hex') !== expected.sha256) throw new Error('Phase 3B partition checksum differs');
  }
  return groups;
}

async function main() {
  const [uci, destination] = process.argv.slice(2);
  const output = resolve(destination);
  const repo = fileURLToPath(new URL('../../', import.meta.url));
  const rel = relative(repo, output);
  if (!rel || (rel !== '..' && !rel.startsWith('..' + sep) && !isAbsolute(rel))) throw new Error('Private output must be outside Git');
  const seen = await uciGroups(uci);
  const records = new Map();
  const brand = new Map();
  const counts = { input: 0, invalid: 0, uciGroupRows: 0, duplicateUrls: 0, conflictingUrls: 0 };
  const overlappingGroups = new Set();
  for await (const line of createInterface({ input: process.stdin })) {
    const [side, label, date, url] = JSON.parse(line);
    counts.input++;
    const ms = Date.parse(date);
    const parsed = extractUrl(url, 'real');
    if (!parsed || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(date) || !Number.isFinite(ms) ||
        new Date(ms).toISOString().slice(0, 10) !== date || !['train', 'test'].includes(side) ||
        !['phish', 'benign'].includes(label)) {
      counts.invalid++;
      continue;
    }
    const group = groupFor(parsed.group);
    if (seen.has(group)) {
      counts.uciGroupRows++;
      overlappingGroups.add(group);
      continue;
    }
    const next = { side, date, label, group, vector: parsed.features };
    if (!brand.has(parsed.host)) brand.set(parsed.host, Number(detectImpersonation(parsed.host).length > 0));
    next.brand = brand.get(parsed.host);
    const prior = records.get(parsed.keyHash);
    if (prior) {
      counts.duplicateUrls++;
      if (prior.conflict || prior.label !== label) next.conflict = true;
      if (!next.conflict && (prior.side === 'test' || prior.side === side && prior.date <= date)) continue;
    }
    records.set(parsed.keyHash, next);
  }
  const rows = [...records.values()].filter(row => {
    if (row.conflict) counts.conflictingUrls++;
    return !row.conflict;
  });
  const test = rows.filter(row => row.side === 'test');
  if (!test.length) throw new Error('No independent external samples');
  const oldestTest = test.reduce((date, row) => row.date < date ? row.date : date, test[0].date);
  const testGroups = new Set(test.map(row => row.group));
  const eligible = rows.filter(row => row.side === 'train' && row.date < oldestTest && !testGroups.has(row.group));
  const days = [...new Set(eligible.map(row => row.date))].sort();
  if (days.length < 2) throw new Error('Insufficient chronological development dates');
  const cutoff = days[Math.floor(days.length * 0.75)];
  const train = eligible.filter(row => row.date < cutoff);
  const trainingGroups = new Set(train.map(row => row.group));
  const calibration = eligible.filter(row => row.date >= cutoff && !trainingGroups.has(row.group));
  await mkdir(output);
  const partitions = {};
  for (const [name, data] of Object.entries({ train, calibration, test })) {
    if (!data.some(r => r.label === 'phish') || !data.some(r => r.label === 'benign')) throw new Error('Partition lacks a class');
    const bytes = data.map(row => [Number(row.label === 'phish'), row.group, row.brand, ...row.vector].join('\t')).join('\n') + '\n';
    await writeFile(join(output, name + '.tsv'), bytes, { flag: 'wx', mode: 0o600 });
    const dates = data.map(row => row.date).sort();
    const phishing = data.filter(row => row.label === 'phish').length;
    partitions[name] = { sha256: sha256(bytes), rows: data.length, phishing, legitimate: data.length - phishing,
      groups: new Set(data.map(row => row.group)).size, firstDay: dates[0], lastDay: dates.at(-1) };
  }
  const manifest = { featureColumns, featureVersion, counts, uciGroups: seen.size,
    overlappingUciGroups: overlappingGroups.size, validIndependentRows: rows.length,
    developmentExcluded: rows.filter(r => r.side === 'train').length - train.length - calibration.length,
    partitions };
  await writeFile(join(output, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  process.stdout.write(JSON.stringify(manifest) + '\n');
}

main().catch(() => {
  process.stderr.write('Cannot normalize the pinned metadata projection or its chronological groups.\n');
  process.exitCode = 1;
});
