import { createHash } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import { mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { extractUrl } from '../../evaluation/features.mjs';
import { detectImpersonation } from '../../extension/impersonation.mjs';
import { campaignProxy, developmentPartitions } from '../phase3d/partition.mjs';
import { domainDigest } from '../phase3e/prepare.mjs';
import { observation } from '../phase3g/validate.mjs';
import { assertOutsideGit } from '../phase5a/run.mjs';
import { rows } from './cohort.mjs';

// These four official train shards belong to the earlier Phase 3C projection.
const skipped = new Set([0, 18, 37, 55]);
const json = async path => JSON.parse(await readFile(path, 'utf8'));

async function replay([input, custody, pin, phase5b, destination]) {
  const source = await json(join(input, 'manifest.json'));
  const legacy = await json(phase5b);
  const published = await json(new URL('../../docs/experiments/phase3d/summary.json', import.meta.url));
  const testGroups = new Set();
  const testFamilies = new Set();
  const ignored = new Set();
  let firstTest;
  for await (const row of rows(custody, pin)) {
    if (row.firstTest) firstTest = row.firstTest;
    if (row.group) testGroups.add(row.group);
    if (row.family) testFamilies.add(row.family);
    if (row.ignore) ignored.add(row.ignore);
  }
  if (!observation(firstTest) || !testGroups.size || !testFamilies.size || !ignored.size ||
      source.revision !== 'eca603e0ecd4f698f8d4d226c088659e72681239' || source.side !== 'train' ||
      source.shards.length !== 56) throw new Error('Replay prerequisites differ');
  const candidates = new Map();
  const brand = new Map();
  for (const [i, shard] of source.shards.entries()) {
    if (skipped.has(i)) continue;
    const expected = 'train-' + String(i).padStart(3, '0') + '.jsonl';
    if (shard.file !== expected) throw new Error('Unexpected replay shard');
    for await (const raw of rows(join(input, shard.file), shard.projectedSha256, shard.rows)) {
      if (!['phish', 'benign'].includes(raw.label) || observation(raw.date)?.precision !== 'day') continue;
      const parsed = extractUrl(raw.url, 'real');
      if (!parsed) continue;
      const group = domainDigest(parsed.group);
      if (ignored.has(group)) continue;
      if (!brand.has(parsed.host)) brand.set(parsed.host, Number(detectImpersonation(parsed.host).length > 0));
      const label = Number(raw.label === 'phish');
      const prior = candidates.get(parsed.keyHash);
      const conflict = prior && (prior.conflict || prior.label !== label);
      if (prior && !conflict && prior.date <= raw.date) continue;
      candidates.set(parsed.keyHash, { side: 'train', date: raw.date, label, group,
        family: campaignProxy(parsed.group), brand: brand.get(parsed.host), vector: parsed.features,
        conflict, sourceId: raw.sha256, url: raw.url });
    }
  }
  const splits = developmentPartitions([...candidates.values()].filter(row => !row.conflict),
    firstTest, testGroups, testFamilies);
  const report = { revision: source.revision, verified: true, partitions: {} };
  for (const [name, members] of Object.entries(splits)) {
    const hash = createHash('sha256');
    for (const row of members) hash.update([row.label, row.group, row.family, row.brand, ...row.vector].join('\t') + '\n');
    const sha256 = hash.digest('hex');
    const reference = published.dataset.partitions[name];
    const expected = name === 'train' ? legacy.phreshTrainSha256 : legacy.phreshValidationSha256;
    const verified = sha256 === expected && sha256 === reference.sha256 && members.length === reference.rows;
    report.verified &&= verified;
    report.partitions[name] = { rows: members.length, referenceRows: reference.rows, sha256, expected, verified };
  }
  await mkdir(destination, { mode: 0o700 });
  if (report.verified) {
    for (const [name, members] of Object.entries(splits)) {
      const sourceIds = new Set(members.map(row => row.sourceId));
      if (sourceIds.size !== members.length) throw new Error('Ambiguous publisher record ID in replay');
      await pipeline(Readable.from(members.map(row => JSON.stringify(row) + '\n')),
        createWriteStream(join(destination, name + '.jsonl'), { flags: 'wx', mode: 0o600 }));
    }
  }
  await writeFile(join(destination, 'report.json'), JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  console.log(JSON.stringify(report));
}

try {
  const args = process.argv.slice(2);
  if (args.length !== 5 || process.env.THREAT_PHASE3D_GUARDED !== '1') throw new Error('Invalid replay invocation');
  for (const index of [0, 1, 3]) args[index] = await assertOutsideGit(await realpath(args[index]));
  await assertOutsideGit(await realpath(dirname(resolve(args[4]))));
  await replay(args);
} catch (error) {
  console.error('Legacy reconstruction stopped at an input, path or integrity check (' + error.name + ').');
  process.exitCode = 1;
}
