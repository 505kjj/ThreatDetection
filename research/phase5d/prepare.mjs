import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { sha256 } from '../../evaluation/features.mjs';
import { observation } from '../phase3g/validate.mjs';
import { components } from '../phase5a/prepare.mjs';
import { assertOutsideGit } from '../phase5a/run.mjs';
import { assertDisjoint, candidate, deduplicate, index, rows, writePartition } from '../phase5c/cohort.mjs';

const protocolBytes = (await readFile(new URL('./protocol.json', import.meta.url), 'utf8')).replace(/\r\n/g, '\n');
export const protocol = JSON.parse(protocolBytes);
const pins = JSON.parse(await readFile(new URL('../phase5c/source-pins.json', import.meta.url)));
const json = async path => JSON.parse(await readFile(path, 'utf8'));
const identityKeys = ['group', 'family', 'exact', 'alias'];
const byId = (a, b) => a.id.localeCompare(b.id);

export function temporal(input, cutoffs = protocol.temporalCutoffsUtc) {
  const names = protocol.temporalPartitions;
  const result = Object.fromEntries(names.map(name => [name, []]));
  let invalidDate = 0;
  let quarantined = 0;
  const dated = [];
  for (const row of input) {
    const day = observation(row.collectedAt);
    if (!day || day.precision !== 'day') {
      invalidDate++;
      continue;
    }
    const position = cutoffs.findIndex(cutoff => row.collectedAt < cutoff);
    dated.push({ ...row, position: position < 0 ? cutoffs.length : position });
  }
  for (const group of components(dated)) {
    const last = group.reduce((max, row) => Math.max(max, row.position), 0);
    for (const { position, ...row } of group) {
      if (position !== last) quarantined++;
      else result[names[last]].push({ ...row, partition: names[last] });
    }
  }
  for (const partition of Object.values(result)) partition.sort(byId);
  assertDisjoint(result);
  return { result, invalidDate, quarantined };
}

export function match(indexed, row) {
  return indexed.id.has(row.sourceId) || identityKeys.some(key => indexed[key].has(row.identity[key]));
}

function keyIndex(members) {
  const keys = Object.fromEntries(['id', ...identityKeys].map(key => [key, new Set()]));
  for (const row of members) {
    keys.id.add(row.sourceId);
    for (const key of identityKeys) if (row.identity[key]) keys[key].add(row.identity[key]);
  }
  return keys;
}

function balanced(rows, size) {
  const groups = [0, 1].map(label => rows.filter(row => row.label === label).slice(0, size / 2));
  if (groups.some(group => group.length !== size / 2)) throw new Error('Balanced capacity changed');
  return groups.flat().sort(byId);
}

export function fusionFit(train, trainSize = protocol.matchedFusionTrainingRows,
                          fitSize = protocol.fusionFitMaximumRows) {
  const used = new Set(balanced(train, trainSize).map(row => row.id));
  const untouched = [];
  for (const group of components(train)) {
    if (!group.some(row => used.has(row.id))) untouched.push(...group);
  }
  return balanced(untouched.sort(byId), fitSize)
    .map(row => ({ ...row, partition: 'fusion-fit' }));
}

async function adaptation(path, pin, excluded, canonical, uciRevision) {
  const fixed = keyIndex(Object.values(canonical).flat());
  const aliases = new Map();
  const rejected = {};
  let inputRows = 0;
  for await (const raw of rows(path, pin)) {
    if (raw.partition !== 'train') continue;
    inputRows++;
    const row = candidate({ ...raw, sourceId: raw.ordinal + ':' + raw.sourceId }, 'phiusiil-uci-967', uciRevision);
    const issue = !row ? 'invalidUrl' : match(excluded, row) ? 'protected' : match(fixed, row) ? 'canonicalOverlap' : null;
    if (issue) {
      rejected[issue] = (rejected[issue] ?? 0) + 1;
      continue;
    }
    const alias = row.identity.alias;
    if (!aliases.has(alias)) aliases.set(alias, []);
    aliases.get(alias).push(row);
  }
  const clean = deduplicate(aliases, rejected);
  const train = [];
  const calibration = [];
  for (const group of components(clean)) {
    const key = group.reduce((min, row) => row.id < min ? row.id : min, group[0].id);
    const rank = parseInt(sha256('phase5d-uci-adaptation\0' + key).slice(0, 8), 16) / 2 ** 32;
    const destination = rank < protocol.targetCalibrationFraction ? calibration : train;
    const partition = destination === calibration ? 'uci-calibration' : 'uci-adaptation';
    for (const row of group) destination.push({ ...row, partition });
  }
  const views = { 'uci-adaptation': train.sort(byId), 'uci-calibration': calibration.sort(byId) };
  assertDisjoint(views);
  return { views, inputRows, rejected };
}

async function digest(path) {
  const hash = createHash('sha256');
  for await (const bytes of createReadStream(path)) hash.update(bytes);
  return hash.digest('hex');
}

async function verifySources(previous, manifest) {
  if (manifest.sourceRevision !== pins.revision) throw new Error('Source revision changed');
  const train = await json(join(previous, 'phresh-development', 'manifest.json'));
  const custody = await json(join(previous, 'phresh-custody-final', 'manifest.json'));
  for (const [side, receipt] of [['train', train], ['test', custody]]) {
    if (receipt.revision !== pins.revision || receipt.side !== side ||
        receipt.shards.length !== pins[side].length) throw new Error('Publisher receipt changed');
    for (const [i, shard] of receipt.shards.entries()) {
      const spec = pins[side][i];
      if (shard.name + '.parquet' !== spec.file || shard.sourceSha256 !== spec.sha256 ||
          shard.size !== spec.size || shard.gitBlob !== spec.gitBlob) throw new Error('Publisher shard pin changed');
      if (side === 'train' && (shard.file !== shard.name + '.jsonl' ||
          await digest(join(previous, 'phresh-development', shard.file)) !== shard.projectedSha256)) {
        throw new Error('Development projection digest changed');
      }
    }
  }
  if (custody.columns.join() !== 'sha256,url' || custody.exclusionsSha256 !== manifest.protected.sha256 ||
      await digest(join(previous, 'uci.zip')) !== '0a639fd03aea6308c5b1c10c92aa23c2ce1505447a9137271865cd0badc9a59a' ||
      manifest.uciRevision !== 'a236549cd369cd80bd478ff8e1779cbf44c58d5c3f79f7a51a1adbed7d06d1c6') {
    throw new Error('Custody or UCI source pin changed');
  }
  const total = custody.shards.reduce((sum, shard) => sum + shard.rows, 0);
  if (total !== manifest.protected.rows) throw new Error('Custody row count changed');
  const excluded = await index(join(previous, 'phresh-custody-final', 'exclusions.jsonl'), custody.exclusionsSha256, total);
  if (excluded.id.size !== total) throw new Error('Unexpected publisher test ID multiplicity');
  return { excluded, total, trainShards: train.shards.length, testShards: custody.shards.length };
}

async function saveViews(directory, views, metadata) {
  await mkdir(directory, { mode: 0o700 });
  const partitions = {};
  for (const [name, members] of Object.entries(views)) {
    partitions[name] = await writePartition(join(directory, name + '.jsonl'), members);
  }
  const manifest = { ...metadata, partitions };
  await writeFile(join(directory, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return manifest;
}

async function main() {
  if (process.argv.length !== 4 || process.env.THREAT_PHASE3D_GUARDED !== '1') throw new Error('Invalid invocation');
  const previous = await assertOutsideGit(await realpath(process.argv[2]));
  const dest = resolve(process.argv[3]);
  await assertOutsideGit(await realpath(dirname(dest)));
  const cohort = join(previous, 'cohort');
  const manifestBytes = await readFile(join(cohort, 'manifest.json'));
  if (sha256(manifestBytes) !== protocol.phase5cManifestSha256) throw new Error('Canonical manifest changed');
  const manifest = JSON.parse(manifestBytes);
  const source = await verifySources(previous, manifest);
  console.log('Verified source shard pins, development projections and custody receipt');
  const historical = await index(join(previous, 'history.jsonl'), manifest.historySha256);
  const canonical = {};
  for (const [name, spec] of Object.entries(manifest.partitions)) {
    canonical[name] = [];
    for await (const row of rows(join(cohort, name + '.jsonl'), spec.sha256, spec.rows)) {
      if (row.partition !== name || match(source.excluded, row) ||
          (name !== 'uci-validation' && match(historical, row))) throw new Error('Canonical partition contains exclusions');
      canonical[name].push(row);
    }
  }
  assertDisjoint(canonical);
  console.log('Verified canonical membership and exclusion checks');
  const phresh = Object.entries(canonical).filter(([part]) => part !== 'uci-validation').flatMap(([, members]) => members);
  const chronological = temporal(phresh);
  const target = await adaptation(join(previous, 'uci-development.jsonl'), manifest.uciReplaySha256,
    source.excluded, canonical, manifest.uciRevision);
  const fusion = fusionFit(canonical.train);
  await mkdir(dest, { mode: 0o700 });
  const protocolSha256 = sha256(protocolBytes);
  const temporalManifest = await saveViews(join(dest, 'temporal'), chronological.result, {
    version: protocol.version, protocolSha256, cutoffs: protocol.temporalCutoffsUtc,
    excludedInvalidDate: chronological.invalidDate, excludedEarlierComponentRows: chronological.quarantined,
    observedDateRanges: Object.fromEntries(Object.entries(chronological.result).map(([name, members]) => {
      const dates = members.map(row => row.collectedAt).sort();
      return [name, dates.length ? [dates[0], dates.at(-1)] : null];
    }))
  });
  const auxiliary = await saveViews(join(dest, 'auxiliary'), { ...target.views, 'fusion-fit': fusion }, {
    version: 'phase5d-auxiliary-v1', protocolSha256, uciInputRows: target.inputRows, uciRejected: target.rejected
  });
  const report = { phase5cManifestSha256: protocol.phase5cManifestSha256, protocolSha256,
    verifiedTrainShards: source.trainShards, verifiedTestShards: source.testShards,
    publisherTestExclusions: source.total, publisherOverlap: 0, historicalPhreshOverlap: 0,
    canonicalRows: phresh.length + canonical['uci-validation'].length,
    temporal: temporalManifest, auxiliary };
  await writeFile(join(dest, 'audit.json'), JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  console.log(JSON.stringify(report));
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    await main();
  } catch (error) {
    console.error('Phase 5D preparation stopped at a private-path, integrity or cohort check (' + error.name + ').');
    process.exitCode = 1;
  }
}
