import { createHash } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { pathToFileURL } from 'node:url';
import { extractUrl, featureColumns, featureVersion, sha256 } from '../../evaluation/features.mjs';
import { destinationFor } from '../../extension/reputation.mjs';
import { components } from '../phase5a/prepare.mjs';
import { assertOutsideGit } from '../phase5a/run.mjs';
import { observation, urlIdentity } from '../phase3g/validate.mjs';

export const VERSION = 'phase5c-development-v1';
const digestPattern = /^[a-f0-9]{64}$/;
const revision = 'eca603e0ecd4f698f8d4d226c088659e72681239';
const uciRevision = 'a236549cd369cd80bd478ff8e1779cbf44c58d5c3f79f7a51a1adbed7d06d1c6';
const partitions = ['train', 'tuning', 'calibration', 'validation'];
const line = value => JSON.stringify(value) + '\n';
const count = (table, key) => { table[key] = (table[key] ?? 0) + 1; };

async function json(path) {
  return JSON.parse(await readFile(path, 'utf8'));
}

export async function* rows(path, pin, expectedRows) {
  const stream = createReadStream(path);
  const hash = createHash('sha256');
  stream.on('data', bytes => hash.update(bytes));
  let size = 0;
  for await (const text of createInterface({ input: stream })) {
    size++;
    yield JSON.parse(text);
  }
  const actual = hash.digest('hex');
  if (pin !== actual || (expectedRows !== undefined && expectedRows !== size)) {
    throw new Error('Projection fails checksum or row count');
  }
}

export async function index(path, pin, expectedRows) {
  const keys = ['id', 'group', 'family', 'exact', 'alias'];
  const sets = Object.fromEntries(keys.map(key => [key, new Set()]));
  for await (const entry of rows(path, pin, expectedRows)) {
    for (const [key, value] of Object.entries(entry)) {
      if (!keys.includes(key) || !digestPattern.test(value)) throw new Error('Invalid exclusion digest');
      sets[key].add(value);
    }
  }
  return sets;
}

export function candidate(raw, source, sourceRevision, kind = 'real') {
  const identity = urlIdentity(raw.url, kind);
  if (!identity || ![0, 1].includes(raw.label)) return null;
  const sourceId = raw.sourceId;
  const id = sha256([source, sourceRevision, sourceId].join('\0'));
  return { id, sourceId, source, revision: sourceRevision, url: raw.url,
    normalizedUrl: destinationFor(raw.url).key, label: raw.label, identity,
    campaign: null, collectedAt: raw.date ?? null, target: raw.target ?? null, lang: raw.lang ?? null,
    x: extractUrl(raw.url, kind).features };
}

// Exact normalized target names only. Short ambiguous strings such as 'axis' and 'sbi'
// are included as candidate metadata, and carry no independent evidence.
export const brands = new Set([
  'airtel payments bank', 'amazon pay india', 'axis', 'axis bank', 'bank of baroda', 'bank of india',
  'bhim', 'bhim upi', 'canara bank', 'central bank of india', 'federal bank', 'freecharge',
  'google pay india', 'hdfc', 'hdfc bank', 'icici', 'icici bank', 'idbi bank', 'idfc first bank',
  'indian bank', 'indian overseas bank', 'indusind bank', 'jio payments bank', 'kotak',
  'kotak mahindra bank', 'mobikwik', 'npci', 'paytm', 'paytm payments bank', 'phonepe',
  'pnb', 'punjab national bank', 'razorpay', 'sbi', 'sbi yono', 'state bank of india', 'uco bank',
  'union bank of india', 'upi', 'yes bank', 'yono sbi'
]);

export function targetName(value) {
  return typeof value === 'string' ? value.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim() : '';
}

export function deduplicate(aliases, rejected) {
  const unique = [];
  for (const variants of aliases.values()) {
    if (new Set(variants.map(row => row.label)).size > 1) {
      rejected.conflictingLabelRows = (rejected.conflictingLabelRows ?? 0) + variants.length;
      continue;
    }
    variants.sort((a, b) => a.id.localeCompare(b.id));
    const representative = variants[0];
    unique.push(representative);
    const raw = new Set([representative.url]);
    for (const row of variants.slice(1)) {
      count(rejected, raw.has(row.url) ? 'exactDuplicateRows' : 'nearDuplicateRows');
      raw.add(row.url);
    }
  }
  return unique;
}

function append(aliases, row) {
  const key = row.identity.alias;
  if (!aliases.has(key)) aliases.set(key, []);
  aliases.get(key).push(row);
}

export function split(candidates) {
  const selected = Object.fromEntries(partitions.map(name => [name, []]));
  for (const group of components(candidates)) {
    let key = group[0].id;
    for (const row of group) if (row.id < key) key = row.id;
    const fraction = parseInt(sha256(VERSION + '\0' + key).slice(0, 8), 16) / 2 ** 32;
    const partition = fraction < 0.7 ? 'train' : fraction < 0.8 ? 'tuning'
      : fraction < 0.9 ? 'calibration' : 'validation';
    for (const row of group) selected[partition].push({ ...row, partition });
  }
  for (const members of Object.values(selected)) members.sort((a, b) => a.id.localeCompare(b.id));
  return selected;
}

export function assertDisjoint(selected) {
  const owners = new Map();
  for (const [name, members] of Object.entries(selected)) {
    for (const row of members) {
      const { group, family, alias } = row.identity;
      for (const [type, value] of Object.entries({ id: row.id, group, family, alias, campaign: row.campaign })) {
        if (!value) continue;
        const key = type + ':' + value;
        if (owners.has(key) && (owners.get(key) !== name || type === 'id' || type === 'alias')) {
          throw new Error('Duplicate ID or alias, or partition overlap');
        }
        owners.set(key, name);
      }
    }
  }
}

export async function writePartition(path, members) {
  const hash = createHash('sha256');
  let bytes = 0;
  let positive = 0;
  const domains = new Set();
  await pipeline(Readable.from((function* () {
    for (const row of members) {
      const chunk = line(row);
      hash.update(chunk);
      bytes += Buffer.byteLength(chunk);
      positive += row.label;
      domains.add(row.identity.group);
      yield chunk;
    }
  })()), createWriteStream(path, { flags: 'wx', mode: 0o600 }));
  return { sha256: hash.digest('hex'), bytes, rows: members.length, positive,
    negative: members.length - positive, domains: domains.size };
}

async function prepare([development, custody, historyPath, historyPin, uciPath, uciPin, output]) {
  const phresh = await json(join(development, 'manifest.json'));
  const protectedData = await json(join(custody, 'manifest.json'));
  if (phresh.side !== 'train' || phresh.revision !== revision ||
      phresh.columns.join() !== 'sha256,url,label,target,date,lang' ||
      phresh.shards.length !== 56 ||
      protectedData.side !== 'test' || protectedData.revision !== revision ||
      protectedData.columns.join() !== 'sha256,url' || protectedData.shards.length !== 21) {
    throw new Error('Full pinned development and label-free custody receipts are required');
  }
  const excludeCount = protectedData.shards.reduce((sum, shard) => sum + shard.rows, 0);
  const [excluded, history] = await Promise.all([
    index(join(custody, 'exclusions.jsonl'), protectedData.exclusionsSha256, excludeCount),
    index(historyPath, historyPin)
  ]);
  const overlaps = (sets, row) => ['group', 'family', 'alias', 'exact']
    .some(key => sets[key].has(row.identity[key]));
  const uci = new Map();
  const uciDomains = new Set();
  const uciFamilies = new Set();
  const transfer = new Map();
  const report = { version: VERSION, featureVersion, featureColumns, sourceRevision: revision,
    uciRevision, historySha256: historyPin, uciReplaySha256: uciPin,
    protected: { sha256: protectedData.exclusionsSha256, rows: excludeCount,
      distinctIds: excluded.id.size, registrableGroups: excluded.group.size, families: excluded.family.size },
    inputRows: 0, rejected: {}, overlap: {}, financial: { candidates: 0, independentlySupported: 0, targets: {} },
    transfer: { validationInput: 0, rejected: {} } };
  for await (const raw of rows(uciPath, uciPin)) {
    if (!['train', 'validation'].includes(raw.partition)) throw new Error('Non-development UCI row');
    const row = candidate({ ...raw, sourceId: raw.ordinal + ':' + raw.sourceId }, 'phiusiil-uci-967', uciRevision);
    if (raw.partition === 'validation') report.transfer.validationInput++;
    if (!row) {
      if (raw.partition === 'validation') count(report.transfer.rejected, 'invalidUrl');
      continue;
    }
    append(uci, row);
    uciDomains.add(row.identity.group);
    if (row.identity.family) uciFamilies.add(row.identity.family);
    if (raw.partition !== 'validation') continue;
    if (overlaps(excluded, row)) count(report.transfer.rejected, 'protectedPhreshOverlap');
    else append(transfer, row);
  }

  const byAlias = new Map();
  const ids = new Set();
  for (const [offset, shard] of phresh.shards.entries()) {
    const expected = 'train-' + String(offset).padStart(3, '0') + '.jsonl';
    if (shard.file !== expected || !digestPattern.test(shard.sourceSha256)) throw new Error('Invalid shard receipt');
    for await (const raw of rows(join(development, shard.file), shard.projectedSha256, shard.rows)) {
      report.inputRows++;
      if (!digestPattern.test(raw.sha256) || !['phish', 'benign'].includes(raw.label)) {
        count(report.rejected, 'invalidSourceIdOrLabel');
        continue;
      }
      const target = targetName(raw.target);
      if (raw.label === 'phish' && brands.has(target)) {
        report.financial.candidates++;
        count(report.financial.targets, target);
      }
      if (ids.has(raw.sha256)) throw new Error('Publisher record ID is not unique');
      ids.add(raw.sha256);
      const row = candidate({ ...raw, label: Number(raw.label === 'phish'), sourceId: raw.sha256 },
        'phreshphish', revision);
      if (!row || (raw.date != null && observation(raw.date)?.precision !== 'day')) {
        count(report.rejected, 'invalidUrlOrDate');
        continue;
      }
      const crossSource = uci.get(row.identity.alias);
      const domainOverlap = uciDomains.has(row.identity.group);
      if (domainOverlap) count(report.overlap, 'uciDevelopmentDomainRows');
      if (crossSource) {
        count(report.overlap, 'uciDevelopmentAliasRows');
        if (crossSource.some(other => other.identity.exact === row.identity.exact)) {
          count(report.overlap, 'uciDevelopmentNormalizedExactRows');
        }
        if (crossSource.some(other => other.label !== row.label)) count(report.overlap, 'uciDevelopmentConflictRows');
        // Any match compromises an independent transfer comparison, even when labels agree.
        transfer.delete(row.identity.alias);
      }
      const protectedOverlap = excluded.id.has(raw.sha256) || overlaps(excluded, row);
      const historicalOverlap = overlaps(history, row);
      const familyOverlap = uciFamilies.has(row.identity.family);
      if (protectedOverlap) count(report.overlap, 'protectedPhreshRows');
      if (historicalOverlap) count(report.overlap, 'historicalIndexRows');
      if (familyOverlap) count(report.overlap, 'uciDevelopmentFamilyRows');
      if (protectedOverlap) count(report.rejected, 'protectedPhreshOverlap');
      else if (historicalOverlap || domainOverlap || familyOverlap || crossSource) count(report.rejected, 'historicalOrCrossSourceOverlap');
      else append(byAlias, row);
    }
  }
  const unique = deduplicate(byAlias, report.rejected);
  const selected = split(unique);
  // Account for all removed cross-source aliases after matching the entire public train split.
  const remainingTransfer = [...transfer.values()].reduce((sum, entries) => sum + entries.length, 0);
  const priorTransferRejects = Object.values(report.transfer.rejected).reduce((a, b) => a + b, 0);
  report.transfer.rejected.crossSourceAlias = report.transfer.validationInput - priorTransferRejects - remainingTransfer;
  selected['uci-validation'] = deduplicate(transfer, report.transfer.rejected)
    .sort((a, b) => a.id.localeCompare(b.id)).map(row => ({ ...row, partition: 'uci-validation' }));
  assertDisjoint(selected);
  const rejected = Object.values(report.rejected).reduce((a, b) => a + b, 0);
  if (unique.length + rejected !== report.inputRows || report.inputRows !== 498255 || excludeCount !== 168060) {
    throw new Error('Source accounting does not reconcile');
  }
  await mkdir(output, { mode: 0o700 });
  report.acceptedRows = unique.length;
  report.rejectedRows = rejected;
  report.partitions = {};
  for (const [name, members] of Object.entries(selected)) {
    report.partitions[name] = await writePartition(join(output, name + '.jsonl'), members);
  }
  await writeFile(join(output, 'manifest.json'), JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  console.log(JSON.stringify(report));
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const args = process.argv.slice(2);
    if (args.length !== 7 || process.env.THREAT_PHASE3D_GUARDED !== '1') throw new Error('Invalid invocation');
    for (const index of [0, 1, 2, 4]) args[index] = await assertOutsideGit(await realpath(args[index]));
    args[6] = join(await assertOutsideGit(await realpath(dirname(resolve(args[6])))), resolve(args[6]).split(/[\\/]/).at(-1));
    await prepare(args);
  } catch (error) {
    console.error('Cohort preparation stopped at a path, input-integrity, schema or isolation check (' + error.name + ').');
    process.exitCode = 1;
  }
}
