import assert from 'node:assert/strict';
import { execFile as exec } from 'node:child_process';
import { mkdtemp, readFile, rm, rmdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import test from 'node:test';
import { checkDestination, destinationFor, parseSnapshot } from '../../extension/reputation.mjs';
import { ingest, loadSnapshots, readManifest, validateManifest } from '../dataset.mjs';
import { evaluate, score } from '../evaluate.mjs';
import { extractUrl, featureColumns, sha256 } from '../features.mjs';
import { splitRecords, timestamp, windows } from '../splits.mjs';

const here = specifier => fileURLToPath(new URL(specifier, import.meta.url));
const fixtureManifest = here('../manifests/synthetic.json');
const fixtureDir = here('../fixtures/');
const execFile = promisify(exec);

test('extraction drops credentials, query and fragment and shares browser canonicalization', () => {
  const clean = 'https://café.example.org:8443/Pay/%2f1';
  const noisy = 'https://id:private-password@café.example.org:8443/Pay/%2f1?otp=private-otp#private-id';
  const a = extractUrl(clean, 'real');
  const b = extractUrl(noisy, 'real');
  assert.deepEqual(a, b);
  assert.equal(a.keyHash, sha256(destinationFor(clean).key));
  assert.equal(a.features.length, featureColumns.length);
  assert.ok(a.features.every(Number.isInteger));
  assert.equal(a.group, 'example.org');
  assert.equal(extractUrl('https://login.merchant.github.io/', 'real').group, 'merchant.github.io');
  assert.equal(extractUrl('https://now.hdfc.bank.in/', 'real').group, 'hdfc.bank.in');
  assert.equal(extractUrl('https://local.test/', 'real'), null);
  assert.equal(extractUrl('https://local.test/', 'synthetic').group, 'local.test');
  for (const raw of ['javascript:alert(1)', 'https://example.org/a\nb', 'https://example.org/' + '1'.repeat(8192)]) {
    assert.equal(extractUrl(raw, 'real'), null);
  }
});

test('cutoffs and grouping stay disjoint without moving future records to training', () => {
  const rows = [
    { group: 'first.test', observedAt: 1 }, { group: 'first.test', observedAt: 12 },
    { group: 'second.test', observedAt: 10 }, { group: 'third.test', observedAt: 20 },
    { group: 'unknown.test', observedAt: null }
  ];
  const plan = { seed: 'fixed', trainBefore: 10, testFrom: 20 };
  const { chronological, domainDisjoint, withheld } = splitRecords(rows, plan);
  assert.deepEqual(chronological, { train: [rows[0]], validation: [rows[2]], test: [rows[3]] });
  assert.deepEqual(withheld, { undated: 1, seenInEarlierWindow: 1 });
  assert.deepEqual(splitRecords(rows, plan).domainDisjoint, domainDisjoint);
  for (const group of new Set(rows.map(row => row.group))) {
    assert.equal(windows.filter(window => domainDisjoint[window].some(row => row.group === group)).length, 1);
  }
  assert.equal(timestamp('2026-02-30T00:00:00Z'), null);
  assert.equal(timestamp('2026-01-01T00:00:00+05:30'), null);
  assert.equal(timestamp('2026-01-01T00:00:00.123Z'), Date.parse('2026-01-01T00:00:00.123Z'));
});

test('manifest rejects mixed, unsafe and unpinned inputs and strips unknown metadata', async () => {
  const raw = JSON.parse(await readFile(fixtureManifest, 'utf8'));
  const changed = source => ({ ...raw, sources: [{ ...raw.sources[0], ...source }] });
  for (const source of [{ file: '../private.jsonl' }, { kind: 'real' }, { sha256: 'invalid' },
    { acquiredAt: 'invalid' }, { reference: 'https://source.example.org/?token=private' }]) {
    assert.throws(() => validateManifest(changed(source)), /provenance/);
  }
  const filtered = validateManifest(changed({ unknownKey: 'private-metadata' }));
  assert.ok(!JSON.stringify(filtered).includes('private-metadata'));
  await assert.rejects(ingest(validateManifest(changed({ sha256: 'a'.repeat(64) })), fixtureDir), /SHA-256/);
});

test('synthetic run validates confidence, deduplicates and reports each baseline and abstentions', async () => {
  const manifest = await readManifest(fixtureManifest);
  const data = await ingest(manifest, fixtureDir);
  const snapshots = await loadSnapshots(manifest, fixtureDir);
  const { report } = evaluate(manifest, data, snapshots);
  assert.equal(report.kind, 'synthetic');
  assert.equal(report.ingestion.received, 20);
  assert.equal(report.ingestion.retained, 15);
  assert.equal(report.ingestion.duplicates, 2);
  assert.equal(report.ingestion.conflictingKeys, 1);
  assert.equal(report.ingestion.belowConfidence, 1);
  assert.equal(report.ingestion.invalidUrl, 1);
  const { withheld, test } = report.chronologicalDomainDisjoint;
  assert.deepEqual(withheld, { undated: 0, seenInEarlierWindow: 1 });
  assert.equal(test.reputation.tp, 3);
  assert.equal(test.reputation.fp, 1);
  assert.equal(test.reputation.decisionCoverage, 0.8);
  assert.equal(test.impersonation.tp, 2);
  assert.equal(test.impersonation.falsePositiveRate, 0.25);
  assert.equal(test.combined.tp, 5);
  assert.equal(test.combined.f1, 10 / 13);
  assert.equal(test.combined.phishingAlertCoverage, 5 / 6);
  assert.deepEqual(test.combinedPolicy, { confirmed: 4, advisoryOnly: 3 });
  assert.ok(!JSON.stringify(report).includes('fixture-marker'));
});

test('replay excludes future, expired and same-lineage snapshots', async () => {
  const manifest = await readManifest(fixtureManifest);
  const [snapshot] = await loadSnapshots(manifest, fixtureDir);
  const url = extractUrl('https://flagged-login.test/private-path', 'synthetic');
  const record = { ...url, label: 'phishing', lineages: new Set(['independent']) };
  const rows = [null, snapshot.capturedAt, snapshot.capturedAt + 1, snapshot.expiresAt]
    .map(observedAt => ({ ...record, observedAt }));
  rows.push({ ...rows[2], lineages: new Set([snapshot.lineage]) });
  const result = score(rows, [snapshot]);
  assert.deepEqual(result.reputationUnavailable, { undated: 1, sameLabelLineage: 1, noPriorFreshSnapshot: 2 });
  assert.equal(result.reputation.tp, 1);
  assert.equal(result.reputation.recall, 1);
  assert.equal(result.reputation.phishingAlertCoverage, 0.2);
  assert.equal(score(rows, []).combined.precision, null);
});

test('offline replay agrees with the browser for exact host, explicit path and SHA-256 matches', async () => {
  const manifest = await readManifest(fixtureManifest);
  const [snapshot] = await loadSnapshots(manifest, fixtureDir);
  const observedAt = snapshot.capturedAt + 1000;
  const raw = JSON.parse(await readFile(here('../fixtures/snapshot.json'), 'utf8'));
  const liveShape = parseSnapshot(raw, observedAt);
  for (const url of ['https://flagged-login.test/anything', 'https://explicit-path.test/pay?private=1',
    'https://legacy-digest.test/download#private', 'https://explicit-path.test/pay/sibling',
    'https://sub.flagged-login.test/anything']) {
    const browser = await checkDestination(liveShape, destinationFor(url), () => observedAt);
    const row = { ...extractUrl(url, 'synthetic'), observedAt, label: 'phishing', lineages: new Set() };
    assert.equal(score([row], [snapshot]).reputation.tp, Number(browser.state === 'confirmed'));
  }
});

test('CLI exports only numeric feature vectors for eligible dated splits', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'threat-fixture-evaluation-'));
  const file = join(dir, 'features.jsonl');
  t.after(async () => { await rm(file, { force: true }); await rmdir(dir); });
  const { stdout } = await execFile(process.execPath, [here('../run.mjs'), '--manifest', fixtureManifest,
    '--input-dir', fixtureDir, '--features', file]);
  assert.equal(JSON.parse(stdout).kind, 'synthetic');
  const raw = await readFile(file, 'utf8');
  assert.ok(!/https?:|private-path|fixture-marker|observedAt|hostname/i.test(raw));
  const records = raw.trimEnd().split('\n').map(JSON.parse);
  assert.equal(records.length, 14);
  assert.ok(records.every(row => Object.keys(row).join(',') === 'featureVersion,split,label,values' &&
    row.values.length === featureColumns.length && row.values.every(Number.isInteger)));
});

test('CSV adapter uses only URL and author label and leaves its observation time unset', async t => {
  const realSpec = here('../manifests/phiusiil-uci-967.json');
  const manifest = JSON.parse(await readFile(realSpec, 'utf8'));
  const dir = await mkdtemp(join(tmpdir(), 'threat-csv-adapter-'));
  const input = join(dir, manifest.sources[0].file);
  const spec = join(dir, 'manifest.json');
  t.after(async () => {
    await Promise.all([rm(input, { force: true }), rm(spec, { force: true })]);
    await rmdir(dir);
  });
  const csv = 'FILENAME,URL,Title,label\r\n' +
    'discard,"https://example.org/a,b?otp=secret","irrelevant,private",0\r\n' +
    'discard,https://example.net/,irrelevant,1\r\n';
  manifest.sources[0].sha256 = sha256(csv);
  await writeFile(input, csv);
  await writeFile(spec, JSON.stringify(manifest));
  const data = await ingest(validateManifest(manifest), dir);
  assert.deepEqual(data.rows.map(row => [row.label, row.observedAt]), [['phishing', null], ['legitimate', null]]);
  assert.ok(!JSON.stringify(data.rows).includes('secret'));
  await assert.rejects(execFile(process.execPath, [here('../run.mjs'), '--manifest', spec,
    '--features', join(dir, 'features.jsonl')]), /Feature export requires dated/);
});
