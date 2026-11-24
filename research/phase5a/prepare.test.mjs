import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { extractUrl, sha256 } from '../../evaluation/features.mjs';
import { domainDigest } from '../phase3e/prepare.mjs';
import { compile, prepare } from './prepare.mjs';
import { fixture, record } from './fixtures.mjs';
import { assertOutsideGit, run } from './run.mjs';
import { previousPartition } from './compare.mjs';

const ref = 'sha256:' + 'a'.repeat(64);

test('deterministic prospective partitions keep groups, campaigns and identities private', () => {
  const { records, manifest } = fixture();
  const cfg = compile(manifest);
  const result = prepare(records, cfg);
  assert.deepEqual(result, prepare(records.toReversed(), cfg));
  const { report, views } = result;
  assert.equal(report.inputRows, 14);
  assert.deepEqual(report.excluded, {
    'required-dates-missing-or-invalid': 1, 'cross-window-component': 3,
    'normalized-variant': 1, 'verification-after-partition-cutoff': 1
  });
  assert.deepEqual(Object.values(report.partitions).map(row => [row.rows, row.balancedRows]), [[3, 2], [2, 2], [3, 2]]);
  assert.equal(report.financialEvaluation, 'not-established');
  assert.equal(report.readyForReview, false);
  const seen = new Set();
  for (const view of Object.values(views)) {
    for (const row of view.natural) {
      assert.ok(!seen.has(row.domainGroup));
      seen.add(row.domainGroup);
    }
    assert.ok(view.balanced.every(id => view.natural.some(row => row.id === id)));
  }
  assert.doesNotMatch(JSON.stringify(result), /https?:|\.test|private-synthetic-marker|\/a1/);
});

test('transitive overlap with past evidence quarantines the entire linked component', () => {
  const { manifest } = fixture();
  const a = record('bridge-a', 'previousexample', 'phishing', '2025-01-10', { campaign: 'bridge' });
  const b = record('bridge-b', 'newexample', 'phishing', '2025-01-10', { campaign: 'bridge' });
  const c = record('bridge-c', 'newexample', 'phishing', '2025-02-10');
  const previous = { domains: new Set([domainDigest('previousexample.test')]), families: new Set() };
  const { report } = prepare([a, b, c], compile(manifest), previous);
  assert.equal(report.excluded['historical-component-overlap'], 3);
  assert.ok(Object.values(report.partitions).every(value => value.rows === 0));
});

test('conflicting duplicates are quarantined and exact duplicates are counted separately', () => {
  const { manifest } = fixture();
  const entries = [
    record('one', 'samealias', 'phishing', '2025-01-10'),
    record('two', 'samealias', 'legitimate', '2025-01-10', { sourceId: 'fixture-b' }),
    record('three', 'sameother', 'phishing', '2025-01-10'),
    record('four', 'sameother', 'phishing', '2025-01-10', { sourceId: 'fixture-b' })
  ];
  const { report } = prepare(entries, compile(manifest));
  assert.equal(report.excluded['conflicting-labels'], 2);
  assert.equal(report.excluded['exact-duplicate'], 1);
  assert.equal(report.partitions.train.rows, 1);
});

test('licensing, unsafe inputs and chronology stop at intake', () => {
  const { manifest } = fixture();
  manifest.sources[0].permission.modelTraining = false;
  const wrongUrl = record('bad-url', 'unsafe', 'phishing', '2025-01-05');
  wrongUrl.url = 'https://demo-user:demo-pass@unsafe.test/';
  const early = record('too-early', 'timeerror', 'phishing', '2025-01-05T19:00:00Z',
    { verifiedAt: '2025-01-05T18:00:00Z' });
  const late = record('late', 'chronological', 'legitimate', '2025-01-31T23:15:00+02:00',
    { verifiedAt: '2025-02-01T02:01:00+02:00' });
  const { report } = prepare([wrongUrl, early, late, record('blocked-rights', 'rights', 'phishing', '2025-01-11')],
    compile(manifest));
  assert.deepEqual(report.excluded, { 'invalid-url-or-userinfo': 1, 'verification-before-observation': 1,
    'verification-after-partition-cutoff': 1, 'training-rights-unconfirmed': 1 });
});

test('a financial resemblance or uncorroborated source target is not a verified financial label', () => {
  const { manifest } = fixture();
  manifest.kind = 'real';
  manifest.targets = [{ id: 'example-bank', name: 'Test-only bank', kind: 'financial-institution', reviewed: true, evidence: ref }];
  const sample = record('reported', 'finance', 'phishing', '2025-03-10');
  sample.url = 'https://finance.example.org/';
  sample.verification.method = 'community-verified';
  sample.target = { id: 'example-bank', verified: true, evidence: ref, reviewSourceId: 'fixture-a' };
  const cfg = compile(manifest);
  assert.throws(() => prepare([sample], cfg), /historical/);
  const prior = { domains: new Set(), families: new Set() };
  assert.equal(prepare([sample], cfg, prior).report.partitions.test.labels.phishing.financialConfirmed, 0);
  sample.target.reviewSourceId = 'fixture-b';
  assert.equal(prepare([sample], cfg, prior).report.partitions.test.labels.phishing.financialConfirmed, 1);
  assert.equal(prepare([sample], cfg, prior).report.financialEvaluation, 'not-established');
});

test('filesystem preparation checks pins and separates private final files', async () => {
  const fixtureDir = await mkdtemp(join(tmpdir(), 'phase5a-validation-'));
  const { manifest, ledger } = fixture();
  const manifestPath = join(fixtureDir, 'manifest.json');
  const ledgerPath = join(fixtureDir, 'ledger.jsonl');
  const output = join(fixtureDir, 'output');
  await writeFile(manifestPath, JSON.stringify(manifest));
  await writeFile(ledgerPath, ledger);
  await run(manifestPath, ledgerPath, output);
  const freeze = JSON.parse(await readFile(join(output, 'freeze.json'), 'utf8'));
  const test = await readFile(join(output, 'final', 'test.numeric.jsonl'));
  assert.equal(sha256(test), freeze.artifacts.test.numericSha256);
  await assert.rejects(readFile(join(output, 'development', 'test.numeric.jsonl')), { code: 'ENOENT' });
  await assert.rejects(run(manifestPath, ledgerPath, output), { code: 'EEXIST' });
  await writeFile(ledgerPath, ledger + ' ');
  await assert.rejects(run(manifestPath, ledgerPath, join(fixtureDir, 'tampered')), /manifest pin/);
  await assert.rejects(assertOutsideGit(resolve('.')), /Git worktrees/);
});

test('numeric comparison verifies the published pin and does not invent dropped features', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'phase5a-numeric-'));
  const path = join(directory, 'train.tsv');
  const url = 'https://sample.test/a1';
  const vector = extractUrl(url, 'synthetic').features;
  const line = [1, 'a'.repeat(64), ...vector].join('\t') + '\n';
  await writeFile(path, line);
  const simulated = { phishing: 1, legitimate: 0, groups: 1, sha256: sha256(line) };
  const { profile } = await previousPartition(path, simulated, false);
  assert.equal(profile.labels.phishing.canonicalUrlLengthDefaultPortDnsOnly.median, url.length);
  assert.equal(profile.tlds, 'not-preserved-in-numeric-input');
  assert.equal(profile.observationRange, null);
  await assert.rejects(previousPartition(path, { ...simulated, sha256: 'b'.repeat(64) }, false), /pin differs/);
});
