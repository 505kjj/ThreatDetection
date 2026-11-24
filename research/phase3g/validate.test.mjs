import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256 } from '../../evaluation/features.mjs';
import { campaignProxy } from '../phase3d/partition.mjs';
import { domainDigest } from '../phase3e/prepare.mjs';
import { descriptors } from './describe.mjs';
import { observation, policy, validate } from './validate.mjs';

const evidence = 'https://example.org/record?token=PRIVATE-MARKER';
const manifest = {
  schemaVersion: 1, kind: 'synthetic', asOf: '2026-11-24T23:59:59+05:30',
  recordsSha256: '0'.repeat(64),
  sources: [{ id: 'issuer', publisher: 'Synthetic issuer', provenance: evidence, license: 'Synthetic rights',
              permission: { evidence, internalResearch: true, aggregateReporting: true } }],
  targets: [{ id: 'issuer-bank', name: 'Synthetic bank', kind: 'financial-institution', reviewed: true, evidence }]
};
const record = (url, split = 'test', overrides = {}) => ({
  url, split, label: 'phishing', observedAt: '2026-03-01', sourceId: 'issuer', sourceRecord: evidence,
  target: { id: 'issuer-bank', verified: true, evidence },
  verification: { status: 'verified', label: 'phishing', sourceId: 'issuer', evidence },
  ...overrides,
});
const batch = (...records) => records.map((record, i) => ({ record, line: i + 1 }));

test('lexical descriptors use the canonical URL and exclude query and fragment contents', () => {
  const clean = descriptors('https://example.org/one-two/%C3%A9');
  const extra = descriptors('https://example.org/one-two/%C3%A9?q=secret#private');
  assert.deepEqual(extra, clean);
  assert.equal(clean.tld, 'org');
  assert.equal(clean.pathPunctuation, 1);
  assert.equal(clean.canonicalLength, 'https://example.org/one-two/%C3%A9'.length);
});

test('observation preserves day precision, accepts offsets and rejects impossible dates', () => {
  assert.equal(observation('2024-02-29').precision, 'day');
  assert.equal(observation('2024-02-29T10:10:00+05:30').precision, 'timestamp');
  for (const value of ['2026-02-29', '2026-01-01T24:00:00Z', '2026-01-01T12:00:00',
    '2026-01-01T12:00:00+14:55', null]) assert.equal(observation(value), null);
});

test('missing license, target, source, observation and verification are reported explicitly', () => {
  const incomplete = structuredClone(manifest);
  delete incomplete.sources[0].license;
  incomplete.sources[0].permission.aggregateReporting = false;
  const got = validate(batch({
    url: 'https://freshbank.test/login', sourceId: 'issuer', label: 'phishing', split: 'test',
  }), policy(incomplete));
  assert.equal(got.report.eligible, 0);
  assert.equal(got.report.manifestIssues['source.license-missing'], 1);
  assert.equal(got.report.manifestIssues['source.aggregate-reporting-not-authorized'], 1);
  for (const item of ['target.missing', 'verification.missing', 'observation.missing',
    'provenance.source-unapproved', 'provenance.record-evidence-missing-or-invalid']) {
    assert.equal(got.report.errors[item], 1);
  }
});

test('aliases, conflicts, prior identities and cross-split campaign links reject all memberships', () => {
  const campaign = { namespace: 'issuer', id: 'cluster-a', evidence };
  const prior = {
    domains: new Set([domainDigest('frozenbank.test')]),
    families: new Set([campaignProxy('previousbranch.test')])
  };
  const rows = batch(
    record('https://one-bank.test/login?session=private', 'calibration', { campaign }),
    record('http://www.one-bank.test/login?another=secret', 'test', { label: 'legitimate' }),
    record('https://relatedbank.test/other', 'test', { campaign }),
    record('https://frozenbank.test/other'),
    record('https://previous-branch2.test/login'),
    record('https://freshunique.test/a')
  );
  const result = validate(rows, policy(manifest), prior);
  for (const [key, count] of Object.entries({
    'duplicate.normalized-variant': 2, 'duplicate.conflicting-label': 2, 'split.registered-domain-overlap': 2,
    'split.campaign-overlap': 2, 'history.registered-domain-overlap': 1, 'history.lexical-family-overlap': 1,
  })) assert.equal(result.report.errors[key], count);
  assert.equal(result.report.eligible, 1);
  assert.equal(result.report.splits.test.registeredDomains, 1);
  assert.equal(result.report.historicalOverlap, 'checked');
  assert.doesNotMatch(JSON.stringify(result), /session|freshunique|private|token/i);
});

test('CLI checks the input pin and writes sanitized aggregate and line-level diagnostics', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'threat-3g-validator-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const input = join(dir, 'records.jsonl');
  const spec = join(dir, 'manifest.json');
  const output = join(dir, 'report');
  const rows = JSON.stringify(record('https://freshbank.test/secure-login?token=SUPER-PRIVATE')) + '\n';
  await writeFile(input, rows);
  await writeFile(spec, JSON.stringify({ ...manifest, recordsSha256: sha256(rows) }));
  const cli = fileURLToPath(new URL('./validate.mjs', import.meta.url));
  const run = (destination) => spawnSync(process.execPath, [cli, spec, input, destination], { encoding: 'utf8' });
  const passed = run(output);
  assert.equal(passed.status, 0, passed.stderr);
  const summary = await readFile(join(output, 'summary.json'), 'utf8');
  assert.equal(JSON.parse(summary).eligible, 1);
  assert.equal(JSON.parse(summary).readyForIndependentEvidenceReview, false);
  assert.equal(JSON.parse(summary).historicalOverlap, 'not-checked');
  const notes = await readFile(join(output, 'private-issues.json'), 'utf8');
  assert.match(notes, /campaign\.missing/);
  assert.doesNotMatch(summary + notes + passed.stdout, /freshbank|SUPER-PRIVATE|PRIVATE-MARKER/);
  await writeFile(input, rows + '\n');
  assert.equal(run(join(dir, 'tampered')).status, 1);
});

test('literal-IP identities have a separate count and leakage reason', () => {
  const prior = { domains: new Set([domainDigest('192.0.2.10')]), families: new Set() };
  const rows = batch(record('https://192.0.2.10/login'),
    record('https://192.0.2.11/a', 'development'), record('https://192.0.2.11/b', 'test'),
    record('https://192.0.2.12/login'));
  const { report } = validate(rows, policy(manifest), prior);
  assert.equal(report.errors['history.literal-ip-overlap'], 1);
  assert.equal(report.errors['split.literal-ip-overlap'], 2);
  assert.equal(report.splits.test.registeredDomains, 0);
  assert.equal(report.splits.test.literalIps, 1);
});
