import assert from 'node:assert/strict';
import test from 'node:test';
import { campaignProxy } from '../phase3d/partition.mjs';
import { domainDigest, filterRows, project } from './prepare.mjs';

const window = { firstDay: '2025-12-17', lastDay: '2026-11-24' };
const raw = (id, url, more = {}) => ({
  id, url, label: 1, observedDay: '2026-04-01', source: 'phishvn-ncsc',
  evidence: 'synthetic provenance', brand: 'unverified', cohort: 'external', ...more
});

test('keeps only dated numeric features and removes query and fragment markers', () => {
  const row = project(raw('a', 'https://mottled.test/critical/login?fixture=secret#private'), window, 'synthetic');
  assert.equal(row.candidate.x.length, 14);
  assert.doesNotMatch(JSON.stringify(row), /mottled|secret|private|critical/);
  assert.equal(project(raw('b', 'https://a:key@mottled.test/x'), window, 'synthetic'), null);
  assert.equal(project(raw('c', 'https://mottled.test/x', { observedDay: '2025-12-16' }), window, 'synthetic'), null);
});

test('prior registrants, lexical families and canonical duplicate conflicts fail closed', () => {
  const rows = [
    raw('old1', 'https://reused.test/page'), raw('old2', 'https://sweet-pepper2.test/page'),
    raw('conflict1', 'https://www.other.test/access?k=y'),
    raw('conflict2', 'http://other.test/access?x=z', { label: 0, source: 'phishvn-trusted' }),
    raw('keep', 'https://fresh-sample.test/path')
  ];
  const { output, audit } = filterRows(rows, {
    domains: new Set([domainDigest('reused.test')]),
    families: new Set([campaignProxy('sweetpepper.test')]),
  }, window, 'synthetic');
  assert.deepEqual(output.map(record => record.id), ['keep']);
  assert.deepEqual(audit, {
    input: 5, invalid: 0, priorDomain: 1, priorFamily: 1, duplicates: 1, conflicting: 1, controlOverlap: 0,
  });
});
