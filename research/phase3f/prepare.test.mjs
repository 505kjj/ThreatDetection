import assert from 'node:assert/strict';
import test from 'node:test';
import { campaignProxy } from '../phase3d/partition.mjs';
import { domainDigest } from '../phase3e/prepare.mjs';
import { filter, project } from './prepare.mjs';

const archive = (id, url, changes = {}) => ({
  id, url, label: 1, cohort: 'general-transfer', observedDay: '2014-02-21',
  source: 'phishtank-archive-20', evidence: 'synthetic evidence', license: 'synthetic',
  sourceVerdict: 'VALID PHISH', brand: null, campaign: null, ...changes
});
const control = (id, url) => ({
  id, url, label: 0, cohort: 'india-control', observedDay: '2026-11-24',
  source: 'official-india', evidence: 'synthetic evidence', license: 'synthetic', brand: 'fixture', kind: 'login'
});

test('requires dated verified positives and keeps queries out of projected results', () => {
  const value = project(archive('a', 'https://testproof.test/login?fixture=secret#value'), 'synthetic');
  assert.equal(value.x.length, 14);
  assert.doesNotMatch(JSON.stringify(value), /testproof|secret|fixture/);
  assert.equal(project(archive('a', 'https://testproof.test/', { sourceVerdict: 'Pending' }), 'synthetic'), null);
  assert.equal(project(archive('a', 'https://testproof.test/', { brand: 'guessed' }), 'synthetic'), null);
  assert.equal(project(control('a', 'https://goodfixture.test/login?value=private'), 'synthetic'), null);
});

test('drops all historic domains and families and keeps one archival site per family', () => {
  const prior = { domains: new Set([domainDigest('oldsite.test')]), families: new Set([campaignProxy('staleair.test')]) };
  const rows = [
    archive('1', 'https://oldsite.test/'), archive('2', 'https://stale-air1.test/'),
    archive('3', 'https://stoneclock.test/p'), archive('4', 'http://www.stoneclock.test/p?example=1'),
    archive('5', 'https://stone-clock3.test/alt'),
    archive('6', 'https://mildgarden.test/x'), control('7', 'https://mildgarden.test/help'),
    control('8', 'https://mildgarden.test/login')
  ];
  const result = filter(rows, prior, 2, 'synthetic');
  const scores = result.byCohort['general-transfer'];
  assert.equal(scores.priorDomain, 1);
  assert.equal(scores.priorFamily, 1);
  assert.equal(scores.duplicate, 1);
  assert.equal(scores.repeatedLexicalFamily, 1);
  assert.equal(scores.crossCohortDomain, 1);
  assert.equal(scores.retained, 1);
  assert.equal(result.byCohort['india-control'].retained, 2);
  assert.deepEqual(filter(rows, prior, 2, 'synthetic').output, result.output);
});
