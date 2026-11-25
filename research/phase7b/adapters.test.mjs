import test from 'node:test';
import assert from 'node:assert/strict';
import { createResearchCoordinator } from './adapters.mjs';
import { createNgramScorer } from '../phase6c/ngram.mjs';
import { assessFixture } from '../phase6e/assess.mjs';

const production = { decision: 'BLOCK_MALWARE', bypassAllowed: false };
test('research adapter codes preserve decisions and distinguish missing modalities and failures', async () => {
  const score = createNgramScorer({ schema: 'phase6c-char-tfidf-logistic-v1', terms: ['ab'],
    idf: [1], coefficients: [1], intercept: 0 });
  const coordinator = createResearchCoordinator({
    url: () => ({ score: score('abc') }),
    dom: () => ({ score: NaN }),
    'browser-security': () => ({ evidence: assessFixture({ form: 'insecure' }) })
  });
  assert.deepEqual((await coordinator.evaluate(production)).evidence, []);
  coordinator.setEnabled(true);
  const result = await coordinator.evaluate(production);
  assert.equal(result.decision, production.decision);
  assert.equal(result.bypassAllowed, false);
  assert.deepEqual(result.evidence.map(item => item.availability), ['available', 'error', 'unavailable', 'available']);
  assert.equal(result.evidence.some(item => 'score' in item), false);
});

test('navigation supersedes pending research and rollback discards observations', async () => {
  const coordinator = createResearchCoordinator({ url: () => new Promise(() => {}) }, { timeoutMs: 20 });
  coordinator.setEnabled(true);
  const stale = coordinator.evaluate(production);
  const current = coordinator.evaluate({ decision: 'BLOCK_PHISHING', bypassAllowed: true });
  assert.deepEqual((await stale).evidence, []);
  assert.equal((await current).evidence[0].code, 'timeout');
  assert.equal((await current).bypassAllowed, true);
  const rolledBack = coordinator.evaluate(production);
  coordinator.setEnabled(false);
  coordinator.setEnabled(true);
  assert.equal((await rolledBack).researchEnabled, false);
});
