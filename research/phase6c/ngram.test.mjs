import test from 'node:test';
import assert from 'node:assert/strict';
import { createNgramScorer } from './ngram.mjs';

test('n-gram scorer applies sublinear counts, IDF and L2 normalization', () => {
  const score = createNgramScorer({ schema: 'phase6c-char-tfidf-logistic-v1',
    terms: ['aa'], idf: [2], coefficients: [3], intercept: -1 });
  assert.ok(Math.abs(score('aaaa') - 1 / (1 + Math.exp(-2))) < 1e-12);
  assert.equal(score('z'), 1 / (1 + Math.exp(1)));
  assert.throws(() => score(null), TypeError);
  assert.throws(() => score('a'.repeat(8193)), TypeError);
  assert.throws(() => createNgramScorer({ schema: 'other', terms: [], idf: [], coefficients: [] }), TypeError);
});
