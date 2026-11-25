import test from 'node:test';
import assert from 'node:assert/strict';
import { createXgboostScorer } from './xgboost.mjs';

test('tree scorer applies split, leaf and input validation', () => {
  const model = { schema: 'phase6c-xgboost-v1', features: 1, baseScore: 0.5,
    trees: [{ split: 'f0', split_condition: 2, yes: 1, no: 2,
      children: [{ nodeid: 1, leaf: -1 }, { nodeid: 2, leaf: 1 }] }] };
  const score = createXgboostScorer(model);
  assert.ok(score([1]) < 0.5);
  assert.ok(score([2]) > 0.5);
  assert.throws(() => score([NaN]), TypeError);
  assert.throws(() => score([]), TypeError);
});
