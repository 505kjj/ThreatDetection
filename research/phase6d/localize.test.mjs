import test from 'node:test';
import assert from 'node:assert/strict';
import { locateCandidates } from './localize.mjs';

function node(tag, { width = 80, height = 30, label = '', header = false } = {}) {
  return { localName: tag, getBoundingClientRect: () => ({ width, height }),
    getAttribute: name => name === 'alt' ? label : null, closest: () => header ? {} : null };
}

test('bounded locator ranks labelled and header candidates and reports truncation', () => {
  const elements = [node('img', { header: true }), node('svg', { label: 'brand logo' }),
    node('img'), node('img', { label: 'logo', width: 4 })];
  const result = locateCandidates({ querySelectorAll: () => elements }, 1);
  assert.equal(result.status, 'partial');
  assert.equal(result.candidates[0].kind, 'svg');
  assert.equal(result.candidates[0].logoLabel, true);
  assert.equal(locateCandidates({ querySelectorAll: () => Array(2001).fill(elements[0]) }).reason, 'candidate-budget');
  assert.throws(() => locateCandidates({}, 0), RangeError);
});
