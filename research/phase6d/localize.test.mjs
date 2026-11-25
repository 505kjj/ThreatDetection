import test from 'node:test';
import assert from 'node:assert/strict';
import { locateCandidates, readCandidate } from './localize.mjs';

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

test('candidate extraction reports inaccessible or unsupported images', () => {
  assert.deepEqual(readCandidate({ kind: 'svg' }, {}), { status: 'unavailable', reason: 'unsupported-kind' });
  assert.equal(readCandidate({ kind: 'image', element: { complete: false } }, {}).status, 'unavailable');
  const document = { createElement: () => ({ getContext: () => ({ drawImage() {}, getImageData() {
    throw Object.assign(new Error('tainted'), { name: 'SecurityError' });
  } }) }) };
  const candidate = { kind: 'image', element: { complete: true, naturalWidth: 32, naturalHeight: 32 } };
  assert.equal(readCandidate(candidate, document).reason, 'cross-origin');
});
