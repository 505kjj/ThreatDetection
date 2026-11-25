import test from 'node:test';
import assert from 'node:assert/strict';
import { extractUrl } from '../../evaluation/features.mjs';
import { destinationFor } from '../../extension/reputation.mjs';
import { parse } from '../../extension/vendor/tldts.mjs';
import { extractBrowserUrl } from './url-features.mjs';

test('browser URL features match the frozen extractor on synthetic and malformed inputs', () => {
  const inputs = [
    'https://example.test/', 'https://user:secret@bücher.example.test/a%2fb?q=secret#private',
    'http://test.example.test:8080/a/123', 'https://example.test/a%20b',
    'https://example.test/💳', 'http://127.0.0.1:8443/', 'ftp://example.test/',
    'https://example.test/\n', 'not a URL', '', 'https://' + 'a'.repeat(8193)
  ];
  for (const input of inputs) {
    const expected = extractUrl(input, 'synthetic');
    const actual = extractBrowserUrl(input, 'synthetic', destinationFor, parse);
    assert.deepEqual(actual?.features ?? null, expected?.features ?? null);
    if (actual) assert.equal(actual.normalizedUrl, destinationFor(input).key);
  }
});
