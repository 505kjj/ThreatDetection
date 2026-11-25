import test from 'node:test';
import assert from 'node:assert/strict';
import { aggregateEvidence } from './policy.mjs';

const observations = [{ source: 'visual', availability: 'available', code: 'brand-match' },
  { source: 'dom', availability: 'unavailable', code: 'cross-origin' }];

test('confirmed decisions and bypass remain authoritative with research enabled', () => {
  for (const decision of ['BLOCK_PHISHING', 'BLOCK_MALWARE', 'SHOW_WARNING', 'ALLOW', 'UNAVAILABLE']) {
    const bypassAllowed = decision === 'BLOCK_PHISHING';
    const result = aggregateEvidence({ production: { decision, bypassAllowed }, observations, enabled: true });
    assert.equal(result.decision, decision);
    assert.equal(result.bypassAllowed, bypassAllowed);
    assert.deepEqual(result.evidence, observations);
  }
});

test('rollback disables research output and rejects malformed inputs', () => {
  const result = aggregateEvidence({ production: { decision: 'ALLOW', bypassAllowed: false }, observations });
  assert.deepEqual(result.evidence, []);
  assert.equal(result.researchEnabled, false);
  assert.throws(() => aggregateEvidence({ production: { decision: 'ALLOW', bypassAllowed: false },
    observations: [{ source: 'visual', availability: 'available', code: 'https://example.test/private' }] }), TypeError);
  assert.throws(() => aggregateEvidence({ production: { decision: 'ALLOW', bypassAllowed: false },
    observations: Array(33).fill(observations[0]) }), TypeError);
});
