import test from 'node:test';
import assert from 'node:assert/strict';
import { assessFixture, evidence } from './assess.mjs';

test('synthetic categories preserve confirmation and advisory boundaries', () => {
  const results = assessFixture({ reputation: 'confirmed', impersonation: true, redirect: 'unexplained',
    form: 'external', cookie: 'broad-scope', permission: 'granted', download: 'mime-mismatch',
    tracker: 'listed', behavior: 'overlay', experimental: 'available' });
  assert.equal(results.length, 10);
  assert.deepEqual(results.filter(row => row.state === 'confirmed').map(row => row.category), ['reputation']);
  assert.equal(results.find(row => row.category === 'cookie').state, 'privacy');
  assert.equal(results.find(row => row.category === 'experimental').state, 'unavailable');
  assert.throws(() => evidence('credential', 'confirmed', 'fixture'), TypeError);
});

test('legitimate flows and absent observations do not create findings', () => {
  assert.deepEqual(assessFixture({ redirect: 'oauth', form: 'local', cookie: 'unknown',
    permission: 'prompt', download: 'unknown', tracker: 'unknown', behavior: 'none' }), []);
  assert.deepEqual(assessFixture({ reputation: 'unavailable' }),
    [{ category: 'reputation', state: 'unavailable', reason: 'snapshot-unavailable' }]);
});
