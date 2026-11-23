import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { checkDestination, createSnapshotCache, destinationFor, parseSnapshot } from '../reputation.mjs';

const START = Date.parse('2026-01-01T00:00:00.000Z');
const HOST = { kind: 'HOST', value: 'known-phish.example.test', threat: 'PHISHING' };
const url = 'https://files.example.test/download';
const HASH = { kind: 'URL_SHA256', value: createHash('sha256').update(url).digest('hex'), threat: 'MALWARE' };
const raw = (entries, lifetime = 300000) => ({ entries,
  generatedAt: new Date(START).toISOString(), expiresAt: new Date(START + lifetime).toISOString() });

test('canonical URL excludes userinfo, query and fragment and retains path scope', async () => {
  const destination = destinationFor('https://name:fixture@FILES.example.test:443/download?id=private#secret');
  assert.deepEqual(destination, { host: 'files.example.test', key: url });
  const feed = parseSnapshot(raw([HOST, HASH]), START);
  assert.equal((await checkDestination(feed, destination, () => START)).threat, 'MALWARE');
  assert.equal((await checkDestination(feed, destinationFor('https://files.example.test/help'), () => START)).state, 'no_match');
  assert.equal((await checkDestination(feed, destinationFor('https://known-phish.example.test/somewhere'), () => START)).threat, 'PHISHING');
  assert.equal((await checkDestination(feed, destinationFor('https://www.known-phish.example.test'), () => START)).state, 'no_match');
  assert.equal(destinationFor('file:///something'), null);
});

test('validates bounds and refuses broadened, duplicate, expired, and future-dated indicators', async () => {
  for (const invalid of [
    raw([HOST, HOST]), raw([{ ...HOST, value: '*.example.test' }]),
    raw([{ ...HASH, value: url }]), raw([{ ...HOST, url }]), { ...raw([HOST]), url },
    raw([HOST], 0), raw([HOST], 86400001)
  ]) assert.equal(parseSnapshot(invalid, START), null);
  assert.equal(parseSnapshot(raw([HOST]), START - 60001), null);
  const feed = parseSnapshot(raw([HOST], 1000), START);
  assert.equal((await checkDestination(feed, destinationFor('https://' + HOST.value), () => START + 1000)).state,
    'unavailable');
});

test('coalesces downloads and keeps fresh data offline until expiry, but revokes on rejection', async () => {
  let clock = START;
  let calls = 0;
  let mode = 'fresh';
  const values = {};
  const storage = {
    async get() { return values; },
    async set(update) { Object.assign(values, update); },
    async remove(key) { delete values[key]; }
  };
  const cache = createSnapshotCache(storage, async () => {
    calls++;
    if (mode === 'offline') throw new Error('No network');
    return mode === 'reject' ? null : raw([HOST], 100000);
  }, () => clock);
  const credential = { id: 'owner' };
  await Promise.all([cache.current(credential), cache.current(credential)]);
  assert.equal(calls, 1);
  mode = 'offline';
  clock += 60000;
  assert.ok(await cache.current(credential));
  assert.equal(calls, 2);
  clock += 40000;
  assert.equal(await cache.current(credential), null);
  mode = 'fresh';
  clock = START;
  await cache.clear();
  await cache.current(credential);
  mode = 'reject';
  clock += 60000;
  assert.equal(await cache.current(credential), null);
});
