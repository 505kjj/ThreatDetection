import assert from 'node:assert/strict';
import test from 'node:test';
import { blockRules, bypassRule, createBlockRules } from '../block-rules.mjs';
import { createBrowserProtection } from '../browser-protection.mjs';
import { checkDestination, destinationFor, parseSnapshot } from '../reputation.mjs';

const START = Date.parse('2026-01-01T00:00:00Z');
const host = 'phishing.example.test';
const path = 'https://shared.example.test/exact-Path';
const feed = (entries = [{ kind: 'HOST', value: host, threat: 'PHISHING' }]) =>
  parseSnapshot({ entries, generatedAt: new Date(START).toISOString(),
    expiresAt: new Date(START + 60000).toISOString() }, START);

test('network rules are exact for host boundaries, scheme, port and case-sensitive paths', () => {
  const [hostRule, pathRule] = blockRules(feed([
    { kind: 'HOST', value: host, threat: 'PHISHING' },
    { kind: 'URL_PATH', value: path, threat: 'MALWARE' }
  ]));
  const hostMatch = new RegExp(hostRule.condition.regexFilter, 'i');
  const pathMatch = new RegExp(pathRule.condition.regexFilter);
  for (const url of [`https://${host}/`, `http://${host}.:8123/account`, `https://user@${host}/`]) {
    assert.ok(hostMatch.test(url), url);
  }
  for (const url of [`https://child.${host}/`, `https://${host}.example.org/`, `https://${host}@example.org/`]) {
    assert.ok(!hostMatch.test(url), url);
  }
  assert.ok(pathMatch.test(path + '?fixture=private'));
  for (const url of [path + '/', path.toLowerCase(), path.replace('https:', 'http:'), path + '.bak']) {
    assert.ok(!pathMatch.test(url), url);
  }
  assert.deepEqual(hostRule.condition.resourceTypes, ['main_frame']);
});

test('operator paths are validated and a hash cannot be compiled into a request rule', async () => {
  for (const value of [path + '?secret', path + '#fragment', 'https://user@shared.example.test/path',
    'https://shared.example.test:443/path', 'https://shared.example.test/a/../path']) {
    assert.equal(feed([{ kind: 'URL_PATH', value, threat: 'MALWARE' }]), null);
  }
  const hashOnly = feed([{ kind: 'URL_SHA256', value: 'a'.repeat(64), threat: 'MALWARE' }]);
  assert.deepEqual(blockRules(hashOnly), []);
  const exact = feed([{ kind: 'URL_PATH', value: path, threat: 'MALWARE' }]);
  const result = await checkDestination(exact, destinationFor(path + '?private=true'), () => START);
  assert.deepEqual(result.evidence, { kind: 'URL_PATH', value: path });
});

test('rule grouping stays within session regex limits and reserves exception capacity', () => {
  const entries = Array.from({ length: 20000 }, (_, i) =>
    ({ kind: 'HOST', value: `threat-fixture-${i}.example.test`, threat: 'PHISHING' }));
  const rules = blockRules(feed(entries));
  assert.ok(rules.length > 1 && rules.length <= 800);
  for (const rule of rules) assert.ok(rule.condition.regexFilter.length < 340);
  assert.equal(new Set(rules.map(rule => rule.id)).size, rules.length);
});

test('the exception rule permits one exact clean GET in a single tab from the extension', () => {
  const rule = bypassRule(5001, 19, 'abcdefghijklmnopabcdefghijklmnop', path);
  assert.equal(rule.action.type, 'allow');
  assert.equal(rule.priority, 2);
  assert.deepEqual(rule.condition.tabIds, [19]);
  assert.deepEqual(rule.condition.initiatorDomains, ['abcdefghijklmnopabcdefghijklmnop']);
  assert.deepEqual(rule.condition.requestMethods, ['get']);
  const allowed = new RegExp(rule.condition.regexFilter);
  assert.ok(allowed.test(path));
  assert.ok(!allowed.test(path + '?token=private'));
  assert.ok(!allowed.test(path + '/another'));
});

test('snapshot replacement, timeout and worker restart revoke old rules and exceptions', async () => {
  let now = START;
  const installed = new Map([[5001, { id: 5001 }]]);
  const api = {
    async getSessionRules() { return Array.from(installed.values()); },
    async updateSessionRules({ removeRuleIds = [], addRules = [] }) {
      for (const id of removeRuleIds) installed.delete(id);
      for (const rule of addRules) installed.set(rule.id, rule);
    }
  };
  const rules = createBlockRules(api, 'fixture-extension', () => now);
  const protection = createBrowserProtection({ runtime: { getURL: name => 'chrome-extension://fixture/' + name },
    storage: { session: {} } }, rules, () => now);
  const snapshot = feed();
  await rules.setSnapshot(snapshot);
  assert.ok(!installed.has(5001));
  assert.equal(await rules.allowOnce(7, path, START + 20000), true);
  assert.equal(await rules.allowOnce(7, path, START + 20000), false);
  assert.ok(installed.has(5001));
  now += 20000;
  await protection.expire(7);
  assert.ok(!installed.has(5001));
  assert.equal(await rules.allowOnce(7, path, START + 20000), false);
  assert.equal(await rules.allowOnce(7, path, START + 40000), true);
  await rules.setSnapshot(snapshot, true);
  assert.ok(!installed.has(5001));
  now = START + 60000;
  assert.equal(rules.snapshot(), null);
  await rules.setSnapshot(snapshot);
  assert.equal(installed.size, 0);
});

test('warning details and exceptions require the live private document and its tab-bound nonce', async () => {
  let now = START;
  let allowCalls = 0;
  const snapshot = feed();
  const url = 'chrome-extension://fixture/warning.html#fixture-token';
  const record = { token: 'fixture-token', host, evidence: { kind: 'HOST', value: host },
    threat: 'PHISHING', phase: 'before_request', until: START + 1000, resume: 'https://' + host + '/' };
  const sender = { url, documentId: 'warning-document', documentLifecycle: 'active', frameId: 0, tab: { id: 7 } };
  const chrome = {
    runtime: {
      getURL: name => 'chrome-extension://fixture/' + name,
      async getContexts({ tabIds: [tabId] }) {
        return tabId === 7 ? [{ documentId: sender.documentId, documentUrl: url }] : [];
      }
    },
    storage: { session: {
      async get() { return { 'network-warning:7': record }; },
      async remove() {}
    } }
  };
  const rules = { snapshot: () => snapshot, async allowOnce() { allowCalls++; return false; } };
  const protection = createBrowserProtection(chrome, rules, () => now);
  assert.equal((await protection.message('GET_NETWORK_WARNING', sender, record.token)).active, true);
  for (const altered of [{ frameId: 2 }, { url: 'https://example.test/warning.html#fixture-token' },
    { tab: { id: 8 } }, { documentLifecycle: 'cached' }, { documentId: 'different-document' }]) {
    assert.deepEqual(await protection.message('PROCEED_ONCE', { ...sender, ...altered }, record.token), { active: false });
  }
  assert.deepEqual(await protection.message('PROCEED_ONCE', sender, 'different-token'), { active: false });
  now += 1000;
  assert.deepEqual(await protection.message('PROCEED_ONCE', sender, record.token), { active: false });
  assert.equal(allowCalls, 0);
});
