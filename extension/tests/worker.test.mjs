import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { analysisFields } from '../backend-api.mjs';
import { backendOrigin, matchingSite, newSite } from '../settings.mjs';

const extensionId = 'abcdefghijklmnopabcdefghijklmnop';
const extensionUrl = 'chrome-extension://' + extensionId + '/';
const defaultOrigin = 'http://127.0.0.1:8081';
const token = 'a'.repeat(43);
const originalSession = 'e647a3e4-42e4-43c1-a8bd-4d5cd065e2b4';
const renewedSession = '1c37f557-0a20-4b9c-b557-c7b8b7daebc7';
const pageUrl = 'https://bank.example.test/login/private?fixture=secret#fragment';
const safe = { riskLevel: 'Safe', action: 'ALLOW', riskScore: 0, reasons: ['No warning'] };
const event = { type: 'TELEMETRY', eventType: 'password_focus', sensitivePage: true };
const snapshot = (entries = []) => ({
  generatedAt: new Date(Date.now() - 1000).toISOString(),
  expiresAt: new Date(Date.now() + 60000).toISOString(),
  entries
});

function chromeModel() {
  const handlers = {};
  const hook = name => ({ addListener(fn) { handlers[name] = fn; } });
  const accessLevels = {};
  const alarms = new Map();
  const badges = new Map();
  const stored = {
    local: { backendUrl: defaultOrigin, monitoredSites: [newSite('bank.example.test')],
      session_old: 'legacy-id', _latestRisk: { riskLevel: 'High Risk' } },
    session: {}
  };
  const frames = {
    1: { url: pageUrl, documentId: 'current-1', documentLifecycle: 'active' },
    2: { url: pageUrl, documentId: 'current-2', documentLifecycle: 'active' }
  };
  const sender = (tabId = 1) => ({
    ...frames[tabId], id: extensionId, frameId: 0, tab: { id: tabId }
  });
  function area(name) {
    const data = stored[name];
    return {
      async setAccessLevel({ accessLevel }) { accessLevels[name] = accessLevel; },
      async get(keys) {
        if (keys === null) return structuredClone(data);
        return structuredClone(Object.fromEntries([keys].flat().filter(key => key in data)
          .map(key => [key, data[key]])));
      },
      async set(values) {
        Object.assign(data, structuredClone(values));
        handlers.change?.(values, name);
      },
      async remove(keys) {
        for (const key of [keys].flat()) delete data[key];
        handlers.change?.(Object.fromEntries([keys].flat().map(key => [key, {}])), name);
      }
    };
  }
  const api = {
    runtime: { id: extensionId, getURL: path => extensionUrl + path, async getContexts() { return []; },
      onMessage: hook('message') },
    storage: { local: area('local'), session: area('session'), onChanged: hook('change') },
    webNavigation: {
      async getFrame({ tabId }) { return frames[tabId]; },
      onCommitted: hook('committed'), onHistoryStateUpdated: hook('history'),
      onBeforeNavigate: hook('before'), onErrorOccurred: hook('error')
    },
    tabs: { async query() { return []; }, async sendMessage() {}, async update() {}, onRemoved: hook('removed') },
    declarativeNetRequest: {
      async getSessionRules() { return []; },
      async updateSessionRules() {}
    },
    action: {
      async setBadgeText({ tabId, text }) { badges.set(tabId, text); },
      async setBadgeBackgroundColor() {}
    },
    alarms: {
      async get(name) { return alarms.get(name); },
      async create(name, { when }) { alarms.set(name, { scheduledTime: when }); },
      async clear(name) { alarms.delete(name); },
      onAlarm: hook('alarm')
    },
    permissions: {
      async contains({ origins }) {
        return origins.every(origin => origin === 'http://127.0.0.1/*' || origin === 'https://api.example.test/*');
      },
      onRemoved: hook('permissionRemoved')
    }
  };
  return {
    api, stored, accessLevels, frames, sender, handlers, badges,
    message(body, from = sender()) {
      return new Promise(resolve => {
        if (!handlers.message(body, from, resolve)) resolve(undefined);
      });
    }
  };
}

async function worker(response, feed = () => json(snapshot())) {
  const mock = chromeModel();
  const previousChrome = globalThis.chrome;
  const previousFetch = globalThis.fetch;
  const calls = [];
  const downloads = [];
  globalThis.chrome = mock.api;
  globalThis.fetch = async (url, options) => {
    options.signal.throwIfAborted();
    if (options.method === 'GET') {
      downloads.push({ url, options });
      return feed();
    }
    const call = { url, options, body: JSON.parse(options.body) };
    calls.push(call);
    return response(call, calls.length);
  };
  try {
    await import('../background.js?test=' + crypto.randomUUID());
    const options = { id: extensionId, url: extensionUrl + 'options.html' };
    const popup = { id: extensionId, url: extensionUrl + 'popup.html' };
    const save = (origin, value) => mock.message({ type: 'SAVE_CONNECTION', origin, token: value }, options);
    const status = (tabId = 1) => mock.message({ type: 'GET_TAB_STATUS', tabId }, popup);
    return { ...mock, calls, downloads, options, save, status, restore() {
      globalThis.chrome = previousChrome;
      globalThis.fetch = previousFetch;
    } };
  } catch (error) {
    globalThis.chrome = previousChrome;
    globalThis.fetch = previousFetch;
    throw error;
  }
}

const json = (value, status = 200) => new Response(JSON.stringify(value), { status });

async function waitFor(predicate) {
  for (let attempt = 0; attempt < 80; attempt++) {
    if (await predicate()) return;
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  assert.fail('Timed out waiting for reporting');
}

test('dashboard consent is options-only, origin-bound and sends only classified evidence', async t => {
  const state = await worker(() => new Response(null, { status: 204 }));
  t.after(state.restore);
  const consent = enabled => ({ type: 'SET_THREAT_REPORTING', enabled });
  const monitorCalls = () => state.calls.filter(call => call.url.includes('/monitoring/'));
  const events = () => monitorCalls().filter(call => call.url.endsWith('/events'));
  state.frames[1].url = 'https://sbi.bank.in.example.org/private?fixture=secret#fragment';
  await state.save(defaultOrigin, token);
  assert.deepEqual(await state.message(consent(true)), { state: 'inactive' });
  assert.ok((await state.message({ type: 'PAGE_CONFIGURATION' })).verdict.impersonation.length);
  assert.equal(monitorCalls().length, 0);
  assert.deepEqual(await state.message(consent(true), state.options), { saved: true });
  await waitFor(() => monitorCalls().some(call => call.url.endsWith('/heartbeat')));
  assert.deepEqual(await state.message({ type: 'REPORT_THREAT', signal: 'MALWARE', action: 'BLOCKED' }),
    { state: 'inactive' });
  await state.message({ type: 'PAGE_CONFIGURATION', signal: 'MALWARE', action: 'BLOCKED', reason: 'private' });
  await state.status();
  await waitFor(() => events().length === 1);
  const [detection] = events();
  assert.deepEqual(Object.keys(detection.body).sort(), ['action', 'detectedAt', 'id', 'signal']);
  assert.equal(detection.body.signal, 'EMBEDDED_OFFICIAL_DOMAIN');
  assert.equal(detection.body.action, 'WARNED');
  assert.match(detection.body.id, /^[0-9a-f-]{36}$/);
  assert.ok(Number.isFinite(Date.parse(detection.body.detectedAt)));
  assert.equal(detection.options.credentials, 'omit');
  assert.equal(detection.options.referrerPolicy, 'no-referrer');
  assert.equal(detection.options.headers.Authorization, 'Bearer ' + token);
  const journal = JSON.stringify(state.stored.session['threat-reporting-journal']);
  assert.doesNotMatch(journal, /sbi|private|secret|fragment/);
  await state.save('https://api.example.test', token);
  assert.equal((await state.message({ type: 'GET_THREAT_REPORTING' }, state.options)).optedIn, false);
  await state.status();
  assert.equal(events().length, 1);
});

test('a dashboard failure leaves financial advisory decisions intact and opt-out removes the journal', async t => {
  const state = await worker(() => { throw new TypeError('offline fixture'); });
  t.after(state.restore);
  await state.save(defaultOrigin, token);
  await state.message({ type: 'SET_THREAT_REPORTING', enabled: true }, state.options);
  state.frames[1].url = 'https://sbi.bank.in.example.org/private';
  const verdict = await state.message({ type: 'PAGE_CONFIGURATION' });
  assert.equal(verdict.verdict.state, 'no_match');
  assert.equal(verdict.verdict.impersonation[0].kind, 'embedded_official_domain');
  await waitFor(async () => (await state.message({ type: 'GET_THREAT_REPORTING' }, state.options))
    .status === 'disconnected');
  await state.message({ type: 'SET_THREAT_REPORTING', enabled: false }, state.options);
  await waitFor(() => !('threat-reporting-journal' in state.stored.session));
  const before = state.calls.length;
  state.handlers.history({ frameId: 0, tabId: 1, documentId: 'current-1' });
  assert.ok((await state.status()).impersonation.length);
  assert.equal(state.calls.length, before);
});

test('origin validation and telemetry allowlisting match the secured contract', () => {
  assert.equal(backendOrigin('https://api.example.test:8443/'), 'https://api.example.test:8443');
  assert.equal(backendOrigin(defaultOrigin), defaultOrigin);
  for (const origin of ['http://api.example.test', 'https://user@api.example.test',
    'https://api.example.test/path', 'https://api.example.test/?secret=1',
    'https://api.example.test/#fragment', 'file:///tmp/backend']) {
    assert.equal(backendOrigin(origin), null);
  }
  assert.equal(analysisFields({ eventType: 'url_exfiltration' }, true), null);
  const fields = analysisFields({ ...event, redirectCount: 500, clicksLast10Sec: 50000,
    tabSwitchCount: -10, averageClickGapMs: 2.25, path: '/private', fieldType: 'secret' }, false);
  assert.deepEqual(fields, {
    eventType: 'password_focus', actionType: 'sensitive_action', pageCategory: 'sensitive_page',
    redirectCount: 0, averageClickGapMs: -1, clicksLast10Sec: 1000, pagesVisitedLast30Sec: 0,
    tabSwitchCount: 0, copyPasteCount: 0, formSubmitCount: 0
  });
  assert.equal(matchingSite([newSite('example.test'), { ...newSite('bank.example.test'), enabled: false }],
    'bank.example.test').enabled, false);
  assert.equal(matchingSite([newSite('bank.example.test')], 'bank.example.test.other.test'), null);
});

test('worker authenticates only the allowlisted requests and strips legacy browsing data', async t => {
  const state = await worker(call => json(call.url.endsWith('/session/start') ? { sessionId: originalSession } : safe));
  t.after(state.restore);
  assert.equal((await state.message({ type: 'PAGE_CONFIGURATION' })).active, false);
  assert.deepEqual(await state.save(defaultOrigin, token), { saved: true });
  assert.equal((await state.message({ type: 'PAGE_CONFIGURATION' })).active, true);
  const verdict = await state.message({ ...event, url: pageUrl, domain: 'untrusted.test', sessionId: 'untrusted',
    referrer: pageUrl, formValue: 'private' });
  assert.equal(verdict.state, 'safe');
  assert.deepEqual(state.calls.map(call => call.url), [
    defaultOrigin + '/api/threat/session/start', defaultOrigin + '/api/threat/analyze'
  ]);
  assert.deepEqual(state.calls[0].body, { domain: 'bank.example.test' });
  assert.deepEqual(state.calls[1].body, { sessionId: originalSession, ...analysisFields(event, false) });
  for (const { options } of state.calls) {
    assert.equal(options.headers.Authorization, 'Bearer ' + token);
    assert.equal(options.credentials, 'omit');
    assert.equal(options.redirect, 'error');
    assert.equal(options.referrerPolicy, 'no-referrer');
  }
  assert.equal(state.stored.local.session_old, undefined);
  assert.equal(state.stored.local._latestRisk, undefined);
  assert.equal(JSON.stringify(state.stored.local).includes(token), false);
  assert.deepEqual(state.accessLevels, { local: 'TRUSTED_CONTEXTS', session: 'TRUSTED_CONTEXTS' });
  assert.equal((await state.status()).state, 'no_match');
  assert.equal((await state.status(2)).reasons, undefined);
  assert.equal(state.downloads.length, 1);
  assert.equal(state.downloads[0].url, defaultOrigin + '/api/threat/reputation/snapshot');
  assert.equal(state.downloads[0].options.body, undefined);
});

test('worker rejects stale documents, subframes, and content attempts to change the backend', async t => {
  const state = await worker(() => { throw new Error('Must not fetch'); });
  t.after(state.restore);
  await state.save(defaultOrigin, token);
  await state.message({ type: 'SAVE_CONNECTION', origin: 'https://other.test', token });
  await state.message(event, { ...state.sender(), frameId: 1 });
  await state.message(event, { ...state.sender(), documentId: 'old' });
  await state.message(event, { ...state.sender(), url: 'https://other.test/' });
  await state.message(event, { ...state.sender(), documentLifecycle: 'prerender' });
  await state.message(event, { ...state.sender(), id: 'unexpected-extension' });
  assert.equal(state.calls.length, 0);
  assert.equal(state.stored.session.backendCredential.origin, defaultOrigin);
  assert.deepEqual(await state.save('https://api.example.test', ''), { saved: true });
  assert.equal(state.stored.session.backendCredential, undefined);
  assert.equal((await state.status()).cause, 'credential');
});

test('a lost server session is recreated once using the server-issued ID', async t => {
  const state = await worker((_call, count) => {
    if (count === 1) return json({ sessionId: originalSession });
    if (count === 2) return json({}, 404);
    if (count === 3) return json({ sessionId: renewedSession });
    return json(safe);
  });
  t.after(state.restore);
  await state.save(defaultOrigin, token);
  assert.equal((await state.message(event)).state, 'safe');
  assert.deepEqual(state.calls.map(call => call.body.sessionId), [undefined, originalSession, undefined, renewedSession]);
});

test('failed and unsupported responses never become blocking verdicts', async t => {
  let failure = 'auth';
  const state = await worker(call => {
    if (failure === 'auth') return json({}, 401);
    if (failure === 'offline') throw new Error('Network unavailable');
    if (call.url.endsWith('/start')) return json({ sessionId: originalSession });
    return json({ riskLevel: 'High Risk', action: 'FORCE_RELOGIN', riskScore: 90, reasons: [] });
  });
  t.after(state.restore);
  await state.save(defaultOrigin, token);
  const recheck = { ...event, eventType: 'recheck_risk' };
  assert.deepEqual(await state.message(recheck), { state: 'unavailable', cause: 'authentication' });
  failure = 'offline';
  assert.deepEqual(await state.message(recheck), { state: 'unavailable', cause: 'backend' });
  failure = 'blocking';
  assert.deepEqual(await state.message(recheck), { state: 'unavailable', cause: 'backend' });
  assert.equal((await state.status()).state, 'unavailable');
  await state.api.storage.local.set({ monitoringEnabled: false });
  assert.equal((await state.message(recheck)).state, 'inactive');
  assert.equal((await state.status()).state, 'paused');
});

test('confirms a URL-path hash only on its current tab and skips behavior telemetry', async t => {
  const hash = createHash('sha256').update('https://bank.example.test/login/private').digest('hex');
  const state = await worker(() => { throw new Error('Unexpected browsing telemetry'); },
    () => json(snapshot([{ kind: 'URL_SHA256', value: hash, threat: 'PHISHING' }])));
  t.after(state.restore);
  await state.save(defaultOrigin, token);
  state.frames[2].url = 'https://bank.example.test/login/public';
  assert.equal((await state.status(1)).state, 'confirmed');
  assert.equal((await state.status(2)).state, 'no_match');
  assert.equal(state.badges.get(1), 'STOP');
  assert.equal(state.badges.get(2), '');
  assert.equal((await state.message(event)).state, 'confirmed');
  assert.equal(state.calls.length, 0);
  assert.equal(state.downloads.length, 1);
  assert.ok(!JSON.stringify(state.stored.session).includes('/login/private'));
  state.frames[1].url = state.frames[2].url;
  state.handlers.history({ tabId: 1, frameId: 0, documentId: state.frames[1].documentId });
  assert.equal((await state.status(1)).state, 'no_match');
  assert.equal(state.badges.get(1), '');
});

test('does not publish a confirmation that arrives after same-document navigation', async t => {
  let release;
  let downloading;
  const started = new Promise(resolve => { downloading = resolve; });
  const body = new Promise(resolve => { release = resolve; });
  const hash = createHash('sha256').update('https://bank.example.test/login/private').digest('hex');
  const state = await worker(() => { throw new Error('Unexpected browsing telemetry'); }, () => {
    downloading();
    return body;
  });
  t.after(state.restore);
  await state.save(defaultOrigin, token);
  const old = state.status();
  await started;
  state.frames[1].url = 'https://bank.example.test/login/public';
  state.handlers.history({ tabId: 1, frameId: 0, documentId: state.frames[1].documentId });
  release(json(snapshot([{ kind: 'URL_SHA256', value: hash, threat: 'MALWARE' }])));
  assert.equal((await old).state, 'inactive');
  assert.equal((await state.status()).state, 'no_match');
  assert.notEqual(state.badges.get(1), 'STOP');
});

test('a missing provider returns unavailable, never no-match or a warning', async t => {
  const state = await worker(() => { throw new Error('Unexpected browsing telemetry'); }, () => json({}, 503));
  t.after(state.restore);
  await state.save(defaultOrigin, token);
  assert.equal((await state.status()).state, 'unavailable');
  assert.equal((await state.message(event)).cause, 'reputation');
  assert.equal(state.calls.length, 0);
});

test('local cautions add no browsing requests and never suppress known threats on verified scopes', async t => {
  const official = 'now.hdfc.bank.in';
  const state = await worker(() => { throw new Error('Unexpected browsing telemetry'); },
    () => json(snapshot([{ kind: 'HOST', value: official, threat: 'PHISHING' }])));
  t.after(state.restore);
  state.frames[1].url = 'https://sbi.bank.in.example.org/private?otp=synthetic';
  state.frames[2].url = 'https://' + official;
  const before = await state.status();
  assert.equal(before.state, 'unavailable');
  assert.equal(before.impersonation[0].kind, 'embedded_official_domain');
  await state.save(defaultOrigin, token);
  assert.equal((await state.status()).impersonation[0].kind, 'embedded_official_domain');
  assert.equal(state.badges.get(1), '!');
  const confirmed = await state.status(2);
  assert.equal(confirmed.state, 'confirmed');
  assert.equal(confirmed.impersonation, undefined);
  assert.equal(state.badges.get(2), 'STOP');
  assert.equal((await state.message({ type: 'PAGE_CONFIGURATION' })).active, false);
  assert.equal(state.calls.length, 0);
  assert.equal(state.downloads.length, 1);
  assert.equal(state.downloads[0].options.body, undefined);
  assert.equal(JSON.stringify(state.stored.session).includes('example.org'), false);
});

test('opted-in telemetry retains the local evidence through cached results and failures', async t => {
  let online = true;
  const state = await worker(call => {
    if (!online) throw new Error('Network unavailable');
    return json(call.url.endsWith('/start') ? { sessionId: originalSession } : safe);
  });
  t.after(state.restore);
  const host = 'hdfcbank.example.org';
  state.frames[1].url = 'https://' + host;
  await state.api.storage.local.set({ monitoredSites: [newSite(host)] });
  await state.save(defaultOrigin, token);
  assert.equal((await state.message({ type: 'PAGE_CONFIGURATION' })).active, true);
  for (let i = 0; i < 2; i++) {
    const verdict = await state.message(event);
    assert.equal(verdict.state, 'safe');
    assert.equal(verdict.impersonation[0].kind, 'subdomain_brand');
  }
  assert.equal(state.calls.length, 2);
  assert.deepEqual(state.calls[0].body, { domain: host });
  assert.deepEqual(state.calls[1].body, { sessionId: originalSession, ...analysisFields(event, false) });
  online = false;
  const unavailable = await state.message({ ...event, eventType: 'recheck_risk' });
  assert.equal(unavailable.state, 'unavailable');
  assert.equal(unavailable.impersonation[0].kind, 'subdomain_brand');
  assert.deepEqual((await state.status()).impersonation, unavailable.impersonation);
});
