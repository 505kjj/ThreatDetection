import assert from 'node:assert/strict';
import test from 'node:test';
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

function chromeModel() {
  const handlers = {};
  const hook = name => ({ addListener(fn) { handlers[name] = fn; } });
  const accessLevels = {};
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
    runtime: { id: extensionId, getURL: path => extensionUrl + path, onMessage: hook('message') },
    storage: { local: area('local'), session: area('session'), onChanged: hook('change') },
    webNavigation: { async getFrame({ tabId }) { return frames[tabId]; }, onCommitted: hook('committed') },
    tabs: { async query() { return []; }, onRemoved: hook('removed') },
    permissions: {
      async contains({ origins }) {
        return origins.every(origin => origin === 'http://127.0.0.1/*' || origin === 'https://api.example.test/*');
      },
      onRemoved: hook('permissionRemoved')
    }
  };
  return {
    api, stored, accessLevels, frames, sender, handlers,
    message(body, from = sender()) {
      return new Promise(resolve => {
        if (!handlers.message(body, from, resolve)) resolve(undefined);
      });
    }
  };
}

async function worker(response) {
  const mock = chromeModel();
  const previousChrome = globalThis.chrome;
  const previousFetch = globalThis.fetch;
  const calls = [];
  globalThis.chrome = mock.api;
  globalThis.fetch = async (url, options) => {
    options.signal.throwIfAborted();
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
    return { ...mock, calls, options, save, status, restore() {
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
  assert.deepEqual(await state.message({ type: 'PAGE_CONFIGURATION' }), { active: false });
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
  assert.equal((await state.status()).state, 'safe');
  assert.equal((await state.status(2)).state, 'waiting');
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
