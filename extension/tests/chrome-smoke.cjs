const assert = require('node:assert/strict');
const { spawn, spawnSync } = require('node:child_process');
const { createHash, randomBytes } = require('node:crypto');
const { once } = require('node:events');
const { createServer } = require('node:http');
const { mkdtempSync, renameSync, rmSync, rmdirSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const path = require('node:path');
const { chromium } = require('playwright');

const extension = path.resolve(__dirname, '..');
const jar = path.resolve(extension, '../backend/target/threat-detection-0.0.1-SNAPSHOT.jar');
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
const token = randomBytes(32).toString('base64url');
const privateMarkers = ['private-path', 'private-query', 'private-fragment', 'private-form-value',
  'private-otp-value', 'private-card-value', 'private-cookie-value'];

function javaExecutable() {
  // The Oracle Java launcher shim on Windows can start a separate JVM process.
  const result = spawnSync('java', ['-XshowSettings:properties', '-version'], { encoding: 'utf8' });
  const home = /^\s*java\.home = (.+)$/m.exec(result.stderr ?? '')?.[1]?.trim();
  if (result.status !== 0 || !home) throw new Error('Java 21 is required');
  return path.join(home, 'bin', process.platform === 'win32' ? 'java.exe' : 'java');
}

async function eventually(get, valid, description, attempts = 100) {
  for (let attempt = 0; attempt < attempts; attempt++) {
    const value = await get();
    if (valid(value)) return value;
    await wait(100);
  }
  throw new Error('Timed out waiting for ' + description);
}

async function stop(process) {
  if (!process || process.exitCode !== null || process.signalCode !== null) return;
  const exited = once(process, 'exit');
  process.kill();
  await exited;
}

async function startBackend(java, extensionOrigin, snapshotPath, port = 0) {
  const config = {
    threat: { security: {
      'allowed-origins': [extensionOrigin],
      clients: { 'chrome-smoke': {
        role: 'BROWSER',
        'token-sha256': createHash('sha256').update(token).digest('hex')
      } }
    } }
  };
  const process = spawn(java, ['-jar', jar, '--server.address=127.0.0.1', '--server.port=' + port], {
    env: { ...globalThis.process.env, SPRING_APPLICATION_JSON: JSON.stringify(config),
      THREAT_REPUTATION_SNAPSHOT_PATH: snapshotPath, THREAT_REPUTATION_RELOAD_INTERVAL: 'PT0.2S' }
  });
  let logs = '';
  process.stdout.on('data', chunk => { logs = (logs + chunk).slice(-8000); });
  process.stderr.on('data', chunk => { logs = (logs + chunk).slice(-8000); });
  process.on('error', error => { logs += String(error); });
  try {
    const deadline = Date.now() + 90000;
    while (Date.now() < deadline) {
      const match = /Tomcat started on port (\d+)/.exec(logs);
      if (match) {
        const health = await fetch('http://127.0.0.1:' + match[1] + '/api/health',
          { signal: AbortSignal.timeout(2000) }).catch(() => null);
        if (health?.ok) return { process, port: Number(match[1]) };
      }
      if (process.exitCode !== null) break;
      await wait(500);
    }
    throw new Error('Backend failed to start\n' + logs);
  } catch (error) {
    await stop(process);
    throw error;
  }
}

async function tabRecord(worker) {
  return worker.evaluate(async () => {
    const records = await chrome.storage.session.get(null);
    return Object.entries(records).find(([key]) => key.startsWith('tab-status:'))?.[1];
  });
}

async function focusPassword(site) {
  await site.bringToFront();
  await site.locator('#other').focus();
  await site.locator('#password').focus();
}

async function badge(worker, url) {
  return worker.evaluate(async url => {
    for (const tab of await chrome.tabs.query({})) {
      const frame = await chrome.webNavigation.getFrame({ tabId: tab.id, frameId: 0 }).catch(() => null);
      if (frame?.url === url) return chrome.action.getBadgeText({ tabId: tab.id });
    }
    return null;
  }, url);
}

function writeFixture(file, content) {
  const pending = file + '.next';
  writeFileSync(pending, JSON.stringify(content));
  renameSync(pending, file);
}

async function inPageWarning(page, phrase) {
  const cdp = await page.context().newCDPSession(page);
  try {
    const { root } = await cdp.send('DOM.getDocument', { depth: -1, pierce: true });
    const contains = node => node.nodeValue?.includes(phrase) ||
      (node.children ?? []).some(contains) || (node.shadowRoots ?? []).some(contains);
    return contains(root);
  } finally {
    await cdp.detach();
  }
}

async function main() {
  const java = javaExecutable();
  const requests = [];
  let holdCleanRoot = false;
  let releaseCleanRoot;
  const phishingHost = 'hdfcbank-help.example.net';
  const cautionHost = 'sbi.bank.in.example.org';
  const fixture = createServer((request, response) => {
    const url = new URL(request.url, 'http://' + request.headers.host);
    requests.push({ host: url.hostname, path: url.pathname, query: url.search });
    if (url.pathname === '/redirect-threat') {
      response.writeHead(302, { Location: `http://${phishingHost}:${fixture.address().port}/redirected?case=private-query` });
      response.end();
      return;
    }
    const send = () => {
      response.writeHead(200, { 'Content-Type': 'text/html', 'Set-Cookie': 'fixture=private-cookie-value; HttpOnly' });
      response.end('<!doctype html><title>Local login fixture</title><link rel="icon" href="data:,"><input id="other">' +
        '<input id="password" type="password" value="private-form-value">' +
        '<input id="otp" autocomplete="one-time-code" value="private-otp-value">' +
        '<input id="card" autocomplete="cc-number" value="private-card-value">');
    };
    if (holdCleanRoot && url.hostname === phishingHost && url.pathname === '/') releaseCleanRoot = send;
    else send();
  });
  await new Promise(resolve => fixture.listen(0, '127.0.0.1', resolve));
  const folder = mkdtempSync(path.join(tmpdir(), 'threat-reputation-smoke-'));
  const snapshotPath = path.join(folder, 'snapshot.json');
  const localSite = 'http://127.0.0.1:' + fixture.address().port;
  const phishingRoot = 'http://' + phishingHost + ':' + fixture.address().port + '/';
  const phishingFixture = phishingRoot + 'private-path?fixture=private-query#private-fragment';
  const cautionFixture = 'http://' + cautionHost + ':' + fixture.address().port + '/private-path?x=private-query';
  function publish(lifetime) {
    writeFixture(snapshotPath, {
      generatedAt: new Date(Date.now() - 1000).toISOString(),
      expiresAt: new Date(Date.now() + lifetime).toISOString(),
      entries: [
        { kind: 'HOST', value: phishingHost, threat: 'PHISHING' },
        { kind: 'URL_PATH', value: localSite + '/download-fixture', threat: 'MALWARE' },
        { kind: 'URL_SHA256', value: createHash('sha256').update(localSite + '/legacy-hash').digest('hex'),
          threat: 'MALWARE' }
      ]
    });
  }
  let browser;
  let backend;
  try {
    publish(300000);
    browser = await chromium.launchPersistentContext('', {
      channel: 'chromium',
      args: ['--disable-extensions-except=' + extension, '--load-extension=' + extension,
        '--no-proxy-server', '--host-resolver-rules=' +
          [phishingHost, cautionHost].map(host => 'MAP ' + host + ' 127.0.0.1').join(',')]
    });
    const worker = browser.serviceWorkers()[0] ?? await browser.waitForEvent('serviceworker');
    const extensionOrigin = new URL(worker.url()).origin === 'null'
      ? 'chrome-extension://' + new URL(worker.url()).hostname
      : new URL(worker.url()).origin;
    backend = await startBackend(java, extensionOrigin, snapshotPath);
    const origin = 'http://127.0.0.1:' + backend.port;
    const apiCalls = [];
    const snapshotCalls = [];
    browser.on('request', request => {
      if (request.method() === 'POST' && request.url().startsWith(origin + '/api/threat/')) {
        apiCalls.push(request);
      }
      if (request.method() === 'GET' && request.url().startsWith(origin + '/api/threat/reputation/snapshot')) {
        snapshotCalls.push(request);
      }
    });

    const options = await browser.newPage();
    await options.goto(extensionOrigin + '/options.html');
    await options.locator('#tokenStatus').getByText('Browser token required.').waitFor();
    await options.locator('#backendOrigin').fill(origin);
    async function refreshCredential() {
      await options.locator('#browserToken').fill(token);
      await options.locator('#saveConnection').click();
      await eventually(() => options.locator('#browserToken').inputValue(), value => value === '', 'saved token');
    }
    await refreshCredential();
    await options.locator('#tokenStatus').getByText('Browser token set for this session.').waitFor();
    await options.locator('#newDomain').fill('127.0.0.1');
    await options.locator('#addDomain').click();
    await options.locator('#siteList').getByText('127.0.0.1', { exact: true }).waitFor();

    const site = await browser.newPage();
    await site.goto(localSite + '/login/private-path?fixture=private-query#private-fragment');
    const first = await eventually(() => tabRecord(worker), result => result?.verdict.state === 'safe', 'initial verdict');
    await wait(600);
    await focusPassword(site);
    await eventually(() => apiCalls, calls => calls.some(request =>
      request.postDataJSON()?.eventType === 'password_focus'), 'password focus request');
    const checked = await eventually(() => tabRecord(worker),
      result => result?.verdict.state === 'safe' && result.checkedAt > first.checkedAt, 'password focus verdict');
    const start = apiCalls.find(request => request.url().endsWith('/session/start'));
    assert.deepEqual(start.postDataJSON(), { domain: '127.0.0.1' });
    for (const request of apiCalls) {
      assert.ok(request.serviceWorker(), 'API traffic must come from the service worker');
      assert.equal((await request.allHeaders()).authorization, 'Bearer ' + token);
      assert.equal((await request.allHeaders()).referer, undefined);
      assert.equal((await request.allHeaders()).cookie, undefined);
      for (const marker of privateMarkers) assert.ok(!request.postData().includes(marker));
    }
    console.log('Chrome: service worker authenticated and sent only the allowed hostname and activity fields');

    const popup = await browser.newPage();
    await popup.goto(extensionOrigin + '/popup.html');
    async function assertStatus(page, label) {
      await page.bringToFront();
      await options.evaluate(() => chrome.storage.session.set({ smokeRefresh: crypto.randomUUID() }));
      await popup.locator('#statusText').getByText(label, { exact: true }).waitFor();
    }
    const hits = (host, route) => requests.filter(request => request.host === host && (!route || request.path === route));
    const installed = () => worker.evaluate(() => chrome.declarativeNetRequest.getSessionRules());
    async function blocked(page, url, label = 'Known threat blocked') {
      await page.goto(url).catch(error => {
        if (!/ERR_BLOCKED_BY_CLIENT|ERR_ABORTED/.test(error.message)) throw error;
      });
      await page.waitForURL(new RegExp('^' + extensionOrigin + '/warning.html#'));
      await page.getByRole('heading', { name: label, exact: true }).waitFor({ timeout: 6000 }).catch(async error => {
        const diagnostics = await worker.evaluate(async () => ({
          frames: await Promise.all((await chrome.tabs.query({})).map(async tab => {
            const frame = await chrome.webNavigation.getFrame({ tabId: tab.id, frameId: 0 }).catch(() => null);
            const key = 'network-warning:' + tab.id;
            const record = (await chrome.storage.session.get(key))[key];
            return { id: tab.id, warningPage: frame?.url?.includes('/warning.html'), fragment: frame?.url?.includes('#'),
              lifecycle: frame?.documentLifecycle, hasDocument: !!frame?.documentId,
              hasRecord: !!record, tokenMatches: !!record && frame?.url?.endsWith('#' + record.token) };
          }))
        }));
        throw new Error((await page.locator('#headline').textContent()) + ' ' + JSON.stringify(diagnostics), { cause: error });
      });
      for (const marker of privateMarkers) assert.ok(!page.url().includes(marker));
    }
    await eventually(installed, rules => rules.filter(rule => rule.action.type === 'block').length === 2,
      'installed network rules');
    await assertStatus(site, 'No known threat match');
    const malware = await browser.newPage();
    const sessionStarts = () => apiCalls.filter(call => call.url().endsWith('/session/start'));
    const firstStarts = sessionStarts().length;
    await blocked(malware, localSite + '/download-fixture?case=private-query#private-fragment');
    await malware.getByText('Reported threat: malware.').waitFor();
    assert.equal(hits('127.0.0.1', '/download-fixture').length, 0);
    assert.equal(sessionStarts().length, firstStarts, 'blocked exact path must not start a behavioral session');
    assert.equal(await malware.locator('#review').isVisible(), false);
    await malware.getByRole('button', { name: 'Leave this site' }).click();
    await malware.waitForURL('about:blank');
    await malware.goto(localSite + '/download-fixture/help');
    assert.equal(hits('127.0.0.1', '/download-fixture/help').length, 1);
    await malware.goto(localSite + '/Download-fixture');
    assert.equal(hits('127.0.0.1', '/Download-fixture').length, 1);
    const phish = await browser.newPage();
    await blocked(phish, phishingFixture);
    await phish.getByText(/subdomain uses the HDFC Bank name/).waitFor();
    assert.equal(hits(phishingHost).length, 0);
    await assertStatus(phish, 'Known malicious website');
    assert.equal(await worker.evaluate(async markers => {
      const state = JSON.stringify(await chrome.storage.session.get(null));
      return markers.some(marker => state.includes(marker));
    }, privateMarkers), false, 'warning state must not store private navigation components');
    const redirect = await browser.newPage();
    await blocked(redirect, localSite + '/redirect-threat');
    assert.equal(hits('127.0.0.1', '/redirect-threat').length, 1);
    assert.equal(hits(phishingHost).length, 0);
    console.log('Chrome: DNR blocked the host, exact path and redirect target before any request reached them');
    const forged = await browser.newPage();
    await forged.goto(phish.url());
    await forged.getByRole('heading', { name: 'Protection unavailable' }).waitFor();
    assert.equal(await forged.locator('#review').isVisible(), false);
    await forged.close();

    const legacy = await browser.newPage();
    await blocked(legacy, localSite + '/legacy-hash', 'Known threat detected');
    assert.equal(hits('127.0.0.1', '/legacy-hash').length, 1);
    assert.equal(await legacy.locator('#review').isVisible(), false);
    await legacy.goto(localSite + '/help-fixture');
    await legacy.evaluate(() => history.pushState({}, '', '/legacy-hash'));
    await legacy.getByRole('heading', { name: 'Known threat detected' }).waitFor();
    assert.equal(hits('127.0.0.1', '/legacy-hash').length, 1);
    await legacy.close();
    console.log('Chrome: hash-only and same-document matches used an accurately labeled post-navigation warning');
    assert.equal(await badge(worker, site.url()), '');
    const caution = await browser.newPage();
    await caution.goto(cautionFixture);
    await assertStatus(caution, 'Possible financial website impersonation');
    await popup.locator('#impersonationReasons').getByText(/official State Bank of India address is embedded/).waitFor();
    await eventually(() => inPageWarning(caution, 'official State Bank of India address is embedded'),
      value => value === true, 'in-page explanation');
    assert.equal(await badge(worker, caution.url()), '!');
    await phish.getByRole('heading', { name: 'Known threat blocked' }).waitFor();
    assert.equal(await badge(worker, site.url()), '');
    assert.equal(caution.url(), cautionFixture, 'a name-only warning must leave the user on the page');
    assert.equal(apiCalls.some(call => call.postData()?.includes(cautionHost)), false,
      'the local impersonation check must not send the hostname to the API');
    console.log('Chrome: local impersonation explains the address evidence without transmitting the hostname or blocking');
    assert.ok(snapshotCalls.length > 0);
    for (const request of snapshotCalls) {
      assert.equal(request.url(), origin + '/api/threat/reputation/snapshot');
      assert.equal(request.postData(), null);
      assert.ok(request.serviceWorker());
      const headers = await request.allHeaders();
      assert.equal(headers.authorization, 'Bearer ' + token);
      assert.equal(headers.referer, undefined);
      assert.equal(headers.cookie, undefined);
    }
    assert.equal(sessionStarts().some(call => call.postDataJSON().domain === phishingHost), false,
      'blocked phishing host must not start a behavioral session');
    await malware.close();
    const parallel = await browser.newPage();
    holdCleanRoot = true;
    await phish.getByRole('button', { name: 'Review one-time exception' }).click();
    const proceeding = phish.getByRole('button', { name: 'Continue once' }).click();
    await eventually(() => releaseCleanRoot, release => typeof release === 'function', 'the exception request');
    try {
      assert.ok((await installed()).some(rule => rule.action.type === 'allow'));
      await blocked(parallel, phishingRoot);
      assert.equal(hits(phishingHost, '/').length, 1, 'the other tab may not reuse the exception');
    } finally {
      holdCleanRoot = false;
      releaseCleanRoot();
      await proceeding;
    }
    await phish.waitForURL(phishingRoot);
    assert.deepEqual(hits(phishingHost).map(({ path, query }) => [path, query]), [['/', '']]);
    await eventually(installed, rules => rules.every(rule => rule.action.type !== 'allow'), 'consumed bypass');
    await redirect.getByRole('heading', { name: 'Known threat blocked' }).waitFor();
    await blocked(phish, phishingRoot);
    assert.equal(hits(phishingHost).length, 1);
    await redirect.close();
    await parallel.close();
    await phish.close();
    console.log('Chrome: private interstitial is bound to its tab; a clean one-time exception is consumed after navigation');
    await site.bringToFront();
    await wait(650);
    for (let i = 0; i < 28; i++) {
      await site.mouse.click(300, 150);
      if (i % 7 === 6) await wait(550);
    }
    await assertStatus(site, 'Suspicious activity, unconfirmed');
    assert.equal(await badge(worker, site.url()), '');
    console.log('Chrome: behavior-only signals stay unconfirmed and never set the malicious badge');

    await stop(backend.process);
    const offline = await browser.newPage();
    await blocked(offline, phishingFixture);
    assert.equal(hits(phishingHost).length, 1);
    await offline.close();
    await wait(600);
    await focusPassword(site);
    await eventually(() => tabRecord(worker), result =>
      result?.verdict.state === 'unavailable' && result.checkedAt > checked.checkedAt, 'offline status', 230);
    await assertStatus(site, 'Protection unavailable');
    backend = await startBackend(java, extensionOrigin, snapshotPath, backend.port);
    await focusPassword(site);
    const recovered = await eventually(() => tabRecord(worker), result => result?.verdict.state === 'safe' &&
      result.sessionId !== first.sessionId, 'new session after restart', 230);
    assert.ok(recovered.sessionId);
    console.log('Chrome: network failure reported unavailable and a backend restart renewed the session');

    await options.locator('#disableMonitoring').click();
    await options.locator('#monitoringStatus').getByText('Monitoring paused.').waitFor();
    await assertStatus(caution, 'Monitoring paused');
    await popup.locator('#impersonationSection').waitFor({ state: 'hidden' });
    assert.equal(await badge(worker, caution.url()), '');
    await eventually(installed, rules => rules.length === 0, 'paused rules cleared');
    await wait(600);
    const before = apiCalls.length;
    await focusPassword(site);
    await wait(600);
    assert.equal(apiCalls.length, before);
    console.log('Chrome: pausing monitoring stopped requests from the open document');

    await options.locator('#enableMonitoring').click();
    await site.close();
    writeFixture(snapshotPath, { invalid: 'synthetic-provider-error' });
    const headers = { Authorization: 'Bearer ' + token };
    const snapshotEndpoint = origin + '/api/threat/reputation/snapshot';
    await eventually(async () => (await fetch(snapshotEndpoint, { headers })).status,
      status => status === 503, 'provider failure response');
    await refreshCredential();
    const stale = await browser.newPage();
    await stale.goto(phishingFixture);
    await assertStatus(stale, 'Protection unavailable');
    await popup.locator('#impersonationReasons').getByText(/subdomain uses the HDFC Bank name/).waitFor();
    await eventually(() => inPageWarning(stale, 'The protection service is unavailable.'),
      value => value === true, 'degraded in-page warning');
    assert.equal(await badge(worker, stale.url()), '');
    publish(17000);
    await eventually(async () => (await fetch(snapshotEndpoint, { headers })).status,
      status => status === 200, 'restored short-lived snapshot');
    await refreshCredential();
    await eventually(installed, rules => rules.length === 2, 'restored network rules');
    await stale.goto('about:blank');
    await blocked(stale, phishingFixture);
    await stale.getByRole('heading', { name: 'Protection unavailable' }).waitFor();
    await eventually(installed, rules => rules.length === 0, 'expired rules removed', 260);
    await stale.goto(phishingFixture);
    await assertStatus(stale, 'Protection unavailable');
    assert.equal(hits(phishingHost, '/private-path').length, 2);
    console.log('Chrome: invalid and expired snapshots report unavailable and stop blocking');
  } finally {
    if (browser) await browser.close();
    await stop(backend?.process);
    fixture.closeAllConnections();
    await new Promise(resolve => fixture.close(resolve));
    rmSync(snapshotPath, { force: true });
    rmSync(snapshotPath + '.next', { force: true });
    rmdirSync(folder);
  }
}

main().catch(error => {
  console.error(error.stack ?? error.message);
  process.exitCode = 1;
});
