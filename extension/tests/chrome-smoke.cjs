const assert = require('node:assert/strict');
const { spawn, spawnSync } = require('node:child_process');
const { createHash, randomBytes } = require('node:crypto');
const { once } = require('node:events');
const { createServer } = require('node:http');
const { mkdtempSync, renameSync, rmSync, rmdirSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const path = require('node:path');
const { chromium } = require('playwright');
const { createRuntime } = require('./windows-local-runtime.cjs');

const extension = path.resolve(__dirname, '..');
const jar = path.resolve(extension, '../backend/target/threat-detection-0.0.1-SNAPSHOT.jar');
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
let token = randomBytes(32).toString('base64url');
let adminToken = randomBytes(32).toString('base64url');
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
    threat: { monitoring: { 'synthetic-clients': ['chrome-smoke'] }, security: {
      'allowed-origins': [extensionOrigin],
      clients: { 'chrome-smoke': {
        role: 'BROWSER',
        'token-sha256': createHash('sha256').update(token).digest('hex')
      }, 'chrome-smoke-admin': {
        role: 'ADMIN',
        'token-sha256': createHash('sha256').update(adminToken).digest('hex')
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
        if (health?.ok) return { stop: () => stop(process), port: Number(match[1]), logs: () => logs };
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

async function writeFixture(file, content) {
  const pending = file + '.next';
  writeFileSync(pending, JSON.stringify(content));
  for (let attempt = 0;; attempt++) {
    try {
      renameSync(pending, file);
      return;
    } catch (error) {
      // Windows may hold the snapshot briefly while the backend reads it.
      if (attempt === 15 || !['EPERM', 'EACCES', 'EBUSY'].includes(error.code)) throw error;
      await wait(35);
    }
  }
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
  const useWindowsSetup = process.env.THREAT_SMOKE_LOCAL_SETUP === '1';
  if (useWindowsSetup && process.platform !== 'win32') throw new Error('Windows is required for the local setup smoke');
  const java = javaExecutable();
  const requests = [];
  let holdCleanRoot = false;
  let releaseCleanRoot;
  const phishingHost = 'hdfcbank-help.example.net';
  const cautionHost = 'sbi.bank.in.example.org';
  const destinationHost = 'forms.example.net';
  const fixture = createServer((request, response) => {
    const url = new URL(request.url, 'http://' + request.headers.host);
    requests.push({ host: url.hostname, path: url.pathname, query: url.search });
    if (url.pathname === '/redirect-threat') {
      response.writeHead(302, { Location: `http://${phishingHost}:${fixture.address().port}/redirected?case=private-query` });
      response.end();
      return;
    }
    if (url.pathname === '/redirect-financial-login') {
      response.writeHead(302, { Location: 'http://' + cautionHost + ':' + fixture.address().port + '/redirected-form' });
      response.end();
      return;
    }
    if (url.pathname === '/redirect-normal-login') {
      response.writeHead(302, { Location: '/sso-fixture' });
      response.end();
      return;
    }
    const send = () => {
      response.writeHead(200, { 'Content-Type': 'text/html', 'Set-Cookie': 'fixture=private-cookie-value; HttpOnly' });
      const action = url.pathname === '/sso-fixture' ? 'https://accounts.google.com/o/oauth2/v2/auth'
        : url.hostname === cautionHost ? 'http://' + destinationHost + '/private-path?marker=private-query#private-fragment' : '/local-form';
      const credentialInputs = url.pathname === '/pay-fixture'
        ? '<input name="number" autocomplete="cc-number" value="private-card-value"><input name="expiry" autocomplete="cc-exp">'
        : '<input id="password" name="fixture-password" type="password" value="private-form-value">';
      response.end('<!doctype html><title>Local login fixture</title><link rel="icon" href="data:,"><input id="other">' +
        '<form method="post" action="' + action + '">' + credentialInputs + '</form>' +
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
    return writeFixture(snapshotPath, {
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
  let runtime;
  try {
    await publish(useWindowsSetup ? 600000 : 300000);
    browser = await chromium.launchPersistentContext('', {
      channel: 'chromium',
      args: ['--disable-extensions-except=' + extension, '--load-extension=' + extension,
        '--no-proxy-server', '--host-resolver-rules=' +
          [phishingHost, cautionHost, destinationHost].map(host => 'MAP ' + host + ' 127.0.0.1').join(',')]
    });
    const worker = browser.serviceWorkers()[0] ?? await browser.waitForEvent('serviceworker');
    const extensionOrigin = new URL(worker.url()).origin === 'null'
      ? 'chrome-extension://' + new URL(worker.url()).hostname
      : new URL(worker.url()).origin;
    if (useWindowsSetup) {
      runtime = await createRuntime(new URL(worker.url()).hostname, snapshotPath);
      [token, adminToken] = await runtime.tokens();
      backend = await runtime.start('powershell.exe');
      console.log('Windows setup: malformed extension ID rejected, separate DPAPI credentials created and backend started with PowerShell 5.1');
    } else {
      backend = await startBackend(java, extensionOrigin, snapshotPath);
    }
    const origin = 'http://127.0.0.1:' + backend.port;
    const apiCalls = [];
    const snapshotCalls = [];
    const formActionRequests = [];
    browser.on('request', request => {
      if (new URL(request.url()).hostname === destinationHost) formActionRequests.push(request);
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
    async function refreshCredential(credential = token) {
      const credentialId = () => worker.evaluate(async () =>
        (await chrome.storage.session.get('backendCredential')).backendCredential?.id);
      const previous = await credentialId();
      await options.locator('#browserToken').fill(credential);
      await options.locator('#saveConnection').click();
      await eventually(() => options.locator('#browserToken').inputValue(), value => value === '', 'cleared token input');
      if (credential === token) {
        await eventually(credentialId, id => !!id && id !== previous, 'verified credential stored');
      }
    }
    if (useWindowsSetup) {
      await refreshCredential(randomBytes(32).toString('base64url'));
      await options.locator('#backendStatus').getByText(/Browser credential rejected/).waitFor();
      await refreshCredential(adminToken);
      await options.locator('#backendStatus').getByText(/Connection denied/).waitFor();
      await options.locator('#tokenStatus').getByText('Browser token required.').waitFor();
      snapshotCalls.length = 0;
    }
    await refreshCredential();
    await options.locator('#tokenStatus').getByText('Browser token set for this session.').waitFor();
    assert.equal(await options.locator('#threatReporting').isChecked(), false);
    const monitoring = origin + '/api/threat/monitoring';
    const reportingCalls = () => apiCalls.filter(call => call.url().startsWith(monitoring + '/'));
    const eventCalls = () => reportingCalls().filter(call => call.url() === monitoring + '/events');
    const adminReports = async (scope = 'SYNTHETIC') => {
      const response = await fetch(monitoring + '/dashboard?scope=' + scope,
        { headers: { Authorization: 'Bearer ' + adminToken } });
      assert.equal(response.status, 200);
      return response.json();
    };
    assert.equal((await fetch(monitoring + '/dashboard')).status, 401);
    assert.equal((await fetch(monitoring + '/dashboard', { headers: { Authorization: 'Bearer ' + token } })).status, 403);
    if (useWindowsSetup) {
      await options.locator('#backendStatus').getByText(/Browser credential accepted/).waitFor();
      const wrong = extensionOrigin === 'chrome-extension://' + 'a'.repeat(32) ? 'b' : 'a';
      const deniedOrigin = await fetch(origin + '/api/threat/reputation/snapshot', {
        headers: { Origin: 'chrome-extension://' + wrong.repeat(32), Authorization: 'Bearer ' + token }
      });
      assert.equal(deniedOrigin.status, 403);
    }
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
    assert.equal(reportingCalls().length, 0, 'blocking and normal usage must not report before opt-in');
    assert.equal((await adminReports()).total, 0);
    await options.locator('#threatReporting').check();
    await eventually(reportingCalls, calls => calls.some(call => call.url().endsWith('/heartbeat')), 'opt-in heartbeat');
    await blocked(malware, localSite + '/download-fixture?case=private-query#private-fragment');
    assert.equal(hits('127.0.0.1', '/download-fixture').length, 0);
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
    await eventually(() => inPageWarning(caution, 'A visible password field was found'),
      value => value === true, 'password form explanation');
    await popup.locator('#impersonationReasons').getByText(/credential form points to an unrelated origin/).waitFor();
    assert.equal(await badge(worker, caution.url()), '!');
    await phish.getByRole('heading', { name: 'Known threat blocked' }).waitFor();
    assert.equal(await badge(worker, site.url()), '');
    assert.equal(caution.url(), cautionFixture, 'a name-only warning must leave the user on the page');
    assert.equal(apiCalls.some(call => call.postData()?.includes(cautionHost)), false,
      'the local impersonation check must not send the hostname to the API');
    assert.equal(apiCalls.some(call => call.postData()?.includes(destinationHost)), false,
      'the form action origin must stay in the extension');
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

    const report = await eventually(() => adminReports(), result =>
      ['BLOCKED', 'WARNED', 'BYPASSED'].every(action => result.recent.some(entry => entry.action === action)) &&
      Object.values(result.categories).every(count => count > 0), 'four categories and three actions in the backend');
    assert.equal(report.total, report.blocked + report.warned);
    assert.ok(report.recent.some(entry => entry.category === 'MALWARE' && entry.action === 'WARNED'));
    assert.ok(report.recent.some(entry => entry.category === 'MALWARE' && entry.action === 'BLOCKED'));
    assert.equal(report.categories.FINANCIAL_IMPERSONATION, 1, 'popup, badge and content rechecks must not duplicate an advisory');
    assert.equal((await adminReports('REAL')).total, 0, 'fixture reports must stay out of live totals');
    for (const request of reportingCalls()) {
      const headers = await request.allHeaders();
      assert.ok(request.serviceWorker());
      assert.equal(headers.authorization, 'Bearer ' + token);
      assert.equal(headers.cookie, undefined);
      assert.equal(headers.referer, undefined);
      const keys = request.url().endsWith('/events') ? ['action', 'detectedAt', 'id', 'signal'] : ['protection'];
      assert.deepEqual(Object.keys(request.postDataJSON()).sort(), keys);
      for (const marker of [...privateMarkers, phishingHost, cautionHost, destinationHost, localSite]) {
        assert.ok(!request.postData().includes(marker));
        assert.ok(!JSON.stringify(report).includes(marker));
        assert.ok(!backend.logs().includes(marker));
      }
    }

    const dashboard = await browser.newPage();
    await dashboard.setViewportSize({ width: 1440, height: 900 });
    await dashboard.goto(origin + '/monitor');
    assert.equal(await dashboard.locator('#dashboard').isVisible(), false);
    const capture = async name => {
      if (process.env.THREAT_MONITOR_CAPTURE_DIR) {
        await dashboard.screenshot({ path: require('node:path').join(process.env.THREAT_MONITOR_CAPTURE_DIR, name + '.png'),
          fullPage: true, animations: 'disabled' });
      }
    };
    await capture('login');
    await dashboard.getByRole('button', { name: 'Show token' }).click();
    assert.equal(await dashboard.locator('#token').getAttribute('type'), 'text');
    await dashboard.getByRole('button', { name: 'Hide token' }).click();
    assert.equal(await dashboard.locator('#token').getAttribute('type'), 'password');
    async function login(credential) {
      await dashboard.locator('#token').fill(credential);
      await dashboard.getByRole('button', { name: 'Sign in', exact: true }).click();
    }
    await login(token);
    await dashboard.getByText(/Access denied/).waitFor();
    await login(adminToken);
    await dashboard.locator('#backend-state').getByText('Backend connected').waitFor();
    await dashboard.getByText('No events reported for this view.').waitFor();
    await dashboard.getByRole('button', { name: 'Synthetic fixtures' }).click();
    await dashboard.getByText('Synthetic test data.').waitFor();
    await dashboard.locator('#history').getByText(/declared action on an unrelated origin/).first().waitFor();
    await dashboard.locator('#history').getByText('Bypassed', { exact: true }).first().waitFor();
    assert.equal(Number(await dashboard.locator('#total').textContent()), report.total);
    assert.match(await dashboard.locator('#reputation-state').textContent(), /1 with current reputation data/);
    assert.equal(await dashboard.locator('#token').inputValue(), '');
    assert.equal(await dashboard.evaluate(() => localStorage.length + sessionStorage.length), 0);
    assert.equal(await dashboard.locator('#category-chart svg').count(), 1);
    assert.equal(await dashboard.locator('#activity-chart svg').count(), 1);
    await capture('overview');
    await dashboard.getByRole('button', { name: 'Threat Centre' }).click();
    await dashboard.getByRole('heading', { name: 'Threat Centre' }).waitFor();
    await dashboard.getByLabel('Action', { exact: true }).selectOption('BYPASSED');
    assert.equal(await dashboard.locator('#history tr').count(), report.recent.filter(entry => entry.action === 'BYPASSED').length);
    await dashboard.locator('#event-search').fill('no-such-event');
    await dashboard.getByText('No recent events match your filters.').waitFor();
    await dashboard.getByRole('button', { name: 'Clear filters' }).click();
    await dashboard.locator('#history').getByText('Bypassed', { exact: true }).first().waitFor();
    await dashboard.getByRole('button', { name: /^Details for/ }).first().click();
    await dashboard.getByRole('dialog', { name: 'Event details' }).waitFor();
    await capture('event-details');
    await dashboard.keyboard.press('Escape');
    assert.equal(await dashboard.getByRole('dialog').count(), 0);
    await capture('threat-centre');
    await dashboard.getByRole('button', { name: 'Overview' }).click();
    await dashboard.getByRole('button', { name: 'Use light appearance' }).click();
    assert.equal(await dashboard.locator('html').getAttribute('data-theme'), 'light');
    await capture('light');
    await dashboard.getByRole('button', { name: 'Use dark appearance' }).click();
    await dashboard.emulateMedia({ reducedMotion: 'reduce' });
    assert.equal(await dashboard.locator('#total-visual').textContent(), await dashboard.locator('#total').textContent());
    if (globalThis.process.env.THREAT_MONITOR_SCREENSHOT) {
      await dashboard.screenshot({ path: globalThis.process.env.THREAT_MONITOR_SCREENSHOT, fullPage: true });
    }
    for (const [width, height] of [[1920, 1080], [1440, 900], [1366, 768], [1024, 768], [768, 900], [390, 844]]) {
      await dashboard.setViewportSize({ width, height });
      assert.equal(await dashboard.evaluate(() => document.documentElement.scrollWidth), width);
    }
    await capture('mobile');
    await dashboard.setViewportSize({ width: 1280, height: 820 });
    await dashboard.getByRole('button', { name: 'Sign out' }).click();
    assert.equal(await dashboard.locator('#history').textContent(), '');
    await login(adminToken);
    await dashboard.locator('#backend-state').getByText('Backend connected').waitFor();
    await dashboard.getByRole('button', { name: 'Synthetic fixtures' }).click();
    await dashboard.locator('#history').getByText('Bypassed', { exact: true }).first().waitFor();

    await options.locator('#threatReporting').uncheck();
    await options.locator('#reportingStatus').getByText('Reporting is off.').waitFor();
    const formChecks = await browser.newPage();
    await formChecks.goto(localSite + '/redirect-normal-login');
    await assertStatus(formChecks, 'No known threat match');
    assert.equal(await inPageWarning(formChecks, 'Possible financial website impersonation'), false);
    await formChecks.goto(cautionFixture.replace('/private-path?x=private-query', '/sso-fixture'));
    await assertStatus(formChecks, 'Possible financial website impersonation');
    await popup.locator('#impersonationReasons').getByText(/State Bank of India/).first().waitFor();
    await wait(1300);
    assert.equal(await inPageWarning(formChecks, 'A visible password field was found'), false);
    await formChecks.goto(cautionFixture.replace('/private-path?x=private-query', '/pay-fixture'));
    await eventually(() => inPageWarning(formChecks, 'A visible payment form asks for card details'),
      value => value === true, 'payment form explanation');
    await formChecks.goto(localSite + '/redirect-financial-login');
    await eventually(() => inPageWarning(formChecks, 'The browser observed a redirect before arriving'),
      value => value === true, 'redirect context');
    assert.equal(hits(cautionHost, '/redirected-form').length, 1, 'financial advice cannot block the target');
    assert.equal(formActionRequests.length, 0, 'observing an action must never visit its destination');
    await formChecks.close();
    console.log('Chrome: bounded form metadata added password, payment and redirect reasons; recognized SSO kept the baseline advisory');
    const beforeOptOut = eventCalls().length;
    const optedOut = await browser.newPage();
    await blocked(optedOut, localSite + '/download-fixture');
    await optedOut.close();
    assert.equal(eventCalls().length, beforeOptOut);
    await options.locator('#threatReporting').check();
    await options.locator('#reportingStatus').getByText('Reporting connected.').waitFor({ timeout: 18000 });
    console.log('Chrome: opted-in alerts reached the admin dashboard, fixture counts were isolated, and opt-out stopped reports');

    const beforeRestart = await adminReports();
    const duplicate = eventCalls().find(call => call.postDataJSON()?.action === 'BLOCKED').postDataJSON();
    await backend.stop();
    await dashboard.getByRole('button', { name: 'Refresh' }).click();
    await dashboard.locator('#load-state').getByText(/Backend unavailable/).waitFor();
    assert.equal(await dashboard.locator('#snapshot').isVisible(), false);
    if (globalThis.process.env.THREAT_MONITOR_OFFLINE_SCREENSHOT) {
      await dashboard.screenshot({ path: globalThis.process.env.THREAT_MONITOR_OFFLINE_SCREENSHOT, fullPage: true });
    }
    const offline = await browser.newPage();
    await blocked(offline, phishingFixture);
    assert.equal(hits(phishingHost).length, 1);
    await offline.close();
    await wait(600);
    await focusPassword(site);
    await eventually(() => tabRecord(worker), result =>
      result?.verdict.state === 'unavailable' && result.checkedAt > checked.checkedAt, 'offline status', 230);
    await assertStatus(site, 'Protection unavailable');
    if (useWindowsSetup) {
      await options.locator('#checkConnection').click();
      await options.locator('#backendStatus').getByText(/Backend unavailable/).waitFor();
      const oldAdmin = adminToken;
      await runtime.checkStartupFailure();
      await runtime.rotateAdmin();
      const [sameBrowser, rotatedAdmin] = await runtime.tokens();
      assert.ok(sameBrowser === token, 'admin rotation changed the browser credential');
      assert.ok(rotatedAdmin !== oldAdmin, 'admin rotation did not replace the old credential');
      adminToken = rotatedAdmin;
      backend = await runtime.start('pwsh.exe');
      const rejected = await fetch(monitoring + '/dashboard', { headers: { Authorization: 'Bearer ' + oldAdmin } });
      assert.equal(rejected.status, 401);
      assert.equal((await adminReports('REAL')).total, 0);
      const persisted = await adminReports();
      assert.equal(persisted.total, beforeRestart.total);
      assert.deepEqual(persisted.recent, beforeRestart.recent);
      const send = (route, body) => fetch(monitoring + '/' + route, {
        method: 'POST', headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      assert.equal((await send('heartbeat', { protection: 'REPUTATION_AVAILABLE' })).status, 204);
      assert.equal((await send('events', duplicate)).status, 204);
      assert.equal((await adminReports()).total, persisted.total);
      // The dashboard's automatic poll may already have rejected the rotated token.
      await dashboard.evaluate(() => {
        if (!document.getElementById('dashboard').hidden) document.getElementById('refresh').click();
      });
      await dashboard.getByText(/Access denied/).waitFor();
      await login(adminToken);
      await dashboard.locator('#backend-state').getByText('Backend connected').waitFor();
      await dashboard.getByRole('button', { name: 'Synthetic fixtures' }).click();
      await dashboard.locator('#history').getByText('Blocked', { exact: true }).first().waitFor();
      assert.equal(Number(await dashboard.locator('#total').textContent()), persisted.total);
      await options.locator('#threatReporting').uncheck();
      await options.locator('#reportingStatus').getByText('Reporting is off.').waitFor();
      const noReport = await browser.newPage();
      await blocked(noReport, localSite + '/download-fixture');
      await noReport.close();
      assert.equal((await adminReports()).total, persisted.total);
      await options.locator('#threatReporting').check();
      console.log('Windows setup: corrupt store failed closed; PowerShell 7 restart preserved reports and deduplication, revoked the old admin token and preserved opt-out');
    } else {
      backend = await startBackend(java, extensionOrigin, snapshotPath, backend.port);
    }
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

    // The direct smoke tests provider polling at a subsecond interval; the local profile uses the normal cadence.
    if (useWindowsSetup) return;
    await options.locator('#enableMonitoring').click();
    await site.close();
    await writeFixture(snapshotPath, { invalid: 'synthetic-provider-error' });
    const headers = { Authorization: 'Bearer ' + token };
    const snapshotEndpoint = origin + '/api/threat/reputation/snapshot';
    await eventually(async () => (await fetch(snapshotEndpoint, { headers })).status,
      status => status === 503, 'provider failure response');
    await refreshCredential();
    await eventually(installed, rules => rules.length === 0, 'rejected snapshot rules removed');
    const stale = await browser.newPage();
    await stale.goto(phishingFixture);
    await assertStatus(stale, 'Protection unavailable');
    await popup.locator('#impersonationReasons').getByText(/subdomain uses the HDFC Bank name/).waitFor();
    await eventually(() => inPageWarning(stale, 'The protection service is unavailable.'),
      value => value === true, 'degraded in-page warning');
    await eventually(() => adminReports(), result => result.clientStatus.REPUTATION_UNAVAILABLE === 1,
      'reported reputation unavailable');
    assert.equal(await badge(worker, stale.url()), '');
    await publish(17000);
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
    if (runtime) await runtime.dispose();
    else await backend?.stop();
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
