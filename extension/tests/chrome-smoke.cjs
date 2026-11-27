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
const { tlsConfiguration, openReleaseEndpoints } = require('./release-https.cjs');

const extension = path.resolve(process.env.THREAT_SMOKE_EXTENSION_DIR ?? path.join(__dirname, '..'));
const jar = path.resolve(__dirname, '../../backend/target/threat-detection-0.0.1-SNAPSHOT.jar');
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

async function clickFixtureBurst(page) {
  const cdp = await page.context().newCDPSession(page);
  try {
    const click = {x:300, y:150, button:'left', clickCount:1};
    for (let index = 0; index < 36; index++) {
      await cdp.send('Input.dispatchMouseEvent', {type:'mousePressed', ...click});
      await cdp.send('Input.dispatchMouseEvent', {type:'mouseReleased', ...click});
      // Keep timestamps distinct while avoiding Playwright's pointer-motion round trips.
      await wait(25);
    }
  } finally {
    await cdp.detach();
  }
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

async function captureEvidence(page, name, fullPage = true) {
  const directory = process.env.THREAT_MONITOR_CAPTURE_DIR;
  if (directory) await page.screenshot({ path: path.join(directory, name + '.png'), fullPage, animations: 'disabled' });
}

const auditFindings = [];
const consoleViewports = [[1920, 1080], [1440, 900], [1366, 768], [1024, 768], [768, 900], [390, 844]];
async function auditAccessibility(page, surface) {
  const source = process.env.THREAT_AXE_SOURCE;
  if (!source) return;
  await page.evaluate(require('node:fs').readFileSync(source, 'utf8'));
  const result = await page.evaluate(() => axe.run(document, {runOnly: {
    type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']
  }}));
  const summarize = checks => checks.map(({id, nodes}) => ({id, targets: nodes.map(node => node.target)}));
  auditFindings.push({surface, violations: summarize(result.violations), incomplete: summarize(result.incomplete)});
}

async function checkResponsiveConsole(page) {
  for (const [width, height] of consoleViewports) {
    await page.setViewportSize({width, height});
    for (const theme of ['dark', 'light']) {
      const failures = await page.evaluate(({theme, width}) => {
        const themeButton = document.getElementById('theme');
        if ((document.documentElement.dataset.theme || 'dark') !== theme) themeButton.click();
        const overflow = [...document.querySelectorAll('.rail button[id^="nav-"]')].flatMap(button => {
          button.click();
          return document.documentElement.scrollWidth > width ? [button.textContent.trim()] : [];
        });
        document.getElementById('nav-threats').click();
        document.querySelector('#history button')?.click();
        const drawer = document.getElementById('event-drawer');
        if (!drawer.open || drawer.getBoundingClientRect().width > width) overflow.push('Event details');
        drawer.close();
        return overflow;
      }, {theme, width});
      assert.deepEqual(failures, [], `Console overflow at ${width} × ${height} in ${theme}`);
    }
  }
  console.log('Responsive console: all 11 views and the event drawer fit both themes at six viewport sizes');
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
  let release;
  const tls = process.env.THREAT_SMOKE_TLS_DIR ? tlsConfiguration(process.env.THREAT_SMOKE_TLS_DIR) : null;
  const tlsExtension = tls && process.env.THREAT_SMOKE_TLS_EXTENSION === '1';
  try {
    await publish(useWindowsSetup ? 600000 : 300000);
    browser = await chromium.launchPersistentContext('', {
      channel: 'chromium',
      headless: !tlsExtension,
      args: ['--disable-extensions-except=' + extension, '--load-extension=' + extension,
        ...(tls ? ['--ignore-certificate-errors-spki-list=' + tls.pin] : []),
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
    if (tls) {
      release = await openReleaseEndpoints(tls, backend.port, folder);
      const publicPage = await browser.newPage();
      await publicPage.goto(release.website);
      await publicPage.getByRole('link', { name: 'Install locally' }).click();
      await publicPage.getByRole('heading', { name: 'Install locally' }).waitFor();
      await publicPage.goto(release.website + '/demo/');
      await publicPage.getByRole('button', { name: 'Credential-form evidence' }).click();
      await publicPage.getByRole('heading', { name: 'Credential-form evidence' }).waitFor();
      assert.equal((await fetch(release.website + '/api/threat/monitoring/dashboard')).status, 404);
      await publicPage.close();
    }
    const origin = tlsExtension ? release.origin : 'http://127.0.0.1:' + backend.port;
    if (release) {
      const readReports = token => fetch(release.origin + '/api/threat/monitoring/dashboard', {
        headers: token ? { Authorization: 'Bearer ' + token } : {}
      });
      assert.equal((await readReports()).status, 401);
      assert.equal((await readReports(token)).status, 403);
      assert.equal((await readReports(adminToken)).status, 200);
    }
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
      await eventually(() => options.locator('#browserToken').inputValue(), value => value === '', 'cleared token input',
        tlsExtension ? 1200 : 100);
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
    await captureEvidence(options, 'extension-settings');
    await auditAccessibility(options, 'extension settings');
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
    const editSite = options.getByRole('button', {name: 'Edit', exact: true});
    await editSite.focus();
    await options.keyboard.press('Enter');
    await options.getByRole('dialog', {name: 'Edit Site Configuration'}).waitFor();
    assert.equal(await options.evaluate(() => document.activeElement.id), 'editPaths');
    await auditAccessibility(options, 'extension site editor');
    await options.keyboard.press('Escape');
    assert.equal(await editSite.evaluate(element => document.activeElement === element), true);

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
    await captureEvidence(phish, 'warning-confirmed');
    await auditAccessibility(phish, 'confirmed warning');
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
    const evidenceSummary = popup.locator('#impersonationSection summary');
    await evidenceSummary.press('Enter');
    assert.equal(await popup.locator('#impersonationReasons').isVisible(), false);
    await evidenceSummary.press('Enter');
    await popup.locator('#impersonationReasons').waitFor();
    await popup.locator('#popupReputation').getByText('Current snapshot').waitFor();
    await popup.locator('#popupReporting').getByText('Connected', { exact: true }).waitFor();
    assert.equal(await popup.getByRole('link', { name: 'Dashboard', exact: true }).getAttribute('href'), origin + '/monitor');
    if (process.env.THREAT_MONITOR_CAPTURE_DIR) {
      await popup.locator('.popup-container').screenshot({
        path: path.join(process.env.THREAT_MONITOR_CAPTURE_DIR, 'extension-popup.png'), animations: 'disabled'
      });
    }
    await captureEvidence(caution, 'warning-advisory', false);
    await auditAccessibility(popup, 'extension popup');
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
    await clickFixtureBurst(site);
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
    if (release) {
      await dashboard.goto(release.website + '/administrator/');
      await dashboard.getByRole('link', { name: 'Open administrator console' }).click();
      await dashboard.waitForURL(release.origin + '/monitor');
    } else {
      await dashboard.goto(origin + '/monitor');
    }
    assert.equal(await dashboard.locator('#dashboard').isVisible(), false);
    if (process.env.THREAT_UI_MATRIX === '1') {
      for (const [width, height] of consoleViewports) {
        await dashboard.setViewportSize({width, height});
        const widths = await dashboard.evaluate(() => {
          const theme = document.getElementById('theme');
          const dark = document.documentElement.scrollWidth;
          theme.click();
          const light = document.documentElement.scrollWidth;
          theme.click();
          return [dark, light];
        });
        assert.deepEqual(widths, [width, width], 'Dark and light sign-in');
      }
      await dashboard.setViewportSize({width: 1440, height: 900});
    }
    const capture = name => captureEvidence(dashboard, name);
    await capture('login');
    await auditAccessibility(dashboard, 'login');
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
    const railToggle = dashboard.getByRole('button', { name: 'Compact navigation' });
    await railToggle.press('Space');
    assert.equal(await railToggle.getAttribute('aria-pressed'), 'true');
    await dashboard.waitForFunction(() => document.querySelector('.rail').getBoundingClientRect().width <= 66);
    await railToggle.press('Space');
    assert.equal(await railToggle.getAttribute('aria-pressed'), 'false');
    let allowSynthetic;
    const waitForSkeleton = new Promise(resolve => { allowSynthetic = resolve; });
    const syntheticDashboardUrl = (release?.origin ?? origin) + '/api/threat/monitoring/dashboard?scope=SYNTHETIC';
    await dashboard.route(syntheticDashboardUrl, async route => {
      await waitForSkeleton;
      await route.continue();
    }, {times: 1});
    const scopedResponse = dashboard.waitForResponse(response => response.url() === syntheticDashboardUrl && response.ok());
    try {
      await dashboard.getByRole('button', { name: 'Synthetic fixtures' }).click();
      await dashboard.locator('#report-placeholder').waitFor();
      assert.equal(await dashboard.locator('#snapshot').isVisible(), false);
    } finally {
      allowSynthetic();
    }
    const scopedReport = await (await scopedResponse).json();
    await dashboard.getByText('Synthetic test data.').waitFor();
    await dashboard.locator('#history').getByText(/declared action on an unrelated origin/).first().waitFor();
    await dashboard.locator('#history').getByText('Bypassed', { exact: true }).first().waitFor();
    assert.equal(Number(await dashboard.locator('#total').textContent()), scopedReport.total);
    assert.match(await dashboard.locator('#reputation-state').textContent(), /1 with current reputation data/);
    assert.equal(await dashboard.locator('#token').inputValue(), '');
    assert.equal(await dashboard.evaluate(() => localStorage.length + sessionStorage.length), 0);
    assert.equal(await dashboard.locator('#category-chart svg').count(), 1);
    assert.equal(await dashboard.locator('#activity-chart svg').count(), 1);
    const activityPoint = dashboard.getByRole('button', {name: /UTC · \d+ detection/}).first();
    await activityPoint.focus();
    await dashboard.locator('#activity-tooltip').waitFor();
    await activityPoint.press('Escape');
    assert.equal(await dashboard.locator('#activity-tooltip').isVisible(), false);
    await activityPoint.press('Enter');
    await dashboard.locator('#activity-tooltip').waitFor();
    await activityPoint.press('Escape');
    const phishingLegend = dashboard.getByRole('button', {name: /^Phishing ·/});
    await phishingLegend.click();
    assert.match(await dashboard.locator('#category-tooltip').textContent(), /Phishing · \d+ of \d+ ·/);
    assert.equal(await dashboard.locator('#category-chart [data-chart-active]').count(), 1);
    await phishingLegend.press('Escape');
    await dashboard.waitForFunction(() => ['total','blocked','warned','bypassed'].every(id =>
      document.getElementById(id).textContent === document.getElementById(id + '-visual').textContent));
    if (process.env.THREAT_MONITOR_CAPTURE_DIR) {
      const metrics = await dashboard.evaluate(() => {
        const navigation = performance.getEntriesByType('navigation')[0];
        const assets = performance.getEntriesByType('resource').filter(entry =>
          /\/monitor\.(css|js)$|\/monitor\/(theme\.css|fonts\/inter-latin\.woff2)$/.test(entry.name));
        return {
          navigationMs: Math.round(navigation.duration),
          domContentLoadedMs: Math.round(navigation.domContentLoadedEventEnd),
          decodedShellBytes: navigation.decodedBodySize + assets.reduce((sum, entry) => sum + entry.decodedBodySize, 0),
          dashboardUsedJsHeapBytes: performance.memory?.usedJSHeapSize ?? null
        };
      });
      writeFileSync(path.join(process.env.THREAT_MONITOR_CAPTURE_DIR, 'performance.json'), JSON.stringify(metrics, null, 2));
    }
    await capture('overview');
    await auditAccessibility(dashboard, 'dark overview');
    await dashboard.getByRole('button', { name: 'Threat Centre' }).click();
    await dashboard.getByRole('heading', { name: 'Threat Centre' }).waitFor();
    await dashboard.getByLabel('Action', { exact: true }).selectOption('BYPASSED');
    assert.equal(await dashboard.locator('#history tr').count(), scopedReport.recent.filter(entry => entry.action === 'BYPASSED').length);
    await dashboard.locator('#event-search').fill('no-such-event');
    await dashboard.getByText('No recent events match your filters.').waitFor();
    await dashboard.getByRole('button', { name: 'Clear filters' }).click();
    await dashboard.locator('#history').getByText('Bypassed', { exact: true }).first().waitFor();
    const detailTrigger = dashboard.getByRole('button', { name: /^Details for/ }).first();
    await detailTrigger.focus();
    await dashboard.keyboard.press('Enter');
    await dashboard.getByRole('dialog', { name: 'Event details' }).waitFor();
    assert.equal(await dashboard.evaluate(() => document.activeElement.id), 'close-drawer');
    await capture('event-details');
    await auditAccessibility(dashboard, 'event dialog');
    await dashboard.keyboard.press('Escape');
    assert.equal(await dashboard.getByRole('dialog').count(), 0);
    assert.equal(await detailTrigger.evaluate(element => document.activeElement === element), true);
    await capture('threat-centre');
    await auditAccessibility(dashboard, 'threat centre');
    await dashboard.getByRole('button', { name: 'Overview' }).click();
    await dashboard.getByRole('button', { name: 'Use light appearance' }).click();
    assert.equal(await dashboard.locator('html').getAttribute('data-theme'), 'light');
    await capture('light');
    await auditAccessibility(dashboard, 'light overview');
    await dashboard.getByRole('button', { name: 'Use dark appearance' }).click();
    await dashboard.emulateMedia({ reducedMotion: 'reduce' });
    assert.equal(await dashboard.locator('#total-visual').textContent(), await dashboard.locator('#total').textContent());
    if (globalThis.process.env.THREAT_MONITOR_SCREENSHOT) {
      await dashboard.screenshot({ path: globalThis.process.env.THREAT_MONITOR_SCREENSHOT, fullPage: true });
    }
    for (const [width, height] of [[320, 800], ...consoleViewports]) {
      await dashboard.setViewportSize({ width, height });
      assert.equal(await dashboard.evaluate(() => document.documentElement.scrollWidth), width);
    }
    assert.equal(await dashboard.locator('#history-table').evaluate(element => element.scrollWidth <= element.clientWidth), true);
    await capture('mobile');
    await auditAccessibility(dashboard, 'mobile overview');
    for (const [label, id, expected] of [
      ['Threat Intelligence', 'intelligence', 'Managed feed disabled'],
      ['Financial Protection', 'financial', 'State Bank of India'],
      ['ML Laboratory', 'ml', '81.50%'],
      ['Visual Intelligence', 'visual', '16/18 correct'],
      ['Dataset Laboratory', 'datasets', 'PhreshPhish development partitions'],
      ['Connected Browsers', 'browsers', 'Fresh browser heartbeats'],
      ['System Health', 'health', 'Dashboard query succeeded'],
      ['Privacy Centre', 'privacy', 'The configured reporting window is'],
      ['Settings', 'settings', 'Console display']
    ]) {
      await dashboard.getByRole('button', { name: label }).click();
      await dashboard.getByRole('heading', { name: label, exact: true }).waitFor();
      const panel = dashboard.locator(id === 'ml' ? '#ml-metrics' : '#' + id);
      await panel.getByText(expected, { exact: id !== 'privacy' }).waitFor();
      assert.equal(await dashboard.evaluate(() => document.documentElement.scrollWidth), 390, label);
      if (id === 'browsers') {
        assert.equal(await dashboard.locator('#browser-report dd').first().textContent(), '1');
        await dashboard.getByText('Synthetic test data.').waitFor();
      }
      if (id === 'financial') assert.equal(await dashboard.locator('#brand-cards article').count(), 8);
      if (id === 'ml') {
        const architecture = dashboard.getByLabel('Model', { exact: true });
        await dashboard.getByRole('button', {name: 'Calibration and fusion'}).press('Enter');
        await dashboard.locator('#architecture-detail').getByText(/75% to URL evidence/).waitFor();
        await architecture.selectOption('cnn');
        assert.equal(await dashboard.locator('#architecture-steps li:nth-child(3)').evaluate(
          element => getComputedStyle(element).animationDelay), '0s');
        await dashboard.getByRole('button', {name: 'Parallel convolutions'}).click();
        await dashboard.locator('#architecture-detail').getByText(/widths 3, 5 and 7/).waitFor();
        await architecture.selectOption('transformer');
        await dashboard.getByRole('button', {name: 'Attention encoders'}).click();
        await dashboard.locator('#architecture-detail').getByText(/four attention heads/).waitFor();
        await architecture.selectOption('fusion');
        await dashboard.getByLabel('Metric', { exact: true }).selectOption('domainFpr');
        await dashboard.locator('#ml-models').getByText('0.88%', { exact: true }).first().waitFor();
        const experiment = dashboard.getByLabel('Cohort', { exact: true });
        const cutoff = dashboard.getByLabel('Operating point', { exact: true });
        await experiment.selectOption('phresh-transfer');
        await cutoff.selectOption('0.001');
        await dashboard.locator('#ml-cohort').getByText(/19,570 rows.*original UCI cutoffs/i).waitFor();
        await dashboard.locator('#ml-models').getByText('Random Forest', { exact: true }).waitFor();
        await experiment.selectOption('temporal-far');
        await dashboard.getByLabel('Metric', { exact: true }).selectOption('prAuc');
        await dashboard.locator('#ml-cohort').getByText(/46,562 rows.*threshold-free/).waitFor();
        assert.equal(await dashboard.locator('#ml-models').getByText(/Score cutoff/).count(), 0);
        await experiment.selectOption('phase3f-general-transfer');
        assert.equal(await dashboard.locator('#ml-metric option[value="domainFpr"]').isDisabled(), true);
        await experiment.selectOption('phase3e-india-control');
        assert.equal(await dashboard.locator('#ml-metric option[value="recall"]').isDisabled(), true);
        await experiment.selectOption('grouped-5f');
        await dashboard.getByLabel('Metric', { exact: true }).selectOption('recall');
      }
      if (id === 'datasets') {
        await dashboard.getByRole('button', {name: 'Deduplication', exact: true}).click();
        await dashboard.locator('#dataset-detail').getByText(/quarantines structural overlap/).waitFor();
      }
      if (id === 'visual') {
        await dashboard.getByRole('button', {name: 'Calculate similarity', exact: true}).click();
        await dashboard.locator('#visual-detail').getByText(/MobileNetV3 compares image embeddings/).waitFor();
      }
    }
    if (process.env.THREAT_UI_MATRIX === '1') {
      await checkResponsiveConsole(dashboard);
      await dashboard.getByRole('button', { name: 'Use dark appearance' }).click();
      await dashboard.getByRole('button', { name: 'Settings', exact: true }).click();
    }
    await dashboard.emulateMedia({ reducedMotion: 'no-preference' });
    await dashboard.getByLabel('Reduce motion').check();
    assert.notEqual(await dashboard.locator('html').getAttribute('data-reduced-motion'), null);
    await dashboard.getByLabel('Appearance', { exact: true }).selectOption('light');
    assert.equal(await dashboard.locator('html').getAttribute('data-theme'), 'light');
    await dashboard.getByRole('button', { name: 'Use dark appearance' }).click();
    assert.equal(await dashboard.getByLabel('Appearance', { exact: true }).inputValue(), 'dark');
    await dashboard.setViewportSize({ width: 1280, height: 820 });
    for (const id of ['intelligence', 'financial', 'ml', 'visual', 'datasets', 'browsers', 'health', 'privacy', 'settings']) {
      await dashboard.locator('#nav-' + id).click();
      if (id === 'intelligence') await dashboard.locator('#feed-message').getByText('Managed feed disabled').waitFor();
      await capture(id);
      await auditAccessibility(dashboard, id);
    }
    const researchApi = origin + '/api/threat/monitoring/research-summary';
    const fontResponse = await fetch(origin + '/monitor/fonts/inter-latin.woff2');
    assert.equal(fontResponse.status, 200);
    assert.equal(fontResponse.headers.get('content-type'), 'font/woff2');
    const markResponse = await fetch(origin + '/monitor/icons/mark.svg');
    assert.equal(markResponse.status, 200);
    assert.match(markResponse.headers.get('content-type'), /^image\/svg\+xml/);
    assert.equal((await fetch(origin + '/monitor/theme.css')).status, 200);
    assert.equal(await dashboard.evaluate(async () => {
      await document.fonts.ready;
      return [...document.fonts].some(font => font.family === 'Inter' && font.status === 'loaded');
    }), true);
    assert.equal((await fetch(researchApi)).status, 401);
    assert.equal((await fetch(researchApi, { headers: { Authorization: 'Bearer ' + token } })).status, 403);
    if (process.env.THREAT_AXE_SOURCE) {
      const target = process.env.THREAT_MONITOR_CAPTURE_DIR;
      if (target) writeFileSync(path.join(target, 'accessibility.json'), JSON.stringify(auditFindings, null, 2));
      console.log('Accessibility: ' + auditFindings.length + ' surfaces checked');
      assert.deepEqual(auditFindings.filter(entry => entry.violations.length), []);
    }
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
    await dashboard.getByRole('button', { name: 'System Health' }).click();
    assert.equal(await dashboard.locator('#health-backend').textContent(), 'Unavailable');
    assert.equal(await dashboard.locator('#health-storage').textContent(), 'Unknown');
    await dashboard.locator('#health-feed').getByText('Feed status unavailable').waitFor();
    await dashboard.getByRole('button', { name: 'Overview' }).click();
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
      backend = await runtime.start(runtime.secondaryHost);
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

    await popup.getByRole('button', { name: 'Pause protection' }).click();
    await popup.getByRole('button', { name: 'Resume protection' }).waitFor();
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
    await popup.getByRole('button', { name: 'Resume protection' }).click();
    await popup.getByRole('button', { name: 'Pause protection' }).waitFor();
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
    if (release) console.log('Release path: site setup and demo, packaged extension (' + (tlsExtension ? 'HTTPS' : 'loopback HTTP') +
      '), and separate HTTPS administrator access passed');
  } finally {
    if (browser) await browser.close();
    release?.close();
    if (runtime) await runtime.dispose();
    else await backend?.stop();
    fixture.closeAllConnections();
    await new Promise(resolve => fixture.close(resolve));
    rmSync(snapshotPath, { force: true });
    rmSync(snapshotPath + '.next', { force: true });
    if (tls) rmSync(path.join(folder, 'release-website'), { recursive: true, force: true });
    rmdirSync(folder);
  }
}

main().catch(error => {
  console.error(error.stack ?? error.message);
  process.exitCode = 1;
});
