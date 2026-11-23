const assert = require('node:assert/strict');
const { spawn, spawnSync } = require('node:child_process');
const { createHash, randomBytes } = require('node:crypto');
const { once } = require('node:events');
const { createServer } = require('node:http');
const path = require('node:path');
const { chromium } = require('playwright');

const extension = path.resolve(__dirname, '..');
const jar = path.resolve(extension, '../backend/target/threat-detection-0.0.1-SNAPSHOT.jar');
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
const token = randomBytes(32).toString('base64url');
const privateMarkers = ['private-path', 'private-query', 'private-fragment', 'private-form-value'];

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

async function startBackend(java, extensionOrigin, port = 0) {
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
    env: { ...globalThis.process.env, SPRING_APPLICATION_JSON: JSON.stringify(config) }
  });
  let logs = '';
  process.stdout.on('data', chunk => { logs = (logs + chunk).slice(-8000); });
  process.stderr.on('data', chunk => { logs = (logs + chunk).slice(-8000); });
  process.on('error', error => { logs += String(error); });
  try {
    for (let attempt = 0; attempt < 60; attempt++) {
      const match = /Tomcat started on port (\d+)/.exec(logs);
      if (match) {
        const health = await fetch('http://127.0.0.1:' + match[1] + '/api/health').catch(() => null);
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

async function main() {
  const java = javaExecutable();
  const fixture = createServer((_request, response) => {
    response.writeHead(200, { 'Content-Type': 'text/html' });
    response.end('<!doctype html><title>Local login fixture</title><input id="other">' +
      '<input id="password" type="password" value="private-form-value">');
  });
  await new Promise(resolve => fixture.listen(0, '127.0.0.1', resolve));
  let browser;
  let backend;
  try {
    browser = await chromium.launchPersistentContext('', {
      channel: 'chromium',
      args: ['--disable-extensions-except=' + extension, '--load-extension=' + extension]
    });
    const worker = browser.serviceWorkers()[0] ?? await browser.waitForEvent('serviceworker');
    const extensionOrigin = new URL(worker.url()).origin === 'null'
      ? 'chrome-extension://' + new URL(worker.url()).hostname
      : new URL(worker.url()).origin;
    backend = await startBackend(java, extensionOrigin);
    const origin = 'http://127.0.0.1:' + backend.port;
    const apiCalls = [];
    browser.on('request', request => {
      if (request.method() === 'POST' && request.url().startsWith(origin + '/api/threat/')) {
        apiCalls.push(request);
      }
    });

    const options = await browser.newPage();
    await options.goto(extensionOrigin + '/options.html');
    await options.locator('#tokenStatus').getByText('Browser token required.').waitFor();
    await options.locator('#backendOrigin').fill(origin);
    await options.locator('#browserToken').fill(token);
    await options.locator('#saveConnection').click();
    await options.locator('#tokenStatus').getByText('Browser token set for this session.').waitFor();
    await options.locator('#newDomain').fill('127.0.0.1');
    await options.locator('#addDomain').click();
    await options.locator('#siteList').getByText('127.0.0.1', { exact: true }).waitFor();

    const site = await browser.newPage();
    await site.goto('http://127.0.0.1:' + fixture.address().port +
      '/login/private-path?fixture=private-query#private-fragment');
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
      for (const marker of privateMarkers) assert.ok(!request.postData().includes(marker));
    }
    console.log('Chrome: service worker authenticated and sent only the allowed hostname and activity fields');

    await stop(backend.process);
    await wait(600);
    await focusPassword(site);
    await eventually(() => tabRecord(worker), result =>
      result?.verdict.state === 'unavailable' && result.checkedAt > checked.checkedAt, 'offline status', 230);
    backend = await startBackend(java, extensionOrigin, backend.port);
    await focusPassword(site);
    const recovered = await eventually(() => tabRecord(worker), result => result?.verdict.state === 'safe' &&
      result.sessionId !== first.sessionId, 'new session after restart', 230);
    assert.ok(recovered.sessionId);
    console.log('Chrome: network failure reported unavailable and a backend restart renewed the session');

    await options.locator('#disableMonitoring').click();
    await options.locator('#monitoringStatus').getByText('Monitoring paused.').waitFor();
    await wait(600);
    const before = apiCalls.length;
    await focusPassword(site);
    await wait(600);
    assert.equal(apiCalls.length, before);
    console.log('Chrome: pausing monitoring stopped requests from the open document');
  } finally {
    if (browser) await browser.close();
    await stop(backend?.process);
    fixture.closeAllConnections();
    await new Promise(resolve => fixture.close(resolve));
  }
}

main().catch(error => {
  console.error(error.message);
  process.exitCode = 1;
});
