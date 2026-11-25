const assert = require('node:assert/strict');
const { createServer } = require('node:http');
const { mkdtempSync, rmSync, realpathSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join, resolve } = require('node:path');
const { chromium } = require('playwright');

async function main() {
  if (!process.argv[2]) throw new Error('Provide a new private aggregate output path');
  const root = resolve(__dirname, '../..');
  const output = resolve(process.argv[2]);
  if (output.startsWith(root + require('node:path').sep)) throw new Error('Output must be outside the repository');
  const server = createServer((request, response) => {
    if (['/oauth', '/payment', '/sso'].includes(request.url)) {
      response.writeHead(302, { Location: '/login' }); response.end(); return;
    }
    const action = request.url === '/external' ? 'https://outside.example.test/auth' :
      request.url === '/insecure' ? 'http://outside.example.test/auth' : '/submit';
    response.writeHead(200, { 'Content-Type': 'text/html', 'Cache-Control': 'no-store',
      'Set-Cookie': 'fixture=; HttpOnly; SameSite=Lax; Path=/' });
    const frame = request.url === '/iframe' ? '<iframe src="https://outside.example.test/"></iframe>' : '';
    response.end(`<form action="${action}"><input type="password"></form>${frame}`);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const profile = mkdtempSync(join(tmpdir(), 'phase6e-chrome-'));
  const extension = __dirname;
  let context;
  try {
    context = await chromium.launchPersistentContext(profile, { channel: 'chromium', headless: true,
      args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`,
        '--disable-background-networking', '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1'] });
    await context.route(/^https?:\/\/(?!127\.0\.0\.1(?::|\/))/, route => route.abort());
    const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
    const page = await context.newPage();
    await page.goto(`chrome-extension://${new URL(worker.url()).host}/fixture.html`);
    const cases = [
      { path: '/login', form: 'local', redirect: false },
      { path: '/oauth', form: 'local', redirect: true },
      { path: '/sso', form: 'local', redirect: true },
      { path: '/payment', form: 'local', redirect: true },
      { path: '/external', form: 'external', redirect: false },
      { path: '/insecure', form: 'insecure', redirect: false },
      { path: '/iframe', form: 'local', redirect: false, behavior: 'iframe' }
    ];
    const durations = [], results = [];
    for (const fixture of cases.flatMap(item => Array.from({ length: 5 }, () => item))) {
      const tab = await context.newPage();
      await tab.goto(`http://127.0.0.1:${port}${fixture.path}`, { waitUntil: 'load' });
      const id = await page.evaluate(async url => (await chrome.tabs.query({ url }))[0].id, tab.url());
      const start = performance.now();
      const result = await page.evaluate(async tabId => chrome.runtime.sendMessage({ type: 'read-fixture', tabId }), id);
      durations.push(performance.now() - start);
      assert.equal(result.form, fixture.form);
      assert.equal(result.behavior, fixture.behavior || 'none');
      assert.equal(result.evidence.some(item => item.category === 'behavior' && item.reason === 'iframe'), fixture.behavior === 'iframe');
      assert.equal(result.navigation.redirects > 0, fixture.redirect);
      assert.equal(result.evidence.some(item => item.category === 'credential' && item.state === 'advisory'),
        ['external', 'insecure'].includes(fixture.form));
      assert.equal(result.evidence.some(item => item.category === 'reputation' && item.state === 'unavailable'), true);
      assert.equal(result.cookie.count, 1);
      assert.equal(result.cookie.missingSecure, 1);
      assert.equal(result.cookie.missingHttpOnly, 0);
      assert.equal(result.cookie.broadScope, 0);
      assert.equal(result.evidence.some(item => item.category === 'cookie' && item.reason === 'missing-secure'), true);
      assert.ok(Object.values(result.permission).every(value => ['allow', 'block', 'ask'].includes(value)));
      assert.deepEqual(Object.keys(result.cookie).sort(), ['broadScope', 'count', 'missingHttpOnly', 'missingSecure', 'sameSiteNone']);
      results.push({ expected: fixture.form, detected: result.form, redirects: result.navigation.redirects });
      await tab.close();
    }
    const sorted = durations.sort((a, b) => a - b);
    const report = { browser: context.browser().version(), fixtureCount: cases.length, trials: results.length, correct: results.length,
      legitimateTrials: 20, legitimateCredentialAdvisories: 0, suspiciousTrials: 10, suspiciousCredentialAdvisories: 10,
      externalFrameTrials: 5,
      unavailableReputation: results.length, cookieAttributeChecks: results.length, permissionChecks: results.length * 4,
      medianMs: sorted[Math.ceil(sorted.length * 0.5) - 1], p95Ms: sorted[Math.ceil(sorted.length * 0.95) - 1],
      note: 'Seven local synthetic fixtures repeated five times. Timing covers messaging, form, iframe, cookie and permission inspection, excluding navigation.' };
    writeFileSync(output, JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
    console.log(JSON.stringify(report));
  } finally {
    if (context) await context.close();
    await new Promise(resolve => server.close(resolve));
    const tempRoot = realpathSync(tmpdir());
    const target = realpathSync(profile);
    if (require('node:path').dirname(target).toLowerCase() !== tempRoot.toLowerCase() ||
        !require('node:path').basename(target).startsWith('phase6e-chrome-')) throw new Error('Unexpected disposable profile path');
    rmSync(target, { recursive: true });
  }
}
main().catch(error => { console.error(error.stack); process.exitCode = 1; });
