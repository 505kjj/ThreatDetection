const assert = require('node:assert/strict');
const { createServer } = require('node:http');
const { mkdtempSync, readFileSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join, resolve } = require('node:path');
const { chromium } = require('playwright');

async function main() {
  if (!process.argv[2]) throw new Error('Provide a new private aggregate output path');
  const root = resolve(__dirname, '../..');
  const output = resolve(process.argv[2]);
  if (output.startsWith(root + require('node:path').sep)) throw new Error('Output must be outside the repository');
  const server = createServer((request, response) => {
    if (request.url === '/oauth' || request.url === '/payment') {
      response.writeHead(302, { Location: '/login' }); response.end(); return;
    }
    const action = request.url === '/external' ? 'https://outside.example.test/auth' :
      request.url === '/insecure' ? 'http://outside.example.test/auth' : '/submit';
    response.writeHead(200, { 'Content-Type': 'text/html', 'Cache-Control': 'no-store' });
    response.end(`<form action="${action}"><input type="password"></form>`);
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
    const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
    const page = await context.newPage();
    await page.goto(`chrome-extension://${new URL(worker.url()).host}/fixture.html`);
    const cases = [
      { path: '/login', form: 'local', redirect: false },
      { path: '/oauth', form: 'local', redirect: true },
      { path: '/payment', form: 'local', redirect: true },
      { path: '/external', form: 'external', redirect: false },
      { path: '/insecure', form: 'insecure', redirect: false }
    ];
    const durations = [], results = [];
    for (const fixture of cases) {
      const tab = await context.newPage();
      await tab.goto(`http://127.0.0.1:${port}${fixture.path}`);
      const id = await page.evaluate(async url => (await chrome.tabs.query({ url }))[0].id, tab.url());
      const start = performance.now();
      const result = await page.evaluate(async tabId => chrome.runtime.sendMessage({ type: 'read-fixture', tabId }), id);
      durations.push(performance.now() - start);
      assert.equal(result.form, fixture.form);
      assert.equal(result.navigation.redirects > 0, fixture.redirect);
      assert.equal(result.evidence.some(item => item.category === 'credential' && item.state === 'advisory'),
        ['external', 'insecure'].includes(fixture.form));
      assert.equal(result.evidence.some(item => item.category === 'reputation' && item.state === 'unavailable'), true);
      results.push({ expected: fixture.form, detected: result.form, redirects: result.navigation.redirects });
      await tab.close();
    }
    const sorted = durations.sort((a, b) => a - b);
    const report = { browser: context.browser().version(), fixtureCount: results.length, correct: results.length,
      legitimateCases: 3, legitimateAdvisories: 0, suspiciousCases: 2, suspiciousAdvisories: 2,
      unavailableReputation: 5, medianMs: sorted[2], p95Ms: sorted[4],
      note: 'Five local synthetic fixtures. Timing covers messaging and form inspection, excluding navigation.' };
    writeFileSync(output, JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
    console.log(JSON.stringify(report));
  } finally {
    if (context) await context.close();
    await new Promise(resolve => server.close(resolve));
  }
}
main().catch(error => { console.error(error.stack); process.exitCode = 1; });
