const assert = require('node:assert/strict');
const { readFileSync, writeFileSync } = require('node:fs');
const { join } = require('node:path');
const { chromium } = require('playwright');

async function main() {
  if (!process.argv[2]) throw new Error('Provide a new private aggregate output path');
  const browser = await chromium.launch({ channel: 'chromium', headless: true,
    args: ['--disable-background-networking', '--host-resolver-rules=MAP * ~NOTFOUND', '--proxy-server=http://127.0.0.1:9'] });
  try {
    const page = await browser.newPage({ viewport: { width: 900, height: 600 } });
    if (!process.argv[3] || !process.argv[4]) throw new Error('Provide a private fictional PNG and new private pixel output path');
    const png = readFileSync(process.argv[3]);
    await page.route('**/*', async route => {
      const address = new URL(route.request().url());
      if (address.hostname === 'fixture.example.test' && address.pathname === '/') {
        await route.fulfill({ contentType: 'text/html', body: '<header><img id="local" alt="Bank logo" width="80" height="40" src="/mark.png"><img id="foreign" alt="Partner logo" width="80" height="40" src="https://foreign.example.test/mark.png"><svg id="svg" aria-label="Brand logo" width="80" height="40"></svg><div id="bg" aria-label="Logo" style="width:80px;height:40px;background-image:url(/mark.png)"></div><img id="hidden" alt="logo" width="80" height="40" style="display:none" src="/mark.png"></header><main><img id="unrelated" width="80" height="40" src="/mark.png"><img id="offscreen" alt="logo" width="80" height="40" style="position:absolute;top:3000px" src="/mark.png"></main>' });
      } else if (['fixture.example.test', 'foreign.example.test'].includes(address.hostname) && address.pathname === '/mark.png') {
        await route.fulfill({ contentType: 'image/png', body: png });
      } else await route.abort();
    });
    await page.goto('https://fixture.example.test/', { waitUntil: 'load' });
    const source = readFileSync(join(__dirname, 'localize.mjs'), 'utf8').replaceAll('export function', 'function');
    const result = await page.evaluate(sourceText => {
      const { locateCandidates, readCandidate } = new Function(sourceText + '; return {locateCandidates,readCandidate};')();
      const initial = locateCandidates(document);
      const records = initial.candidates.map(candidate => ({ id: candidate.element.id, kind: candidate.kind,
        status: readCandidate(candidate, document).status, reason: readCandidate(candidate, document).reason ?? null }));
      const delayed = document.createElement('img'); delayed.alt = 'merchant logo'; delayed.id = 'delayed';
      delayed.width = 80; delayed.height = 40; delayed.src = '/mark.png'; document.body.append(delayed);
      const local = readCandidate(initial.candidates.find(item => item.element.id === 'local'), document);
      return { records, pixels: Array.from(local.pixels), width: local.width, height: local.height,
        delayedDetected: locateCandidates(document).candidates.some(item => item.element.id === 'delayed') };
    }, source);
    const byId = Object.fromEntries(result.records.map(item => [item.id, item]));
    assert.equal(byId.local.status, 'usable');
    assert.equal(byId.foreign.reason, 'cross-origin');
    assert.equal(byId.svg.reason, 'unsupported-kind');
    assert.equal(byId.bg.reason, 'unsupported-kind');
    assert.equal(byId.hidden, undefined);
    assert.equal(byId.unrelated, undefined);
    assert.equal(result.delayedDetected, true);
    writeFileSync(process.argv[4], JSON.stringify({ width: result.width, height: result.height, pixels: result.pixels }), { flag: 'wx' });
    const report = { browser: browser.version(), candidates: result.records.length,
      readable: result.records.filter(item => item.status === 'usable').length,
      unavailable: result.records.filter(item => item.status !== 'usable').length,
      offscreenIncluded: Boolean(byId.offscreen), delayedDetected: true,
      scope: 'One synthetic page. The labelled partner is a fictional third-party-use fixture.' };
    writeFileSync(process.argv[2], JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
    console.log(JSON.stringify(report));
  } finally { await browser.close(); }
}
main().catch(error => { console.error(error.stack); process.exitCode = 1; });
