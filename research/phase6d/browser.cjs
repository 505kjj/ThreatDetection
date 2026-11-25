const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { chromium } = require('playwright');

async function main() {
  const browser = await chromium.launch({ channel: 'chromium', headless: true });
  try {
    const page = await browser.newPage();
    await page.route('**/*', route => route.abort());
    await page.setContent('<header><img alt="Bank logo" width="160" height="40"><svg width="80" height="30"></svg></header><main><img alt="Product" width="80" height="80"><div id="later"></div></main>');
    const source = readFileSync(join(__dirname, 'localize.mjs'), 'utf8').replace('export function', 'function');
    const result = await page.evaluate(sourceText => {
      const locate = new Function(sourceText + '; return locateCandidates;')();
      const first = locate(document);
      const later = document.createElement('img');
      later.alt = 'merchant logo'; later.width = 100; later.height = 30;
      document.querySelector('#later').append(later);
      const second = locate(document);
      return { first: first.candidates.map(item => item.kind), second: second.candidates.map(item => item.kind),
        statuses: [first.status, second.status] };
    }, source);
    assert.deepEqual(result.first, ['image', 'svg']);
    assert.equal(result.second.length, 3);
    assert.deepEqual(result.statuses, ['usable', 'usable']);
    console.log(JSON.stringify({ browser: browser.version(), syntheticPages: 1, initialCandidates: 2, afterDelayedElement: 3 }));
  } finally { await browser.close(); }
}
main().catch(error => { console.error(error.stack); process.exitCode = 1; });
