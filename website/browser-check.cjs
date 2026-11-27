const assert = require('node:assert/strict');
const { mkdirSync, readFileSync, writeFileSync } = require('node:fs');
const { join } = require('node:path');
const { chromium } = require('playwright');

async function main() {
  const capture = process.argv[2];
  const axe = process.env.THREAT_AXE_SOURCE;
  if (!capture || !axe) throw new Error('Set THREAT_AXE_SOURCE and supply a private capture directory');
  const axeSource = readFileSync(axe, 'utf8');
  mkdirSync(capture, { recursive: true });
  const { servePreview } = await import('./preview.mjs');
  const { pages } = await import('./pages.mjs');
  const { server, url } = await servePreview();
  let browser;
  try {
    browser = await chromium.launch({ channel: 'chromium' });
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    await page.emulateMedia({ reducedMotion: 'reduce' });
    const errors = [];
    const network = new Set();
    page.on('request', request => network.add(new URL(request.url()).origin));
    page.on('pageerror', error => errors.push(error.message));
    page.on('requestfailed', request => {
      const message = request.failure()?.errorText;
      // Chromium can cancel its separate favicon request when a QA navigation ends.
      if (message === 'net::ERR_ABORTED' && request.resourceType() === 'other' &&
          request.url() === url + '/assets/mark.svg') return;
      errors.push(`${message} ${request.resourceType()} ${request.url()}`);
    });
    async function open(route) {
      const response = await page.goto(url + route);
      // Complete deferred image loads before the next test navigation can cancel them.
      await page.evaluate(async () => {
        for (const image of document.images) image.loading = 'eager';
        await Promise.all([...document.images].map(image => image.decode()));
        await document.fonts.ready;
      });
      return response;
    }
    const audits = [];
    for (const width of [1440, 1024, 768, 390, 320]) {
      await page.setViewportSize({ width, height: width < 768 ? 844 : 1000 });
      for (const slug of Object.keys(pages)) {
        const route = slug ? `/${slug}/` : '/';
        const response = await open(route);
        assert.equal(response.status(), 200);
        assert.match(response.headers()['content-security-policy'], /connect-src 'none'/);
        assert.equal(response.headers()['referrer-policy'], 'no-referrer');
        assert.equal(await page.locator('h1').count(), 1);
        assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), route + ' overflows at ' + width);
        assert(await page.evaluate(async () => {
          await document.fonts.ready;
          return document.fonts.check('700 16px Inter');
        }), 'bundled Inter missing');
        if (width !== 1440 && width !== 390) continue;
        await page.evaluate(axeSource);
        const result = await page.evaluate(async () => {
          const { violations, incomplete } = await axe.run({ runOnly: {
            type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']
          }});
          return { violations: violations.map(rule => rule.id), incomplete: incomplete.map(rule => rule.id) };
        });
        assert.deepEqual(result.violations, [], route + ' at ' + width);
        audits.push({ route, width, ...result });
        await page.screenshot({ path: join(capture, (slug || 'home') + '-' + width + '.png'),
          fullPage: true, animations: 'disabled' });
      }
    }
    await open('/demo/');
    const scenarios = page.getByRole('group', { name: 'Synthetic scenarios' }).getByRole('button');
    for (const button of await scenarios.all()) {
      await button.focus();
      assert(await button.evaluate(node => node.matches(':focus-visible')));
      await page.keyboard.press('Enter');
      assert.equal(await button.getAttribute('aria-pressed'), 'true');
      assert.equal(await page.locator('[data-panel]:visible').count(), 1);
      assert.equal(await page.locator('[data-panel]:visible h2').textContent(), await button.textContent());
    }
    assert.equal(await page.locator('form, input, iframe').count(), 0);
    assert.deepEqual([...network], [url]);
    await open('/');
    await page.keyboard.press('Tab');
    await page.keyboard.press('Enter');
    assert.equal(await page.evaluate(() => document.activeElement.id), 'main');
    const menu = page.locator('.mobile-nav');
    await menu.locator('summary').focus();
    await page.keyboard.press('Enter');
    await menu.getByRole('link', { name: 'Features' }).focus();
    await page.keyboard.press('Escape');
    assert.equal(await menu.evaluate(node => node.open), false);
    assert(await menu.locator('summary').evaluate(node => node === document.activeElement));
    await open('/how-it-works/');
    await page.getByRole('button', { name: /Backend/ }).click();
    assert(await page.getByRole('heading', { name: 'Refresh the snapshot securely' }).isVisible());
    await page.emulateMedia({ reducedMotion: 'no-preference' });
    await open('/');
    assert.equal(await page.locator('h1 span').first().evaluate(node => getComputedStyle(node).animationName), 'settle');
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await open('/');
    assert.equal(await page.locator('h1 span').first().evaluate(node => getComputedStyle(node).animationName), 'none');
    assert.equal(await page.locator('html').evaluate(node => getComputedStyle(node).scrollBehavior), 'auto');
    const publicApi = await fetch(url + '/api/threat/monitoring/dashboard');
    assert.equal(publicApi.status, 404);
    assert.equal(publicApi.headers.get('set-cookie'), null);
    assert.equal((await fetch(url + '/demo/', { method: 'POST' })).status, 405);
    assert.equal((await fetch(url + '/assets/mark.svg')).status, 200);
    assert.deepEqual(errors, []);
    writeFileSync(join(capture, 'website-checks.json'), JSON.stringify({
      chromium: browser.version(), layoutChecks: 5 * Object.keys(pages).length, audits
    }, null, 2));
    console.log(`Website passed 50 layout checks and ${audits.length} axe audits on Chromium ${browser.version()}`);
  } finally {
    await browser?.close();
    server.close();
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
