import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdtemp, readFile, realpath, rmdir, unlink, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { assertOutsideGit } from '../phase5a/run.mjs';
import { describeDOM } from './dom.mjs';
import { FIXTURES, ORIGIN } from './fixtures.mjs';
import { inspectHtml } from './parse.mjs';

const require = createRequire(import.meta.url);
const { chromium } = require('playwright');
const productionManifest = JSON.parse(await readFile(new URL('../../extension/manifest.json', import.meta.url)));

const probe = `
const describeDOM = ${describeDOM.toString()};
const adapter = {
  tag: node => node.nodeType === 1 ? node.localName : undefined,
  attr: (node, name) => node.getAttribute(name),
  children: node => Array.from(node.children || []),
  text: node => node.textContent || ''
};
function snapshot() {
  const start = performance.now();
  const features = describeDOM(document, location.href, adapter);
  document.documentElement.dataset.phase5eFixture = JSON.stringify({ features, milliseconds: performance.now() - start });
}
document.addEventListener('phase5e-fixture-inspect', snapshot);
snapshot();
`;

async function benchmark(destination) {
  const parent = await assertOutsideGit(await realpath(dirname(destination)));
  const extension = await mkdtemp(join(parent, 'mv3-fixture-'));
  let context;
  try {
    const [{ matches, run_at }] = productionManifest.content_scripts;
    await writeFile(join(extension, 'manifest.json'), JSON.stringify({
      manifest_version: productionManifest.manifest_version,
      name: 'Offline Phase 5E fixture probe', version: '1.0.0',
      content_scripts: [{ matches, run_at, js: ['probe.js'] }]
    }), { flag: 'wx' });
    await writeFile(join(extension, 'probe.js'), probe, { flag: 'wx' });
    context = await chromium.launchPersistentContext('', {
      channel: 'chromium', headless: true, serviceWorkers: 'block',
      args: ['--disable-background-networking', '--host-resolver-rules=MAP * ~NOTFOUND',
        '--proxy-server=http://127.0.0.1:9', '--disable-extensions-except=' + extension,
        '--load-extension=' + extension]
    });
    let blocked = 0;
    let fulfilled = 0;
    await context.route('**/*', async route => {
      const url = new URL(route.request().url());
      const name = url.pathname.slice(1);
      const fixture = url.origin === ORIGIN && Object.hasOwn(FIXTURES, name) && FIXTURES[name];
      if (!fixture) {
        blocked++;
        await route.abort();
        return;
      }
      fulfilled++;
      await route.fulfill({ contentType: 'text/html; charset=utf-8', body: fixture,
        headers: { 'Content-Security-Policy': "default-src 'none'; form-action 'none'" } });
    });
    const page = context.pages()[0] ?? await context.newPage();
    const read = async () => {
      await page.waitForSelector('html[data-phase5e-fixture]', { timeout: 10000, state: 'attached' });
      return JSON.parse(await page.locator('html').getAttribute('data-phase5e-fixture'));
    };
    const rows = [];
    for (const [name, html] of Object.entries(FIXTURES)) {
      const url = ORIGIN + '/' + name;
      const parsed = inspectHtml(html, url);
      assert.equal(parsed.status, 'usable');
      await page.goto(url, { waitUntil: 'load' });
      const native = await read();
      assert.deepEqual(native.features, parsed.features, name);
      const receipt = { name, staticParity: true, browserMs: native.milliseconds, features: native.features };
      if (name === 'dynamic-login') {
        await page.evaluate(() => {
          const panel = document.querySelector('#panel');
          const form = document.createElement('form');
          const field = document.createElement('input');
          field.setAttribute('type', 'password');
          form.append(field);
          panel.append(form);
          document.dispatchEvent(new Event('phase5e-fixture-inspect'));
        });
        const dynamic = await read();
        assert.equal(native.features.inputs_password, 0);
        assert.equal(dynamic.features.inputs_password, 1);
        assert.equal(dynamic.features.password_forms, 1);
        receipt.dynamic = { features: dynamic.features, browserMs: dynamic.milliseconds };
      }
      rows.push(receipt);
    }
    assert.equal(fulfilled, rows.length);
    const report = { engine: context.browser()?.version() ?? await page.evaluate(() => navigator.userAgent),
      manifestVersion: productionManifest.manifest_version,
      runAt: productionManifest.content_scripts[0].run_at, fulfilledSyntheticDocuments: fulfilled,
      blockedRequests: blocked, rows };
    await writeFile(destination, JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    console.log(JSON.stringify({ passed: rows.length, fulfilled, blocked, manifestVersion: report.manifestVersion }));
  } finally {
    await context?.close();
    for (const file of ['manifest.json', 'probe.js']) {
      try { await unlink(join(extension, file)); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
    await rmdir(extension);
  }
}

if (process.argv.length !== 3 || process.env.THREAT_PHASE3D_GUARDED !== '1') {
  throw new Error('Use the resource guard and a private browser report path');
}
await benchmark(resolve(process.argv[2]));
