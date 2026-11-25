const assert = require('node:assert/strict');
const { cpSync, mkdirSync, readFileSync, writeFileSync } = require('node:fs');
const { join, resolve, sep } = require('node:path');
const { chromium } = require('playwright');

const root = resolve(__dirname, '../..');
const experiment = resolve(process.argv[2] || '');
const runtime = resolve(process.argv[3] || '');
if (!process.argv[2] || !process.argv[3] || experiment === root || experiment.startsWith(root + sep)) {
  throw new Error('Provide a private experiment directory and local ONNX Runtime Web dist directory');
}
const packageDir = join(experiment, 'neural-package');
mkdirSync(packageDir);
writeFileSync(join(packageDir, 'manifest.json'), JSON.stringify({ manifest_version: 3,
  name: 'Offline sequence research fixture', version: '0.1.0',
  background: { service_worker: 'empty.js' },
  content_security_policy: { extension_pages: "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'; connect-src 'self'" } }));
writeFileSync(join(packageDir, 'empty.js'), '');
writeFileSync(join(packageDir, 'fixture.html'), '<!doctype html><html lang="en"><meta charset="utf-8"><title>Sequence fixture</title><body>Running<script type="module" src="neural-page.mjs"></script></body></html>');
cpSync(join(__dirname, 'neural-page.mjs'), join(packageDir, 'neural-page.mjs'));
cpSync(join(__dirname, 'tokenize.mjs'), join(packageDir, 'tokenize.mjs'));
for (const name of ['ort.wasm.min.mjs', 'ort-wasm-simd-threaded.mjs', 'ort-wasm-simd-threaded.wasm']) {
  cpSync(join(runtime, name), join(packageDir, name));
}
for (const name of ['cnn.onnx', 'cnn-reference.json', 'transformer.onnx', 'transformer-reference.json']) {
  cpSync(join(experiment, 'neural', name), join(packageDir, name));
}
const quantile = (values, p) => [...values].sort((a, b) => a - b)[Math.ceil(values.length * p) - 1];

async function main() {
  const context = await chromium.launchPersistentContext(join(experiment, 'neural-profile'), {
    headless: true, channel: 'chromium', args: ['--disable-background-networking', '--host-resolver-rules=MAP * ~NOTFOUND',
      '--proxy-server=http://127.0.0.1:9', `--disable-extensions-except=${packageDir}`, `--load-extension=${packageDir}`]
  });
  try {
    const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
    const page = await context.newPage();
    await page.goto(`chrome-extension://${new URL(worker.url()).host}/fixture.html`);
    await page.waitForFunction(() => document.body.textContent.trim().startsWith('{'), null, { timeout: 60000 });
    const actual = JSON.parse(await page.locator('body').innerText());
    if (actual.error) throw new Error(actual.error);
    const results = {};
    for (const name of ['cnn', 'transformer']) {
      const reference = JSON.parse(readFileSync(join(experiment, 'neural', `${name}-reference.json`)));
      assert.equal(actual[name].tokenParity, true, `${name} tokenization differs`);
      const errors = actual[name].scores.map((score, index) => Math.abs(score - reference.scores[index]));
      assert.ok(Math.max(...errors) <= reference.tolerance, `${name} parity exceeds tolerance`);
      for (const threshold of Object.values(reference.thresholds).filter(value => value !== null)) {
        actual[name].scores.forEach((score, index) => assert.equal(score >= threshold, reference.scores[index] >= threshold));
      }
      results[name] = { fixtures: errors.length, tolerance: reference.tolerance,
        maximumAbsoluteError: Math.max(...errors), thresholdDecisionsAgree: true,
        tokenParity: true, initializationMs: actual[name].initializationMs, samples: actual[name].durations.length,
        medianMs: quantile(actual[name].durations, 0.5), p95Ms: quantile(actual[name].durations, 0.95) };
    }
    const report = { browser: context.browser().version(), executionProvider: 'wasm', threads: 1, results };
    writeFileSync(join(experiment, 'neural-results.json'), JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
    console.log(JSON.stringify(report));
  } finally { await context.close(); }
}
main().catch(error => { console.error(error.stack); process.exitCode = 1; });
