const assert = require('node:assert/strict');
const { cpSync, mkdirSync, readFileSync, writeFileSync } = require('node:fs');
const { join, resolve } = require('node:path');
const { chromium } = require('playwright');

const root = resolve(__dirname, '../..');
const experiment = resolve(process.argv[2] || '');
if (!process.argv[2] || experiment === root || experiment.startsWith(root + require('node:path').sep)) {
  throw new Error('Provide a private experiment directory outside the repository');
}
const packageDir = join(experiment, 'browser-package');
mkdirSync(packageDir);
for (const name of ['manifest.json', 'worker.mjs', 'ngram.mjs', 'url-features.mjs', 'xgboost.mjs', 'fixture.html']) {
  cpSync(join(__dirname, name), join(packageDir, name));
}
for (const [source, name] of [['extension/reputation.mjs', 'reputation.mjs'],
  ['extension/settings.mjs', 'settings.mjs'], ['extension/vendor/tldts.mjs', 'tldts.mjs']]) {
  cpSync(join(root, source), join(packageDir, name));
}
cpSync(join(experiment, 'ngram', 'model.json'), join(packageDir, 'model.json'));
for (const name of ['url', 'dom']) cpSync(join(experiment, 'xgboost', `${name}.json`), join(packageDir, `${name}.json`));
const reference = JSON.parse(readFileSync(join(experiment, 'ngram', 'reference.json')));
const quantile = (values, p) => [...values].sort((a, b) => a - b)[Math.ceil(values.length * p) - 1];

async function main() {
  const context = await chromium.launchPersistentContext(join(experiment, 'chromium-profile'), {
    headless: true, channel: 'chromium',
    args: [`--disable-extensions-except=${packageDir}`, `--load-extension=${packageDir}`, '--enable-precise-memory-info']
  });
  try {
    let outboundRequests = 0;
    await context.route(/^https?:\/\//, async route => {
      outboundRequests++;
      await route.abort();
    });
    let worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
    const extensionId = new URL(worker.url()).host;
    const page = await context.newPage();
    await page.goto(`chrome-extension://${extensionId}/fixture.html`);
    const send = inputs => page.evaluate(async inputs => chrome.runtime.sendMessage({ type: 'synthetic-inference', inputs }), inputs);
    const first = await send(reference.fixtures);
    if (first.error) throw new Error(first.error);
    const invalid = await send([null]);
    assert.equal(invalid.error, 'Invalid model input');
    assert.deepEqual((await send(reference.fixtures)).scores, first.scores);
    const { extractUrl } = await import('../../evaluation/features.mjs');
    const urlFixtures = ['https://example.test/', 'https://user:secret@bücher.example.test/a%2fb?q=secret#private',
      'http://test.example.test:8080/a/123', 'https://example.test/💳', 'ftp://example.test/', 'not a URL'];
    const urlResults = await page.evaluate(async inputs => chrome.runtime.sendMessage({ type: 'synthetic-url', inputs }), urlFixtures);
    for (let index = 0; index < urlFixtures.length; index++) {
      assert.deepEqual(urlResults.scores[index]?.features ?? null, extractUrl(urlFixtures[index], 'synthetic')?.features ?? null);
    }
    const trees = {};
    for (const name of ['url', 'dom']) {
      const expected = JSON.parse(readFileSync(join(experiment, 'xgboost', `${name}-reference.json`)));
      const result = await page.evaluate(async ({ name, inputs }) =>
        chrome.runtime.sendMessage({ type: 'synthetic-trees', model: name, inputs }), { name, inputs: expected.vectors });
      if (result.error) throw new Error(result.error);
      const errors = result.scores.map((score, index) => Math.abs(score - expected.scores[index]));
      assert.ok(Math.max(...errors) <= expected.tolerance, `${name} tree parity exceeds tolerance`);
      const thresholds = Object.values(expected.thresholds).filter(value => value !== null);
      for (const threshold of thresholds) {
        result.scores.forEach((score, index) => assert.equal(score >= threshold, expected.scores[index] >= threshold));
      }
      trees[name] = { fixtures: errors.length, tolerance: expected.tolerance, maximumAbsoluteError: Math.max(...errors),
        thresholdDecisionsAgree: thresholds.length ? true : null };
    }
    const errors = first.scores.map((score, index) => Math.abs(score - reference.scores[index]));
    assert.ok(Math.max(...errors) <= reference.tolerance, `Parity exceeds ${reference.tolerance}`);
    for (const threshold of Object.values(reference.thresholds).filter(value => value !== null)) {
      first.scores.forEach((score, index) => assert.equal(score >= threshold, reference.scores[index] >= threshold));
    }
    const inputs = Array.from({ length: 1000 }, (_, index) => reference.fixtures[index % reference.fixtures.length]);
    const runs = await Promise.all([send(inputs), send(inputs), send(inputs)]);
    for (const run of runs) assert.equal(run.scores.length, inputs.length);
    const durations = runs.flatMap(run => run.durations);
    const cdp = await context.newCDPSession(page);
    await cdp.send('ServiceWorker.enable');
    await cdp.send('ServiceWorker.stopAllWorkers');
    const recovered = await send(reference.fixtures);
    assert.deepEqual(recovered.scores, first.scores);
    assert.equal(outboundRequests, 0);
    const result = {
      browser: await context.browser().version(), fixtures: reference.fixtures.length,
      tolerance: reference.tolerance, maximumAbsoluteError: Math.max(...errors),
      thresholdDecisionsAgree: true, initializationMs: first.initializationMs,
      repeatedInferences: durations.length, medianMs: quantile(durations, 0.5), p95Ms: quantile(durations, 0.95),
      concurrentRequests: runs.length, serviceWorkerRecovery: true, invalidInputRecovery: true,
      outboundPageRequests: outboundRequests, urlFeatureFixtures: urlFixtures.length, trees,
      note: 'Synthetic normalized strings only. DOM, end-to-end URL extraction, memory growth and CPU attribution are not measured.'
    };
    writeFileSync(join(experiment, 'browser-results.json'), JSON.stringify(result, null, 2) + '\n', { flag: 'wx' });
    console.log(JSON.stringify(result));
  } finally {
    await context.close();
  }
}
main().catch(error => { console.error(error.stack); process.exitCode = 1; });
