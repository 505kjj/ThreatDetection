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
for (const name of ['manifest.json', 'worker.mjs', 'ngram.mjs', 'fixture.html']) {
  cpSync(join(__dirname, name), join(packageDir, name));
}
cpSync(join(experiment, 'ngram', 'model.json'), join(packageDir, 'model.json'));
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
      outboundPageRequests: outboundRequests,
      note: 'Synthetic normalized strings only. DOM, end-to-end URL extraction, memory growth and CPU attribution are not measured.'
    };
    writeFileSync(join(experiment, 'browser-results.json'), JSON.stringify(result, null, 2) + '\n', { flag: 'wx' });
    console.log(JSON.stringify(result));
  } finally {
    await context.close();
  }
}
main().catch(error => { console.error(error.stack); process.exitCode = 1; });
