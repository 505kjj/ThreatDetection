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
for (const name of ['manifest.json', 'worker.mjs', 'ngram.mjs', 'url-features.mjs', 'xgboost.mjs', 'fusion.mjs', 'fixture.html']) {
  cpSync(join(__dirname, name), join(packageDir, name));
}
for (const [source, name] of [['extension/reputation.mjs', 'reputation.mjs'],
  ['extension/settings.mjs', 'settings.mjs'], ['extension/vendor/tldts.mjs', 'tldts.mjs']]) {
  cpSync(join(root, source), join(packageDir, name));
}
cpSync(join(experiment, 'ngram', 'model.json'), join(packageDir, 'model.json'));
cpSync(join(experiment, 'ngram-f', 'model.json'), join(packageDir, 'grouped.json'));
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
    const timed = [];
    // Canonicalization and scoring must agree when synthetic query and fragment data is appended.
    const decorated = reference.fixtures.map(url => url + '?fixture=ignored#ignored');
    for (let repeat = 0; repeat < 5; repeat++) {
      const endToEnd = await page.evaluate(async inputs => {
        const start = performance.now();
        const response = await chrome.runtime.sendMessage({ type: 'synthetic-url', inputs });
        return { response, elapsed: performance.now() - start };
      }, decorated);
      assert.equal(endToEnd.response.scores.length, reference.scores.length);
      endToEnd.response.scores.forEach((result, index) => {
        assert.ok(Math.abs(result.score - reference.scores[index]) <= reference.tolerance);
        for (const threshold of Object.values(reference.thresholds).filter(value => value !== null)) {
          assert.equal(result.score >= threshold, reference.scores[index] >= threshold);
        }
      });
      timed.push(endToEnd.elapsed);
    }
    const urlPipeline = { fixtures: decorated.length, batches: timed.length,
      batchMedianMs: quantile(timed, 0.5), batchP95Ms: quantile(timed, 0.95) };
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
      const repeated = Array.from({ length: 1000 }, (_, index) => expected.vectors[index % expected.vectors.length]);
      const timing = await page.evaluate(async ({ name, inputs }) =>
        chrome.runtime.sendMessage({ type: 'synthetic-trees', model: name, inputs }), { name, inputs: repeated });
      trees[name] = { fixtures: errors.length, tolerance: expected.tolerance, maximumAbsoluteError: Math.max(...errors),
        thresholdDecisionsAgree: thresholds.length ? true : null,
        medianMs: quantile(timing.durations, 0.5), p95Ms: quantile(timing.durations, 0.95), samples: repeated.length };
    }
    const fusionReference = JSON.parse(readFileSync(join(experiment, 'fusion-reference.json')));
    const fusion = {};
    let domPipeline = null;
    for (const name of ['phase5d', 'phase5f']) {
      const expected = fusionReference[name];
      const urlScale = name === 'phase5d'
        ? [expected.scales.ngram.coefficient, expected.scales.ngram.intercept] : expected.scales['url-ngram'];
      const otherScale = name === 'phase5d'
        ? [expected.scales.xgboost.coefficient, expected.scales.xgboost.intercept] : expected.scales['dom-weighted'];
      const vectors = name === 'phase5d' ? fusionReference.urlVectors : fusionReference.domVectors;
      const inputs = fusionReference.fixtures.map((text, index) => ({ text, vector: vectors[index] }));
      const actual = await page.evaluate(async message => chrome.runtime.sendMessage(message),
        { type: 'synthetic-fusion', model: name, inputs, urlScale, otherScale });
      if (name === 'phase5f') {
        const missing = await page.evaluate(async message => chrome.runtime.sendMessage(message),
          { type: 'synthetic-fusion', model: name, inputs: [{ text: inputs[0].text, vector: null }, inputs[0]],
            urlScale, otherScale });
        assert.deepEqual(missing.scores, [null, actual.scores[0]]);
        if (process.argv[3]) {
          const reference = JSON.parse(readFileSync(process.argv[3]));
          const { FIXTURES, ORIGIN } = await import('../phase5e/fixtures.mjs');
          const { describeDOM, FEATURE_GROUPS } = await import('../phase5e/dom.mjs');
          const fixtureInputs = reference.names.map(name => ({
            text: ORIGIN + '/' + name,
            html: name === 'dynamic-login-materialized'
              ? FIXTURES['dynamic-login'].replace('</main>', '<form><input type="password"></form></main>')
              : FIXTURES[name]
          }));
          const dom = await page.evaluate(async ({ source, fixtures, columns }) => {
            // Playwright serializes the frozen function into its isolated execution world.
            const describe = (0, eval)(`(${source})`);
            const adapter = { tag: node => node.nodeType === 1 ? node.localName : undefined,
              attr: (node, attribute) => node.getAttribute(attribute),
              children: node => Array.from(node.children || []), text: node => node.textContent || '' };
            return fixtures.map(({ text, html }) => {
              const doc = new DOMParser().parseFromString(html, 'text/html');
              const values = describe(doc, text, adapter);
              const forms = Math.max(values.forms, 1);
              const auth = Number([values.inputs_password, values.inputs_payment,
                values.actions_external, values.iframe_external].some(value => value > 0));
              return { text, vector: [...columns.map(key => Math.fround(values[key])),
                values.actions_external / forms, values.actions_local / forms, values.password_forms / forms,
                values.payment_forms / forms, values.iframe_external / Math.max(values.iframe, 1), auth] };
            });
          }, { source: describeDOM.toString(), fixtures: fixtureInputs, columns: Object.values(FEATURE_GROUPS).flat() });
          assert.deepEqual(dom.map(item => item.vector), reference.vectors);
          const scored = await page.evaluate(async message => chrome.runtime.sendMessage(message),
            { type: 'synthetic-fusion', model: name, inputs: dom, urlScale, otherScale });
          assert.equal(scored.scores.length, reference.scores.length);
          const maximumError = Math.max(...scored.scores.map((score, index) => {
            for (const threshold of Object.values(expected.thresholds).filter(value => value !== null)) {
              assert.equal(score >= threshold, reference.scores[index] >= threshold);
            }
            return Math.abs(score - reference.scores[index]);
          }));
          assert.ok(maximumError <= reference.tolerance);
          domPipeline = { fixtures: dom.length, maximumError, missingDomUnavailable: true };
        }
      }
      if (actual.error) throw new Error(actual.error);
      const errors = actual.scores.map((score, index) => Math.abs(score - expected.scores[index]));
      assert.ok(Math.max(...errors) <= fusionReference.tolerance, `${name} fusion parity exceeds tolerance`);
      for (const threshold of Object.values(expected.thresholds).filter(value => value !== null)) {
        actual.scores.forEach((score, index) => assert.equal(score >= threshold, expected.scores[index] >= threshold));
      }
      const repeated = Array.from({ length: 1000 }, (_, index) => inputs[index % inputs.length]);
      const timing = await page.evaluate(async message => chrome.runtime.sendMessage(message),
        { type: 'synthetic-fusion', model: name, inputs: repeated, urlScale, otherScale });
      fusion[name] = { fixtures: errors.length, tolerance: fusionReference.tolerance,
        maximumAbsoluteError: Math.max(...errors), thresholdDecisionsAgree: true,
        medianMs: quantile(timing.durations, 0.5), p95Ms: quantile(timing.durations, 0.95), samples: repeated.length };
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
      outboundPageRequests: outboundRequests, urlFeatureFixtures: urlFixtures.length, trees, fusion,
      urlPipeline, domPipeline,
      note: 'Synthetic URL and inert HTML fixtures. Live navigation collection and long-running memory are outside this run.'
    };
    writeFileSync(join(experiment, 'browser-results.json'), JSON.stringify(result, null, 2) + '\n', { flag: 'wx' });
    console.log(JSON.stringify(result));
  } finally {
    await context.close();
  }
}
main().catch(error => { console.error(error.stack); process.exitCode = 1; });
