import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { copyFile, mkdtemp, readFile, realpath, rmdir, stat, unlink, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertOutsideGit } from '../phase5a/run.mjs';

const require = createRequire(import.meta.url);
const { chromium } = require('playwright');
const here = fileURLToPath(new URL('.', import.meta.url));
const runtimeFiles = ['ort.wasm.min.mjs', 'ort-wasm-simd-threaded.mjs', 'ort-wasm-simd-threaded.wasm'];
const allowedOrigins = ['https://canvas-a.example.test', 'https://canvas-b.example.test'];

function stats(values) {
  const sorted = [...values].sort((a, b) => a - b);
  function quantile(q) {
    const index = q * (sorted.length - 1), base = Math.floor(index);
    return sorted[base] + (sorted[Math.ceil(index)] - sorted[base]) * (index - base);
  }
  return { medianMs: quantile(0.5), p95Ms: quantile(0.95) };
}

async function benchmark(exported, runtime, output) {
  const parent = await assertOutsideGit(await realpath(dirname(output)));
  await assertOutsideGit(await realpath(exported));
  await assertOutsideGit(await realpath(runtime));
  const extension = await mkdtemp(join(parent, 'mv3-phase6a-'));
  const installed = [];
  const manifest = {
    manifest_version: 3, name: 'Phase 6A inert visual fixture probe', version: '1.0.0',
    background: { service_worker: 'worker.js' }, permissions: [], host_permissions: [],
    content_security_policy: { extension_pages:
      "script-src 'self' 'wasm-unsafe-eval'; object-src 'none'; connect-src 'self'; img-src 'self';" }
  };
  const expected = JSON.parse(await readFile(join(exported, 'browser-vectors.json'), 'utf8'));
  assert.equal(expected.length, 3);
  assert(expected.every((item, i) => item.name === 'fixture-' + i + '.png' &&
    item.normalized === 'normalized-' + i + '.png'));
  let context;
  const save = async (name, data) => {
    await writeFile(join(extension, name), data, { flag: 'wx' });
    installed.push(name);
  };
  const copy = async (source, name) => {
    await copyFile(join(source, name), join(extension, name));
    installed.push(name);
  };
  try {
    await save('manifest.json', JSON.stringify(manifest));
    await save('worker.js', '// Empty service worker for discovery by the fixture driver.\n');
    await save('probe.html', '<!doctype html><meta charset="utf-8"><script type="module" src="fixture-page.mjs"></script>');
    await copy(here, 'fixture-page.mjs');
    await copy(exported, 'embedding.onnx');
    for (const name of runtimeFiles) await copy(runtime, name);
    for (const item of expected) {
      await copy(exported, item.name);
      await copy(exported, item.normalized);
    }
    context = await chromium.launchPersistentContext('', {
      channel: 'chromium', headless: true,
      args: ['--disable-background-networking', '--host-resolver-rules=MAP * ~NOTFOUND',
        '--proxy-server=http://127.0.0.1:9', '--disable-extensions-except=' + extension,
        '--load-extension=' + extension, '--enable-precise-memory-info']
    });
    const worker = context.serviceWorkers()[0] ?? await context.waitForEvent('serviceworker', { timeout: 15000 });
    const extensionOrigin = new URL(worker.url()).origin === 'null'
      ? 'chrome-extension://' + new URL(worker.url()).hostname : new URL(worker.url()).origin;
    const demo = await readFile(join(exported, expected[0].name));
    let blocked = 0, syntheticRequests = 0;
    await context.route('**/*', async route => {
      const address = new URL(route.request().url());
      if (address.protocol === 'chrome-extension:' && address.hostname === new URL(extensionOrigin).hostname) {
        await route.continue();
      } else if (allowedOrigins.includes(address.origin) && address.pathname === '/fixture.png') {
        syntheticRequests++;
        await route.fulfill({ contentType: 'image/png', body: demo });
      } else if (address.origin === allowedOrigins[0] && address.pathname === '/controls') {
        syntheticRequests++;
        await route.fulfill({ contentType: 'text/html', body:
          '<img id="local" src="/fixture.png"><img id="foreign" src="https://canvas-b.example.test/fixture.png">' });
      } else if (address.origin === allowedOrigins[1] && address.pathname === '/frame') {
        syntheticRequests++;
        await route.fulfill({ contentType: 'text/html', body: '<!doctype html><title>Isolated fixture frame</title>' });
      } else {
        blocked++;
        await route.abort();
      }
    });
    const page = context.pages()[0] ?? await context.newPage();
    await page.goto(extensionOrigin + '/probe.html', { waitUntil: 'load' });
    await page.waitForFunction(() => typeof globalThis.runPhase6a === 'function');
    const result = await page.evaluate(([names, canonical]) => globalThis.runPhase6a(names, canonical, 24),
      [expected.map(item => item.name), expected.map(item => item.normalized)]);
    function distances(output) {
      return expected.map((item, i) => {
        assert.equal(output[i].length, item.vector.length);
        return item.vector.reduce((sum, value, j) => sum + value * output[i][j], 0);
      });
    }
    const similarities = distances(result.prediction);
    const canonical = distances(result.canonical);
    assert(canonical.every(value => value >= 0.9999), 'Identical normalized inputs diverged in ONNX');
    await page.goto(allowedOrigins[0] + '/controls', { waitUntil: 'load' });
    const canvasReadback = await page.evaluate(async () => {
      const outcome = {};
      for (const id of ['local', 'foreign']) {
        const image = document.getElementById(id);
        await image.decode();
        const surface = document.createElement('canvas').getContext('2d');
        surface.drawImage(image, 0, 0, 16, 16);
        try {
          surface.getImageData(0, 0, 1, 1);
          outcome[id] = 'readable';
        } catch (error) {
          outcome[id] = error.name;
        }
      }
      return outcome;
    });
    assert.deepEqual(canvasReadback, {local: 'readable', foreign: 'SecurityError'});
    const observationLimits = await page.evaluate(async () => {
      const initialImageCount = document.images.length;
      const delayed = new Image();
      delayed.src = '/fixture.png';
      document.body.append(delayed);
      await delayed.decode();
      const frame = document.createElement('iframe');
      const loaded = new Promise(resolve => frame.addEventListener('load', resolve, { once: true }));
      frame.src = 'https://canvas-b.example.test/frame';
      document.body.append(frame);
      await loaded;
      return { initialImageCount, laterImageCount: document.images.length,
        crossOriginFrameReadable: frame.contentDocument !== null };
    });
    assert.deepEqual(observationLimits, {initialImageCount: 2, laterImageCount: 3, crossOriginFrameReadable: false});
    const modelBytes = (await stat(join(extension, 'embedding.onnx'))).size;
    const runtimeBytes = (await Promise.all(runtimeFiles.map(name => stat(join(extension, name)))))
      .reduce((sum, entry) => sum + entry.size, 0);
    const report = {
      preprocessingVariant: 'canvas-high-smoothing', predefinedCosineGate: 0.97,
      engine: context.browser()?.version() ?? await page.evaluate(() => navigator.userAgent),
      permissions: manifest.permissions, hostPermissions: manifest.host_permissions, wasmThreads: 1,
      runtimeBytes, modelBytes, initializationMs: result.initializationMs,
      extraction: stats(result.extraction), inference: stats(result.inference),
      extractionPlusInference: stats(result.extraction.map((value, i) => value + result.inference[i])),
      rendererJsHeapBytes: result.heapBytes, measuredIterations: result.extraction.length,
      minimumCanvasPreprocessCosine: Math.min(...similarities), minimumIdenticalInputCosine: Math.min(...canonical),
      canvasParityAt097: similarities.every(value => value >= 0.97), fixtureCount: expected.length,
      canvasReadback, observationLimits, syntheticRequests, blockedRequests: blocked
    };
    await writeFile(output, JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
    console.log(JSON.stringify(report));
  } finally {
    await context?.close();
    for (const name of installed) await unlink(join(extension, name));
    await rmdir(extension);
  }
}

if (process.argv.length !== 5 || process.env.THREAT_PHASE3D_GUARDED !== '1') {
  throw new Error('Use the Windows guard with private export, runtime and output paths');
}
await benchmark(...process.argv.slice(2).map(value => resolve(value)));
