import * as ort from './ort.wasm.min.mjs';
import { tokenize } from './tokenize.mjs';

ort.env.wasm.numThreads = 1;
ort.env.wasm.wasmPaths = chrome.runtime.getURL('/');

async function run() {
  const result = {};
  for (const name of ['cnn', 'transformer']) {
    const reference = await (await fetch(chrome.runtime.getURL(`${name}-reference.json`))).json();
    const start = performance.now();
    const session = await ort.InferenceSession.create(chrome.runtime.getURL(`${name}.onnx`), { executionProviders: ['wasm'] });
    const initializationMs = performance.now() - start;
    const scores = [];
    const durations = [];
    let tokenParity = true;
    for (let index = 0; index < 110; index++) {
      const fixture = index % reference.fixtures.length;
      const vector = tokenize(reference.fixtures[fixture], name === 'cnn' ? 160 : 80);
      if (vector.some((value, i) => value !== BigInt(reference.vectors[fixture][i]))) tokenParity = false;
      const tensor = new ort.Tensor('int64', vector, [1, vector.length]);
      const began = performance.now();
      const output = await session.run({ tokens: tensor });
      const duration = performance.now() - began;
      const score = 1 / (1 + Math.exp(-output.logits.data[0]));
      if (index < reference.vectors.length) scores.push(score);
      if (index >= 10) durations.push(duration);
    }
    result[name] = { scores, durations, initializationMs, tokenParity };
    await session.release();
  }
  document.body.textContent = JSON.stringify(result);
}
run().catch(error => { document.body.textContent = JSON.stringify({ error: error.stack }); });
