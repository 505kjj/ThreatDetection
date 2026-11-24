import * as ort from './ort.wasm.min.mjs';

const size = 224;
const pixels = size * size;
const mean = [0.485, 0.456, 0.406];
const std = [0.229, 0.224, 0.225];
ort.env.wasm.numThreads = 1;
ort.env.wasm.proxy = false;
ort.env.wasm.wasmPaths = new URL('.', location.href).href;

function canvas(width, height) {
  const surface = document.createElement('canvas');
  surface.width = width;
  surface.height = height;
  return surface.getContext('2d', { willReadFrequently: true });
}

function toTensor(rgb) {
  const values = new Float32Array(3 * pixels);
  for (let i = 0; i < pixels; i++) {
    for (let c = 0; c < 3; c++) {
      values[c * pixels + i] = (rgb[4 * i + c] / 255 - mean[c]) / std[c];
    }
  }
  return new ort.Tensor('float32', values, [1, 3, size, size]);
}

function tensor(image, normalized = false) {
  const width = image.naturalWidth;
  const height = image.naturalHeight;
  if (Math.min(width, height) < 4 || Math.max(width, height) > 2048 || width * height > 2_000_000) {
    throw new Error('Fixture exceeds dimensions');
  }
  const source = canvas(width, height);
  source.drawImage(image, 0, 0);
  const data = source.getImageData(0, 0, width, height).data;
  if (normalized) {
    if (width !== size || height !== size) throw new Error('Invalid canonical fixture');
    return toTensor(data);
  }
  let left = width, top = height, right = -1, bottom = -1;
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      if (data[4 * (y * width + x) + 3] === 0) continue;
      left = Math.min(left, x);
      top = Math.min(top, y);
      right = Math.max(right, x);
      bottom = Math.max(bottom, y);
    }
  }
  if (right < 0) throw new Error('No visible content');
  const w = right - left + 1, h = bottom - top + 1;
  const scale = (size - 16) / Math.max(w, h);
  const nw = Math.max(1, Math.round(w * scale)), nh = Math.max(1, Math.round(h * scale));
  const context = canvas(size, size);
  context.fillStyle = 'white';
  context.fillRect(0, 0, size, size);
  context.drawImage(image, left, top, w, h, Math.floor((size - nw) / 2), Math.floor((size - nh) / 2), nw, nh);
  return toTensor(context.getImageData(0, 0, size, size).data);
}

async function load(name) {
  const image = new Image();
  image.src = './' + name;
  await image.decode();
  return image;
}

globalThis.runPhase6a = async function (names, canonicalNames, iterations) {
  const images = await Promise.all(names.map(load));
  const start = performance.now();
  const session = await ort.InferenceSession.create('./embedding.onnx', {
    executionProviders: ['wasm'], graphOptimizationLevel: 'all'
  });
  const initializationMs = performance.now() - start;
  const extraction = [], inference = [], prediction = [];
  for (let i = 0; i < iterations + 3; i++) {
    const image = images[i % images.length];
    const before = performance.now();
    const input = tensor(image);
    const prepared = performance.now();
    const result = await session.run({ pixels: input });
    const finished = performance.now();
    const output = result.embedding.data;
    const norm = Math.hypot(...output);
    if (i < names.length) prediction.push(Array.from(output, value => value / norm));
    input.dispose();
    result.embedding.dispose();
    if (i >= 3) {
      extraction.push(prepared - before);
      inference.push(finished - prepared);
    }
  }
  const heapBytes = performance.memory?.usedJSHeapSize ?? null;
  const canonical = [];
  for (const image of await Promise.all(canonicalNames.map(load))) {
    const input = tensor(image, true);
    const result = await session.run({ pixels: input });
    const output = result.embedding.data;
    const norm = Math.hypot(...output);
    canonical.push(Array.from(output, value => value / norm));
    input.dispose();
    result.embedding.dispose();
  }
  await session.release();
  return { initializationMs, extraction, inference, prediction, canonical, heapBytes };
};
