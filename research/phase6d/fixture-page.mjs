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

// Match Pillow's widened bilinear filter on downsampling. Filter premultiplied
// channels and composite onto white after both passes.
function weights(length, target) {
  const scale = length / target;
  const support = Math.max(1, scale);
  return Array.from({ length: target }, (_, index) => {
    const center = (index + 0.5) * scale - 0.5;
    const first = Math.max(0, Math.ceil(center - support));
    const last = Math.min(length - 1, Math.floor(center + support));
    const values = Array.from({ length: last - first + 1 }, (_, i) =>
      Math.max(0, 1 - Math.abs(first + i - center) / support));
    const total = values.reduce((sum, value) => sum + value, 0);
    return { first, values: values.map(value => value / total) };
  });
}

function resizeOnWhite(data, stride, left, top, width, height, nw, nh) {
  const horizontal = new Float32Array(nw * height * 4);
  weights(width, nw).forEach(({ first, values }, x) => {
    for (let y = 0; y < height; y++) {
      const output = 4 * (y * nw + x);
      values.forEach((weight, i) => {
        const input = 4 * ((top + y) * stride + left + first + i);
        const alpha = data[input + 3] / 255;
        for (let c = 0; c < 3; c++) horizontal[output + c] += weight * alpha * data[input + c];
        horizontal[output + 3] += weight * alpha;
      });
    }
  });
  const output = new Uint8ClampedArray(size * size * 4).fill(255);
  const offsetX = Math.floor((size - nw) / 2), offsetY = Math.floor((size - nh) / 2);
  weights(height, nh).forEach(({ first, values }, y) => {
    for (let x = 0; x < nw; x++) {
      const pixel = 4 * ((offsetY + y) * size + offsetX + x);
      for (let c = 0; c < 3; c++) {
        let channel = 0;
        values.forEach((weight, i) => {
          const input = 4 * ((first + i) * nw + x);
          channel += weight * (horizontal[input + c] + 255 * (1 - horizontal[input + 3]));
        });
        output[pixel + c] = channel;
      }
    }
  });
  return output;
}

function roundEven(value) {
  const floor = Math.floor(value);
  return value - floor === 0.5 ? floor + floor % 2 : Math.round(value);
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
  const nw = Math.max(1, roundEven(w * scale)), nh = Math.max(1, roundEven(h * scale));
  return toTensor(resizeOnWhite(data, width, left, top, w, h, nw, nh));
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
