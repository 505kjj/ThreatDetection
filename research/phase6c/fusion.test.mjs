import test from 'node:test';
import assert from 'node:assert/strict';
import { calibratedProbability, fixedFusion } from './fusion.mjs';

test('fusion uses clipped log-odds calibration and fixed weights', () => {
  const scale = [1, 0];
  assert.ok(Math.abs(calibratedProbability(0, ...scale) - 1e-6) < 1e-12);
  assert.ok(Math.abs(calibratedProbability(1, ...scale) - (1 - 1e-6)) < 1e-12);
  assert.ok(Math.abs(fixedFusion(0.8, 0.4, scale, scale) - 0.7) < 1e-12);
  assert.throws(() => fixedFusion(NaN, 0.4, scale, scale), TypeError);
});
