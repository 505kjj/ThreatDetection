// Frozen calibration uses clipped log-odds followed by a logistic transform.
export function calibratedProbability(score, coefficient, intercept) {
  if (!Number.isFinite(score) || score < 0 || score > 1 ||
      !Number.isFinite(coefficient) || !Number.isFinite(intercept)) throw new TypeError('Invalid fusion input');
  const clipped = Math.max(1e-6, Math.min(1 - 1e-6, score));
  const value = coefficient * Math.log(clipped / (1 - clipped)) + intercept;
  return 1 / (1 + Math.exp(-value));
}

export function fixedFusion(url, other, urlScale, otherScale) {
  return 0.75 * calibratedProbability(url, ...urlScale) + 0.25 * calibratedProbability(other, ...otherScale);
}
