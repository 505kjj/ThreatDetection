// Offline synthetic metadata only. No Chrome API access, collection or product decisions.
const states = new Set(['confirmed', 'advisory', 'privacy', 'unavailable']);
const categories = new Set(['reputation', 'impersonation', 'redirect', 'credential', 'cookie',
  'permission', 'download', 'tracking', 'behavior', 'experimental']);

export function evidence(category, state, reason) {
  if (!categories.has(category) || !states.has(state) || typeof reason !== 'string') throw new TypeError('Invalid evidence');
  if (state === 'confirmed' && category !== 'reputation') throw new TypeError('Confirmation requires reputation evidence');
  return { category, state, reason };
}

export function assessFixture(input) {
  const results = [];
  if (input.reputation === 'confirmed') results.push(evidence('reputation', 'confirmed', 'authorized-match'));
  else if (input.reputation === 'unavailable') results.push(evidence('reputation', 'unavailable', 'snapshot-unavailable'));
  if (input.impersonation === true) results.push(evidence('impersonation', 'advisory', 'financial-lookalike'));
  if (input.redirect === 'unexplained') results.push(evidence('redirect', 'advisory', 'unexplained-destination-change'));
  if (input.form === 'insecure') results.push(evidence('credential', 'advisory', 'insecure-credential-form'));
  if (input.form === 'external') results.push(evidence('credential', 'advisory', 'external-form-action'));
  if (input.cookie === 'missing-secure' || input.cookie === 'broad-scope' || input.cookie === 'samesite-none') {
    results.push(evidence('cookie', 'privacy', input.cookie));
  }
  if (input.permission === 'granted') results.push(evidence('permission', 'privacy', 'sensitive-permission-granted'));
  if (input.download === 'mime-mismatch') results.push(evidence('download', 'advisory', 'mime-extension-mismatch'));
  if (input.tracker === 'listed') results.push(evidence('tracking', 'privacy', 'listed-third-party'));
  if (input.behavior === 'overlay' || input.behavior === 'popup' || input.behavior === 'iframe') {
    results.push(evidence('behavior', 'advisory', input.behavior));
  }
  if (input.experimental === 'available') results.push(evidence('experimental', 'unavailable', 'research-only'));
  return results;
}
