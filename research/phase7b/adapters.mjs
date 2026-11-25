import { aggregateEvidence } from './policy.mjs';

const adapters = {
  url: receipt => numericEvidence(receipt),
  dom: receipt => numericEvidence(receipt),
  visual: receipt => typeof receipt?.matchesOfflineDecisions === 'boolean'
    ? { availability: 'available', code: receipt.matchesOfflineDecisions ? 'fixture-agreement' : 'fixture-disagreement' }
    : { availability: 'unavailable', code: 'missing-visual-receipt' },
  'browser-security': browserEvidence
};

function browserEvidence(receipt) {
  if (!receipt || receipt.form === 'unavailable') return { availability: 'unavailable', code: 'missing-browser-receipt' };
  if (!Array.isArray(receipt.evidence) || receipt.evidence.length > 32) throw new TypeError('Invalid browser evidence');
  if (receipt.evidence.some(item => item?.category === 'credential' && item?.state === 'advisory')) {
    return { availability: 'available', code: 'credential-advisory' };
  }
  return { availability: 'available', code: 'no-credential-advisory-observed' };
}

function numericEvidence(receipt) {
  if (!receipt || receipt.score === null) return { availability: 'unavailable', code: 'missing-score' };
  if (!Number.isFinite(receipt.score) || receipt.score < 0 || receipt.score > 1) throw new TypeError('Invalid score');
  return { availability: 'available', code: 'score-computed' };
}

// One coordinator per isolated fixture tab. Readers can honor an AbortSignal.
export function createResearchCoordinator(readers, { timeoutMs = 250 } = {}) {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 5000) throw new RangeError('Invalid deadline');
  let enabled = false;
  let active;
  function setEnabled(value) {
    enabled = value === true;
    if (!enabled) {
      active?.abort();
      active = undefined;
    }
  }
  async function evaluate(production) {
    const baseline = aggregateEvidence({ production, observations: [] });
    if (!enabled) return baseline;
    active?.abort();
    const request = new AbortController();
    active = request;
    const timeout = setTimeout(() => request.abort('deadline'), timeoutMs);
    const cancelled = new Promise(resolve => request.signal.addEventListener('abort', () => resolve({
      availability: 'unavailable', code: request.signal.reason === 'deadline' ? 'timeout' : 'cancelled'
    }), { once: true }));
    try {
      const observations = await Promise.all(Object.entries(adapters).map(async ([source, project]) => {
        const read = readers[source];
        const observation = typeof read === 'function'
          ? await Promise.race([Promise.resolve().then(() => read(request.signal)).then(project)
            .catch(() => ({ availability: 'error', code: 'invalid-or-failed-observation' })), cancelled])
          : { availability: 'unavailable', code: 'adapter-unavailable' };
        return { source, ...observation };
      }));
      if (active !== request || !enabled) return baseline;
      return aggregateEvidence({ production: baseline, observations, enabled });
    } finally {
      clearTimeout(timeout);
      if (active === request) active = undefined;
    }
  }
  return { evaluate, setEnabled };
}
