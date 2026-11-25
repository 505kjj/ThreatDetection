// Offline policy exploration. Existing product enforcement remains authoritative.
const sources = new Set(['reputation', 'financial', 'url', 'dom', 'visual', 'browser-security']);
const availability = new Set(['available', 'unavailable', 'error']);
const verdicts = new Set(['ALLOW', 'SHOW_WARNING', 'BLOCK_PHISHING', 'BLOCK_MALWARE', 'UNAVAILABLE']);

export function aggregateEvidence({ production, observations, enabled = false }) {
  if (!production || !verdicts.has(production.decision) || typeof production.bypassAllowed !== 'boolean' ||
      (production.bypassAllowed && production.decision !== 'BLOCK_PHISHING') ||
      !Array.isArray(observations) || observations.length > 32 || typeof enabled !== 'boolean') {
    throw new TypeError('Invalid policy input');
  }
  const evidence = observations.map(item => {
    if (!item || !sources.has(item.source) || !availability.has(item.availability) ||
        typeof item.code !== 'string' || !/^[a-z0-9-]{1,64}$/.test(item.code)) {
      throw new TypeError('Invalid evidence item');
    }
    return { source: item.source, availability: item.availability, code: item.code };
  });
  // The supplied production decision is opaque and retains the existing bypass policy.
  return {
    decision: production.decision,
    bypassAllowed: production.bypassAllowed,
    researchEnabled: enabled,
    evidence: enabled ? evidence : [],
    explanation: enabled ? 'Research observations are informational and do not change the product decision.' :
      'Research observations are disabled.'
  };
}
