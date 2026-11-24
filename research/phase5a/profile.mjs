import { featureColumns } from '../../evaluation/features.mjs';

export function distribution(values) {
  const ordered = values.filter(Number.isFinite).sort((a, b) => a - b);
  if (!ordered.length) return null;
  const position = (ordered.length - 1) / 2;
  return { min: ordered[0], median: (ordered[Math.floor(position)] + ordered[Math.ceil(position)]) / 2,
    max: ordered.at(-1), nonzero: ordered.filter(value => value !== 0).length, measured: ordered.length };
}

function frequencies(values) {
  const counts = new Map();
  for (const value of values) counts.set(value, (counts.get(value) ?? 0) + 1);
  return Object.fromEntries([...counts].sort(([a], [b]) => a.localeCompare(b, 'en')));
}

export function summarize(rows) {
  const groups = new Set(rows.filter(row => !row.identity.isIp).map(row => row.identity.group));
  const ips = new Set(rows.filter(row => row.identity.isIp).map(row => row.identity.group));
  const labels = {};
  for (const label of ['legitimate', 'phishing']) {
    const items = rows.filter(row => row.label === label);
    labels[label] = {
      rows: items.length, sources: frequencies(items.map(row => row.source)),
      verificationMethods: frequencies(items.map(row => row.method)),
      financialConfirmed: items.filter(row => row.financial).length,
      financialUnknown: items.filter(row => !row.financial).length,
      tlds: frequencies(items.map(row => row.facts.tld)),
      features: Object.fromEntries([...featureColumns.map((name, index) =>
        [name, distribution(items.map(row => row.features[index]))]),
        ...['canonicalLength', 'pathPunctuation'].map(name =>
          [name, distribution(items.map(row => row.facts[name]))])])
    };
  }
  function range(key) {
    if (!rows.length) return null;
    let first = Infinity;
    let last = -Infinity;
    for (const row of rows) {
      first = Math.min(first, row[key].time);
      last = Math.max(last, row[key].time);
    }
    return [first, last].map(time => new Date(time).toISOString().slice(0, 10));
  }
  return { rows: rows.length, registrableDomains: groups.size, literalIps: ips.size,
    documentedCampaigns: new Set(rows.map(row => row.campaign).filter(Boolean)).size,
    observationRange: range('observed'), verificationRange: range('verified'), labels: labels };
}
