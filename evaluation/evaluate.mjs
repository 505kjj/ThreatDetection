import { detectImpersonation } from '../extension/impersonation.mjs';
import { featureColumns, featureVersion } from './features.mjs';
import { splitRecords, windows } from './splits.mjs';

const ratio = (numerator, denominator) => denominator ? numerator / denominator : null;
const baselines = ['reputation', 'impersonation', 'combined'];

function labelCounts(rows) {
  let phishing = 0;
  for (const row of rows) if (row.label === 'phishing') phishing++;
  return { phishing, legitimate: rows.length - phishing };
}

function cohortCounts(rows) {
  const cohorts = {};
  for (const row of rows) {
    const counts = cohorts[row.cohort] ??= { phishing: 0, legitimate: 0 };
    counts[row.label]++;
  }
  return cohorts;
}

function disposition(row, snapshots) {
  if (row.observedAt === null) return { alert: null, cause: 'undated' };
  let overlap = false;
  for (let index = snapshots.length - 1; index >= 0; index--) {
    const snapshot = snapshots[index];
    if (snapshot.capturedAt >= row.observedAt || snapshot.expiresAt <= row.observedAt) continue;
    if (row.lineages.has(snapshot.lineage)) {
      overlap = true;
      continue;
    }
    return { alert: snapshot.hosts.has(row.host) || snapshot.explicitPaths.has(row.keyHash) ||
      snapshot.hashes.has(row.keyHash) };
  }
  return { alert: null, cause: overlap ? 'sameLabelLineage' : 'noPriorFreshSnapshot' };
}

const empty = () => ({ tp: 0, fp: 0, tn: 0, fn: 0, abstainPhishing: 0, abstainLegitimate: 0 });

function tabulate(matrix, label, alert) {
  const positive = label === 'phishing';
  if (alert === null) matrix[positive ? 'abstainPhishing' : 'abstainLegitimate']++;
  else if (positive) matrix[alert ? 'tp' : 'fn']++;
  else matrix[alert ? 'fp' : 'tn']++;
}

function metrics(matrix) {
  const { tp, fp, tn, fn, abstainPhishing, abstainLegitimate } = matrix;
  const scored = tp + fp + tn + fn;
  const total = scored + abstainPhishing + abstainLegitimate;
  return { ...matrix, total, scored, precision: ratio(tp, tp + fp), recall: ratio(tp, tp + fn),
    f1: ratio(2 * tp, 2 * tp + fp + fn), falsePositiveRate: ratio(fp, fp + tn),
    decisionCoverage: ratio(scored, total), phishingAlertCoverage: ratio(tp, tp + fn + abstainPhishing) };
}

export function score(rows, snapshots) {
  const matrices = Object.fromEntries(baselines.map(name => [name, empty()]));
  const unavailable = { undated: 0, sameLabelLineage: 0, noPriorFreshSnapshot: 0 };
  const byHost = new Map();
  let confirmed = 0;
  let advisoryOnly = 0;
  for (const row of rows) {
    if (!byHost.has(row.host)) byHost.set(row.host, detectImpersonation(row.host).length > 0);
    const impersonation = byHost.get(row.host);
    const reputation = disposition(row, snapshots);
    if (reputation.cause) unavailable[reputation.cause]++;
    if (reputation.alert === true) confirmed++;
    else if (impersonation) advisoryOnly++;
    const combined = reputation.alert === true || impersonation ? true : reputation.alert;
    tabulate(matrices.reputation, row.label, reputation.alert);
    tabulate(matrices.impersonation, row.label, impersonation);
    tabulate(matrices.combined, row.label, combined);
  }
  return { ...Object.fromEntries(baselines.map(name => [name, metrics(matrices[name])])),
    reputationUnavailable: unavailable, combinedPolicy: { confirmed, advisoryOnly } };
}

export function evaluate(manifest, data, snapshots) {
  const splits = splitRecords(data.rows, manifest.plan);
  const splitReport = assigned => Object.fromEntries(windows.map(name => [name, {
    ...labelCounts(assigned[name]), groups: new Set(assigned[name].map(row => row.group)).size
  }]));
  return {
    splits,
    report: {
      schemaVersion: 1, dataset: manifest.dataset, kind: manifest.kind,
      provenance: { sources: manifest.sources, snapshots: manifest.snapshots,
        minimumConfidence: manifest.minConfidence, split: manifest.split },
      featureSchema: { version: featureVersion, columns: featureColumns },
      ingestion: { ...data.counts, inputCounts: data.inputCounts, ...labelCounts(data.rows),
        retained: data.rows.length, cohorts: cohortCounts(data.rows) },
      chronologicalDomainDisjoint: { splitCounts: splitReport(splits.chronological),
        withheld: splits.withheld, test: score(splits.chronological.test, snapshots) },
      retrospectiveDomainDisjoint: { splitCounts: splitReport(splits.domainDisjoint),
        test: score(splits.domainDisjoint.test, snapshots) }
    }
  };
}
