import { extractUrl, sha256, featureVersion, featureColumns } from '../../evaluation/features.mjs';
import { observation, policy, urlIdentity, reference, knownId } from '../phase3g/validate.mjs';
import { descriptors } from '../phase3g/describe.mjs';
import { summarize } from './profile.mjs';

const DAY = 86400000;
const partitions = ['train', 'validation', 'test'];
const methods = new Set(['community-verified', 'independently-reviewed', 'official-control', 'synthetic-fixture']);
const count = (object, key) => { object[key] = (object[key] ?? 0) + 1; };

export function compile(manifest) {
  const base = policy(manifest);
  const boundaries = [manifest.validationFrom, manifest.testFrom].map(observation);
  if (!boundaries.every(date => date?.precision === 'day') || boundaries[0].time >= boundaries[1].time ||
      boundaries[1].time > base.reviewed || !knownId(manifest.dataset) ||
      !knownId(manifest.revision) || !knownId(manifest.seed)) throw new Error('Invalid frozen split policy');
  const rights = new Map(manifest.sources.map(source => [source.id, source.permission?.modelTraining === true]));
  // General phishing records may legitimately have no financial target.  The
  // row-level checks still record missing/unconfirmed targets; an empty target
  // registry is therefore not a manifest failure by itself.
  return { ...base, issues: base.issues.filter(issue => issue !== 'targets.empty'),
    rights, dataset: manifest.dataset, revision: manifest.revision, seed: manifest.seed,
    cutoffs: boundaries.map(date => date.time) };
}

const day = time => Math.floor(time / DAY);
const utcDay = time => new Date(time).toISOString().slice(0, 10);
const validObject = value => value && typeof value === 'object' && !Array.isArray(value);

function project(row, cfg, history, stats) {
  if (!validObject(row) || !knownId(row.id)) return 'invalid-record';
  const identity = urlIdentity(row.url, cfg.kind);
  if (!identity) return 'invalid-url-or-userinfo';
  if (!['legitimate', 'phishing'].includes(row.label)) return 'invalid-label';
  if (!cfg.sources.get(row.sourceId) || !reference(row.sourceRecord)) return 'source-or-permission-unverified';

  const observed = observation(row.observedAt);
  const review = row.verification;
  const verified = observation(review?.verifiedAt);
  if (!observed) count(stats.metadata, row.observedAt == null ? 'observation-missing' : 'observation-invalid');
  if (!verified) count(stats.metadata, review?.verifiedAt == null ? 'verification-time-missing' : 'verification-time-invalid');
  if (!observed || !verified) return 'required-dates-missing-or-invalid';
  if (observed.time > cfg.reviewed || verified.time > cfg.reviewed) return 'date-after-freeze';
  const chronological = observed.precision === 'day' || verified.precision === 'day'
    ? day(verified.time) >= day(observed.time) : verified.time >= observed.time;
  if (!chronological) return 'verification-before-observation';
  if (!cfg.sources.get(review.sourceId) || review.status !== 'verified' || review.label !== row.label ||
      !reference(review.evidence) || !methods.has(review.method) ||
      (cfg.kind === 'synthetic') !== (review.method === 'synthetic-fixture') ||
      (review.method === 'official-control' && row.label !== 'legitimate')) return 'label-evidence-unverified';

  const [validation, test] = cfg.cutoffs;
  const position = observed.time < validation ? 0 : observed.time < test ? 1 : 2;
  const verificationBeforeNextWindow = position === 2 || verified.time < cfg.cutoffs[position];
  const trainingRights = cfg.rights.get(row.sourceId) && cfg.rights.get(review.sourceId);

  const target = row.target;
  const corroborated = target?.verified === true && cfg.targets.get(target.id) && reference(target.evidence) &&
    cfg.sources.get(target.reviewSourceId) && target.reviewSourceId !== row.sourceId;
  if (!target) count(stats.metadata, 'financial-target-missing');
  else if (!corroborated) count(stats.metadata, 'financial-target-unconfirmed');

  let campaign = '';
  if (row.campaign == null) count(stats.metadata, 'campaign-missing');
  else if (!knownId(row.campaign.namespace) || !knownId(row.campaign.id) || !reference(row.campaign.evidence)) {
    return 'campaign-evidence-invalid';
  } else {
    campaign = sha256('phase5a-campaign\0' + row.campaign.namespace + '\0' + row.campaign.id);
  }
  const parsed = extractUrl(row.url, cfg.kind);
  const overlaps = history?.domains.has(identity.group) || identity.family && history?.families.has(identity.family);
  return { stableId: row.sourceId + ':' + row.id, label: row.label, source: row.sourceId, method: review.method,
    identity, campaign, observed, verified, partition: partitions[position], financial: !!corroborated,
    features: parsed.features, facts: descriptors(row.url),
    blocked: overlaps ? 'historical-overlap'
      : !verificationBeforeNextWindow ? 'verification-after-partition-cutoff'
        : position === 0 && !trainingRights ? 'training-rights-unconfirmed' : null };
}

const order = (a, b) => a.observed.time - b.observed.time || a.verified.time - b.verified.time ||
  a.stableId.localeCompare(b.stableId, 'en');

export function components(candidates) {
  const parent = candidates.map((_, index) => index);
  const owners = new Map();
  function root(index) {
    while (parent[index] !== index) {
      parent[index] = parent[parent[index]];
      index = parent[index];
    }
    return index;
  }
  for (const [index, row] of candidates.entries()) {
    for (const [kind, value] of Object.entries({ domain: row.identity.group, alias: row.identity.alias,
      family: row.identity.family, campaign: row.campaign })) {
      if (!value) continue;
      const key = kind + ':' + value;
      if (owners.has(key)) parent[root(index)] = root(owners.get(key));
      else owners.set(key, index);
    }
  }
  const groups = new Map();
  candidates.forEach((row, index) => {
    const id = root(index);
    if (!groups.has(id)) groups.set(id, []);
    groups.get(id).push(row);
  });
  return groups.values();
}

function deduplicate(rows, counters) {
  const aliases = new Map();
  for (const row of rows) {
    const key = row.identity.alias;
    if (!aliases.has(key)) aliases.set(key, []);
    aliases.get(key).push(row);
  }
  const result = [];
  for (const entries of aliases.values()) {
    if (new Set(entries.map(row => row.label)).size > 1) {
      for (const row of entries) count(counters, 'conflicting-labels');
      continue;
    }
    entries.sort(order);
    const representative = entries[0];
    result.push(representative);
    for (const variant of entries.slice(1)) {
      count(counters, representative.identity.exact === variant.identity.exact ? 'exact-duplicate' : 'normalized-variant');
    }
  }
  return result;
}

function balanced(rows, seed) {
  const rank = row => sha256(seed + '\0' + row.stableId);
  const classes = ['phishing', 'legitimate'].map(label =>
    rows.filter(row => row.label === label).map(row => [rank(row), row]).sort(([a], [b]) => a.localeCompare(b)));
  const size = Math.min(...classes.map(values => values.length));
  return classes.flatMap(values => values.slice(0, size).map(([, row]) => row));
}

function payload(row, cfg) {
  return { id: sha256(cfg.seed + '\0' + row.stableId),
    domainGroup: row.identity.group, lexicalFamily: row.identity.family || null, campaign: row.campaign || null,
    label: row.label, observationDay: utcDay(row.observed.time), verificationDay: utcDay(row.verified.time),
    observationPrecision: row.observed.precision, verificationPrecision: row.verified.precision,
    source: row.source, financial: row.financial, x: row.features };
}

export function prepare(records, cfg, history = null) {
  if (cfg.kind === 'real' && !history) throw new Error('Real prospective splits require verified historical exclusion');
  const stats = { inputRows: records.length, excluded: {}, metadata: {} };
  const seen = new Set();
  const candidates = [];
  for (const record of records) {
    const result = project(record, cfg, history, stats);
    if (typeof result === 'string') count(stats.excluded, result);
    else {
      if (seen.has(result.stableId)) throw new Error('Duplicate source record identity');
      seen.add(result.stableId);
      candidates.push(result);
    }
  }
  const selected = Object.fromEntries(partitions.map(name => [name, []]));
  for (const group of components(candidates)) {
    const historical = group.some(row => row.blocked === 'historical-overlap');
    const spansWindows = new Set(group.map(row => row.partition)).size > 1;
    if (historical || spansWindows) {
      for (const row of group) count(stats.excluded, historical ? 'historical-component-overlap' : 'cross-window-component');
      continue;
    }
    const unique = deduplicate(group, stats.excluded);
    for (const row of unique) {
      if (row.blocked) count(stats.excluded, row.blocked);
      else selected[row.partition].push(row);
    }
  }
  const views = {};
  const report = { dataset: cfg.dataset, revision: cfg.revision, kind: cfg.kind,
    featureVersion, featureColumns, historyChecked: !!history, validationFrom: utcDay(cfg.cutoffs[0]),
    testFrom: utcDay(cfg.cutoffs[1]), manifestIssues: cfg.issues, ...stats, partitions: {} };
  for (const name of partitions) {
    const rows = selected[name].sort(order);
    const balancedRows = balanced(rows, cfg.seed + ':' + name);
    views[name] = { natural: rows.map(row => payload(row, cfg)),
      balanced: balancedRows.map(row => payload(row, cfg).id) };
    report.partitions[name] = { ...summarize(rows), balancedRows: balancedRows.length };
  }
  report.financialEvaluation = cfg.kind === 'real' &&
    selected.test.some(row => row.financial && row.label === 'phishing') &&
    selected.test.some(row => row.financial && row.label === 'legitimate') ? 'has-both-classes-for-review' : 'not-established';
  report.readyForReview = cfg.kind === 'real' && !cfg.issues.length &&
    partitions.every(name => report.partitions[name].balancedRows > 0);
  return { report, views };
}
