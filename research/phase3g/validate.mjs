import { readFile, realpath, stat, writeFile, mkdir } from 'node:fs/promises';
import { dirname, basename, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { destinationFor } from '../../extension/reputation.mjs';
import { extractUrl, sha256 } from '../../evaluation/features.mjs';
import { campaignProxy } from '../phase3d/partition.mjs';
import { domainDigest, priorIndex } from '../phase3e/prepare.mjs';
import { privatePath } from './describe.mjs';

const digest = /^[a-f0-9]{64}$/;
const identifier = /^[a-z0-9][a-z0-9-]{0,63}$/;
const splitNames = ['development', 'calibration', 'test'];
const phase3e = new URL('../../docs/experiments/phase3e/summary.json', import.meta.url);
const phase3f = new URL('../../docs/experiments/phase3f/summary.json', import.meta.url);
const validLabel = label => label === 'phishing' || label === 'legitimate';
export const knownId = value => typeof value === 'string' && identifier.test(value);
const object = value => value && typeof value === 'object' && !Array.isArray(value);

async function read(path) {
  return JSON.parse(await readFile(path, 'utf8'));
}

export function observation(value) {
  if (typeof value !== 'string') return null;
  const match = /^(\d{4}-\d{2}-\d{2})(?:T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,3})?(?:Z|[+-](?:0\d|1[0-4]):[0-5]\d))?$/.exec(value);
  if (!match || /[+-]14:(?!00$)/.test(value)) return null;
  const day = new Date(match[1] + 'T00:00:00Z');
  if (!Number.isFinite(+day) || day.toISOString().slice(0, 10) !== match[1]) return null;
  const time = Date.parse(value);
  return Number.isFinite(time) ? { time, precision: value === match[1] ? 'day' : 'timestamp' } : null;
}

export function reference(value) {
  if (typeof value !== 'string' || value.length > 8192) return false;
  if (value.startsWith('sha256:')) return digest.test(value.slice(7));
  try {
    const address = new URL(value);
    return address.protocol === 'https:' && !address.username && !address.password && Boolean(address.hostname);
  } catch {
    return false;
  }
}

function present(value) {
  return typeof value === 'string' && value.trim().length > 0 && value.length <= 250;
}

function collectRegistry(items, section, check, issues) {
  const registry = new Map();
  for (const item of items) {
    if (!object(item) || !knownId(item.id) || registry.has(item.id)) {
      throw new Error('Invalid or duplicate registry identifier');
    }
    const reasons = check(item);
    for (const reason of reasons) issues.push(section + '.' + reason);
    registry.set(item.id, reasons.length === 0);
  }
  return registry;
}

export function policy(manifest) {
  if (!object(manifest) || manifest.schemaVersion !== 1 || !['real', 'synthetic'].includes(manifest.kind) ||
      !Array.isArray(manifest.sources) || !Array.isArray(manifest.targets) ||
      manifest.sources.length > 1000 || manifest.targets.length > 1000 ||
      !digest.test(manifest.recordsSha256 ?? '')) throw new Error('Invalid manifest structure or pin');
  const reviewed = observation(manifest.asOf);
  if (reviewed?.precision !== 'timestamp') throw new Error('Manifest asOf must be an explicit timestamp');
  const issues = [];
  if (!manifest.sources.length) issues.push('sources.empty');
  if (!manifest.targets.length) issues.push('targets.empty');
  const sources = collectRegistry(manifest.sources, 'source', row => {
    const errors = [];
    if (!present(row.publisher)) errors.push('publisher-missing');
    if (!reference(row.provenance)) errors.push('provenance-missing-or-invalid');
    if (!present(row.license)) errors.push('license-missing');
    if (!reference(row.permission?.evidence)) errors.push('permission-evidence-missing-or-invalid');
    if (row.permission?.internalResearch !== true) errors.push('internal-research-not-authorized');
    if (row.permission?.aggregateReporting !== true) errors.push('aggregate-reporting-not-authorized');
    return errors;
  }, issues);
  const targets = collectRegistry(manifest.targets, 'target', row => {
    const errors = [];
    if (!present(row.name)) errors.push('name-missing');
    if (!['financial-institution', 'payment-provider'].includes(row.kind)) errors.push('kind-missing-or-invalid');
    if (row.reviewed !== true || !reference(row.evidence)) errors.push('authority-evidence-missing-or-invalid');
    return errors;
  }, issues);
  return { reviewed: reviewed.time, kind: manifest.kind, issues, sources, targets };
}

export function urlIdentity(url, kind) {
  const parsed = extractUrl(url, kind);
  if (!parsed) return null;
  const original = new URL(url);
  if (original.username || original.password) return null;
  const normalized = new URL(destinationFor(url).key);
  return {
    isIp: parsed.features[2] === 1,
    group: domainDigest(parsed.group),
    family: campaignProxy(parsed.group),
    exact: parsed.keyHash,
    alias: sha256(parsed.host.replace(/^www\./, '') + '\0' + normalized.port + '\0' + normalized.pathname),
  };
}

function mark(row, cfg, prior, index) {
  const errors = new Set();
  const warnings = new Set();
  if (!object(row)) return { index, errors: new Set(['row.invalid-json-or-object']), warnings, identity: null };
  const identity = urlIdentity(row.url, cfg.kind);
  if (!identity) errors.add(typeof row.url !== 'string' ? 'url.missing' : 'url.invalid-or-userinfo');
  if (!validLabel(row.label)) errors.add(row.label == null ? 'label.missing' : 'label.invalid');
  if (!splitNames.includes(row.split)) errors.add(row.split == null ? 'split.missing' : 'split.invalid');
  const date = observation(row.observedAt);
  if (!date || date.time > cfg.reviewed) errors.add(row.observedAt == null ? 'observation.missing' : 'observation.invalid-or-future');
  if (!cfg.sources.get(row.sourceId)) errors.add(row.sourceId == null ? 'provenance.source-missing' : 'provenance.source-unapproved');
  if (!reference(row.sourceRecord)) errors.add('provenance.record-evidence-missing-or-invalid');
  if (!object(row.target)) errors.add('target.missing');
  else if (!cfg.targets.get(row.target.id) || row.target.verified !== true || !reference(row.target.evidence)) {
    errors.add('target.unconfirmed');
  }
  if (!object(row.verification)) errors.add('verification.missing');
  else {
    const verifiedAt = observation(row.verification.verifiedAt);
    if (!cfg.sources.get(row.verification.sourceId)) errors.add('verification.source-missing-or-unapproved');
    if (!reference(row.verification.evidence)) errors.add('verification.evidence-missing-or-invalid');
    if (row.verification.status !== 'verified' || row.verification.label !== row.label) {
      errors.add('verification.label-unconfirmed');
    }
    if (row.verification.verifiedAt == null) warnings.add('verification.timestamp-missing');
    else if (!verifiedAt || verifiedAt.time > cfg.reviewed) errors.add('verification.timestamp-invalid-or-future');
  }
  let campaign = null;
  if (row.campaign == null) {
    if (row.label === 'phishing') warnings.add('campaign.missing');
  } else if (!knownId(row.campaign.namespace) || !knownId(row.campaign.id) || !reference(row.campaign.evidence)) {
    errors.add('campaign.invalid-or-unverified');
  } else {
    campaign = sha256(row.campaign.namespace + '\0' + row.campaign.id);
  }
  if (identity && prior?.domains.has(identity.group)) {
    errors.add(identity.isIp ? 'history.literal-ip-overlap' : 'history.registered-domain-overlap');
  }
  if (identity?.family && prior?.families.has(identity.family)) errors.add('history.lexical-family-overlap');
  return { index, errors, warnings, identity, date, campaign, split: row.split, label: row.label };
}

function groups(rows, key) {
  const result = new Map();
  for (const row of rows) {
    const value = key(row);
    if (!value) continue;
    if (!result.has(value)) result.set(value, []);
    result.get(value).push(row);
  }
  return result.values();
}

function counted(values) {
  const counts = {};
  for (const item of values) counts[item] = (counts[item] ?? 0) + 1;
  return Object.fromEntries(Object.entries(counts).sort(([a], [b]) => a.localeCompare(b, 'en')));
}

export function validate(records, cfg, prior = null) {
  const rows = records.map(({ record, line }) => mark(record, cfg, prior, line));
  for (const values of groups(rows, row => row.identity?.alias)) {
    if (values.length < 2) continue;
    const different = new Set(values.map(row => row.identity.exact)).size > 1;
    const conflict = new Set(values.map(row => row.label).filter(validLabel)).size > 1;
    for (const row of values) {
      row.errors.add(different ? 'duplicate.normalized-variant' : 'duplicate.canonical-url');
      if (conflict) row.errors.add('duplicate.conflicting-label');
    }
  }
  for (const [kind, key] of [
    ['registered-domain', row => row.identity && !row.identity.isIp ? row.identity.group : null],
    ['literal-ip', row => row.identity?.isIp ? row.identity.group : null],
    ['lexical-family', row => row.identity?.family],
    ['campaign', row => row.campaign],
  ]) {
    for (const values of groups(rows, key)) {
      if (values.length < 2) continue;
      const splits = new Set(values.map(row => row.split).filter(s => splitNames.includes(s)));
      for (const row of values) {
        if (splits.size > 1) row.errors.add('split.' + kind + '-overlap');
        else if (kind === 'registered-domain' || kind === 'literal-ip') row.warnings.add('split.correlated-urls');
      }
    }
  }
  const eligible = rows.filter(row => row.errors.size === 0);
  const splits = Object.fromEntries(splitNames.map(split => {
    const selected = eligible.filter(row => row.split === split);
    const domains = new Set(selected.filter(row => !row.identity.isIp).map(row => row.identity.group));
    const ips = new Set(selected.filter(row => row.identity.isIp).map(row => row.identity.group));
    const campaigns = new Set(selected.map(row => row.campaign).filter(Boolean));
    return [split, { eligibleRows: selected.length, registeredDomains: domains.size, literalIps: ips.size,
                     documentedCampaigns: campaigns.size,
                     labels: counted(selected.map(row => row.label)), observationPrecision: counted(selected.map(row => row.date.precision)) }];
  }));
  const report = {
    kind: cfg.kind, checked: rows.length, eligible: eligible.length, rejected: rows.length - eligible.length,
    historicalOverlap: prior ? 'checked' : 'not-checked',
    historicalCampaignCoverage: 'previous-experiments-have-no-comparable-campaign-ids',
    readyForIndependentEvidenceReview: cfg.kind === 'real' && Boolean(prior) &&
      rows.length > 0 && eligible.length === rows.length && cfg.issues.length === 0,
    manifestIssues: counted(cfg.issues),
    errors: counted(rows.flatMap(row => [...row.errors])),
    warnings: counted(rows.flatMap(row => [...row.warnings])),
    splits,
  };
  const issues = rows.filter(row => row.errors.size || row.warnings.size)
    .map(row => ({ line: row.index, errors: [...row.errors].sort(), warnings: [...row.warnings].sort() }));
  return { report, issues };
}

async function addHistory(index, input, published, expected) {
  const content = await readFile(input);
  if (sha256(content) !== expected) throw new Error('Prior cohort checksum differs');
  const domains = new Set();
  const text = content.toString('utf8').trimEnd();
  const rows = text.split('\n');
  const count = Object.values(published.cohorts)
    .reduce((sum, item) => sum + item.support.phishing + item.support.legitimate, 0);
  if (rows.length !== count) throw new Error('Prior cohort counts differ');
  for (const line of rows) {
    const { group, family } = JSON.parse(line);
    if (!digest.test(group) || (family && !digest.test(family))) throw new Error('Invalid historical identity');
    domains.add(group);
    if (family) index.families.add(family);
  }
  for (const group of domains) index.domains.add(group);
}

export async function historical(paths, options) {
  if (!paths.length) return null;
  const [uci, c, d, e, f] = paths.map(privatePath);
  const index = await priorIndex(uci, c, d, options);
  const [earlier, later] = await Promise.all([read(phase3e), read(phase3f)]);
  await addHistory(index, e, earlier, earlier.freeze.projection.sha256);
  await addHistory(index, f, later, later.manifest.numericSha256);
  return index;
}

async function main(arguments_) {
  if (arguments_.length !== 3 && arguments_.length !== 8) throw new Error('Bad validator arguments');
  const [manifestFile, source, output, ...prior] = arguments_;
  const datasetFile = privatePath(await realpath(source));
  const policyPath = privatePath(await realpath(manifestFile));
  const dir = privatePath(resolve(await realpath(dirname(resolve(output))), basename(output)));
  if ((await stat(datasetFile)).size > 64 * 1024 * 1024) throw new Error('Dataset exceeds the byte budget');
  const policyBytes = await readFile(policyPath);
  const manifest = JSON.parse(policyBytes.toString('utf8'));
  const cfg = policy(manifest);
  const content = await readFile(datasetFile);
  if (content.length > 64 * 1024 * 1024 || sha256(content) !== manifest.recordsSha256) throw new Error('Dataset checksum differs');
  const lines = content.toString('utf8').replace(/^\uFEFF/, '').split(/\r?\n/);
  if (!lines.at(-1)) lines.pop();
  if (lines.length > 100000) throw new Error('Dataset exceeds the row budget');
  const rows = lines.map((line, index) => {
    let record = null;
    if (line.length <= 18000) {
      try { record = JSON.parse(line); } catch { /* The issue report identifies the line. */ }
    }
    return { record, line: index + 1 };
  });
  const { report, issues } = validate(rows, cfg, await historical(prior));
  await mkdir(dir);
  const summary = { inputs: { manifestSha256: sha256(policyBytes), recordsSha256: manifest.recordsSha256 }, ...report };
  await writeFile(join(dir, 'summary.json'), JSON.stringify(summary, null, 2) + '\n', { flag: 'wx' });
  await writeFile(join(dir, 'private-issues.json'), JSON.stringify(issues, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  console.log(JSON.stringify({ checked: report.checked, eligible: report.eligible, rejected: report.rejected }));
  if (report.rejected || Object.keys(report.manifestIssues).length) process.exitCode = 2;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    await main(process.argv.slice(2));
  } catch {
    console.error('Validator stopped at a manifest, input digest, historical data, or path check.');
    process.exitCode = 1;
  }
}
