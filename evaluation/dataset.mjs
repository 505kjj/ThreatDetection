import { readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { parse } from 'csv-parse';
import { parseSnapshot } from '../extension/reputation.mjs';
import { extractUrl, sha256 } from './features.mjs';
import { timestamp } from './splits.mjs';

const FILE_LIMIT = 128 * 1024 * 1024;
const SNAPSHOT_LIMIT = 3 * 1024 * 1024;
const RECORD_LIMIT = 1_000_000;
const CONFIDENCE = ['low', 'medium', 'high'];
const COHORTS = ['global', 'india-financial', 'unknown'];
const id = value => typeof value === 'string' && /^[a-z0-9][a-z0-9-]{0,63}$/.test(value);
const filename = value => typeof value === 'string' &&
  /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}\.(csv|jsonl|json)$/.test(value);
const digest = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const text = value => typeof value === 'string' && value.trim().length > 0 && value.length <= 1024;
const sourceUrl = value => typeof value === 'string' &&
  /^https:\/\/[a-z0-9.-]+(?::\d+)?(?:\/[^?#\s]*)?$/i.test(value);

export class EvaluationInputError extends Error {}
const reject = message => { throw new EvaluationInputError(message); };

async function fileBytes(file, limit) {
  try {
    const metadata = await stat(file);
    if (metadata.isFile() && metadata.size <= limit) {
      const bytes = await readFile(file);
      if (bytes.length <= limit) return bytes;
    }
  } catch {
    // Do not echo local paths, raw rows or parser errors.
  }
  return reject('A registered input is missing, unreadable, or exceeds its size limit.');
}

const utf8 = bytes => new TextDecoder('utf-8', { fatal: true }).decode(bytes);

export async function readManifest(file) {
  const bytes = await fileBytes(file, 128 * 1024);
  try {
    return validateManifest(JSON.parse(utf8(bytes)));
  } catch (error) {
    if (error instanceof EvaluationInputError) throw error;
    return reject('The manifest is not valid UTF-8 JSON.');
  }
}

function validFile(entry) {
  return filename(entry.file) && digest(entry.sha256);
}

function validSource(source, kind) {
  if (!source || !validFile(source) || !id(source.id) || !id(source.lineage) || source.kind !== kind ||
      timestamp(source.acquiredAt) === null || !text(source.license?.name) || !text(source.attribution)) return false;
  if ((kind === 'real' || source.reference !== undefined) && !sourceUrl(source.reference)) return false;
  if ((kind === 'real' || source.license.url !== undefined) && !sourceUrl(source.license.url)) return false;
  if (source.format === 'phiusiil-csv') {
    return kind === 'real' && source.confidence === 'medium' && timestamp(source.releasedAt) !== null &&
      timestamp(source.releasedAt) <= timestamp(source.acquiredAt);
  }
  return source.format === 'reviewed-jsonl';
}

function validSnapshot(snapshot, kind) {
  return snapshot && validFile(snapshot) && id(snapshot.id) && id(snapshot.lineage) && snapshot.kind === kind &&
    timestamp(snapshot.capturedAt) !== null && text(snapshot.license?.name) && text(snapshot.attribution) &&
    ((kind === 'synthetic' && snapshot.reference === undefined) || sourceUrl(snapshot.reference)) &&
    ((kind === 'synthetic' && snapshot.license.url === undefined) || sourceUrl(snapshot.license.url));
}

export function validateManifest(manifest) {
  if (!manifest || manifest.schemaVersion !== 1 || !id(manifest.dataset) ||
      !['real', 'synthetic'].includes(manifest.kind) || !Array.isArray(manifest.sources) ||
      !Array.isArray(manifest.snapshots) || manifest.sources.length < 1 || manifest.sources.length > 32 ||
      manifest.snapshots.length > 512 || !['medium', 'high'].includes(manifest.minConfidence) ||
      !id(manifest.split?.seed)) return reject('Invalid manifest structure.');
  const trainBefore = timestamp(manifest.split.trainBefore);
  const testFrom = timestamp(manifest.split.testFrom);
  if (trainBefore === null || testFrom === null || trainBefore >= testFrom) return reject('Invalid split cutoffs.');
  if (!manifest.sources.every(source => validSource(source, manifest.kind)) ||
      !manifest.snapshots.every(snapshot => validSnapshot(snapshot, manifest.kind))) {
    return reject('Invalid, mixed, or incomplete input provenance.');
  }
  const entries = [...manifest.sources, ...manifest.snapshots];
  if (new Set(entries.map(entry => entry.id)).size !== entries.length ||
      new Set(entries.map(entry => entry.file.toLowerCase())).size !== entries.length ||
      new Set(entries.map(entry => entry.sha256)).size !== entries.length) {
    return reject('Input IDs, filenames and content digests must be unique.');
  }
  function provenance(entry) {
    const { id, lineage, kind, file, sha256, reference, attribution, license: { name, url } } = entry;
    return { id, lineage, kind, file, sha256, reference, attribution, license: { name, url } };
  }
  const sources = manifest.sources.map(source => ({
    ...provenance(source), format: source.format, acquiredAt: source.acquiredAt,
    releasedAt: source.format === 'phiusiil-csv' ? source.releasedAt : undefined,
    confidence: source.format === 'phiusiil-csv' ? source.confidence : undefined
  }));
  const snapshots = manifest.snapshots.map(snapshot => ({ ...provenance(snapshot), capturedAt: snapshot.capturedAt }));
  return { dataset: manifest.dataset, kind: manifest.kind, minConfidence: manifest.minConfidence, sources, snapshots,
    split: { trainBefore: manifest.split.trainBefore, testFrom: manifest.split.testFrom, seed: manifest.split.seed },
    plan: { trainBefore, testFrom, seed: manifest.split.seed } };
}

async function verifiedBytes(dir, entry, size) {
  const bytes = await fileBytes(join(dir, entry.file), size);
  if (sha256(bytes) !== entry.sha256) reject('An input SHA-256 does not match its manifest.');
  return bytes;
}

async function readPhiusiil(bytes, source, submit) {
  const input = utf8(bytes);
  function* chunks() {
    for (let index = 0; index < input.length; index += 65536) yield input.slice(index, index + 65536);
  }
  const csv = parse({ bom: true, skip_empty_lines: true, max_record_size: 128 * 1024,
    columns(headers) {
      if (headers.filter(field => field === 'URL').length !== 1 ||
          headers.filter(field => field === 'label').length !== 1) reject('Unexpected PhiUSIIL columns.');
      return headers.map(column => column === 'URL' || column === 'label' ? column : false);
    } });
  await pipeline(Readable.from(chunks()), csv, async records => {
    for await (const row of records) {
      submit({ kind: 'real', url: row.URL, observedAt: null, confidence: source.confidence, cohort: 'unknown',
        label: row.label === '0' ? 'phishing' : row.label === '1' ? 'legitimate' : 'unknown' });
    }
  });
}

function readReviewed(bytes, submit) {
  for (const line of utf8(bytes).split(/\r?\n/)) {
    if (!line.trim()) continue;
    if (line.length > 16384) reject('Oversized reviewed input record.');
    let record = null;
    try { record = JSON.parse(line); } catch { /* Count malformed labels without retaining the line. */ }
    submit(record);
  }
}

function labeledUrl(raw, source, kind, minimum) {
  if (!raw || raw.kind !== kind || !['phishing', 'legitimate'].includes(raw.label) ||
      !CONFIDENCE.includes(raw.confidence) || !COHORTS.includes(raw.cohort)) return 'invalidLabel';
  if (CONFIDENCE.indexOf(raw.confidence) < minimum) return 'belowConfidence';
  const observedAt = timestamp(raw.observedAt);
  if ((observedAt === null && source.format !== 'phiusiil-csv') || observedAt > timestamp(source.acquiredAt)) {
    return 'invalidObservationTime';
  }
  const url = extractUrl(raw.url, kind);
  return url ? { ...url, observedAt, label: raw.label, confidence: raw.confidence, cohort: raw.cohort,
    lineages: new Set([source.lineage]) } : 'invalidUrl';
}

function combine(prior, next) {
  for (const lineage of next.lineages) prior.lineages.add(lineage);
  if (prior.label !== next.label || prior.conflict) {
    prior.conflict = true;
    return prior;
  }
  // Keep the earliest actual observation without assigning a date to an undated record.
  const earliest = (next.observedAt ?? Infinity) < (prior.observedAt ?? Infinity) ? next : prior;
  return { ...earliest, lineages: prior.lineages, cohort: prior.cohort === next.cohort ? prior.cohort : 'unknown' };
}

export async function ingest(manifest, dir) {
  const data = new Map();
  const counts = { received: 0, eligibleBeforeDedup: 0, duplicates: 0, conflictingKeys: 0,
    invalidLabel: 0, belowConfidence: 0, invalidObservationTime: 0, invalidUrl: 0 };
  const inputCounts = {};
  for (const source of manifest.sources) {
    const input = { received: 0, phishingLabels: 0, legitimateLabels: 0 };
    inputCounts[source.id] = input;
    const bytes = await verifiedBytes(dir, source, FILE_LIMIT);
    function submit(raw) {
      if (++counts.received > RECORD_LIMIT) reject('Dataset row limit exceeded.');
      input.received++;
      if (raw?.label === 'phishing') input.phishingLabels++;
      if (raw?.label === 'legitimate') input.legitimateLabels++;
      const row = labeledUrl(raw, source, manifest.kind, CONFIDENCE.indexOf(manifest.minConfidence));
      if (typeof row === 'string') {
        counts[row]++;
        return;
      }
      counts.eligibleBeforeDedup++;
      const prior = data.get(row.keyHash);
      if (prior) counts.duplicates++;
      data.set(row.keyHash, prior ? combine(prior, row) : row);
    }
    try {
      if (source.format === 'phiusiil-csv') await readPhiusiil(bytes, source, submit);
      else readReviewed(bytes, submit);
    } catch (error) {
      if (error instanceof EvaluationInputError) throw error;
      reject('A registered dataset is unreadable in its declared format.');
    }
  }
  const rows = [];
  for (const row of data.values()) {
    if (row.conflict) counts.conflictingKeys++;
    else rows.push(row);
  }
  return { rows, counts, inputCounts };
}

export async function loadSnapshots(manifest, dir) {
  const snapshots = [];
  for (const entry of manifest.snapshots) {
    const bytes = await verifiedBytes(dir, entry, SNAPSHOT_LIMIT);
    try {
      const raw = JSON.parse(utf8(bytes));
      const capturedAt = timestamp(entry.capturedAt);
      const generatedAt = timestamp(raw.generatedAt);
      const expiresAt = timestamp(raw.expiresAt);
      const snapshot = parseSnapshot(raw, capturedAt);
      if (!snapshot || generatedAt === null || expiresAt === null || generatedAt > capturedAt) {
        reject('A reputation snapshot was invalid at its recorded capture time.');
      }
      snapshots.push({ capturedAt, expiresAt, lineage: entry.lineage, hosts: snapshot.hosts, hashes: snapshot.paths,
        explicitPaths: new Set(Array.from(snapshot.urlPaths.keys(), sha256)) });
    } catch (error) {
      if (error instanceof EvaluationInputError) throw error;
      reject('A reputation snapshot is not valid UTF-8 JSON.');
    }
  }
  return snapshots.sort((a, b) => a.capturedAt - b.capturedAt);
}
