import { mkdir, realpath, writeFile } from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { sha256 } from '../../evaluation/features.mjs';
import { assertOutsideGit } from './run.mjs';

const ref = purpose => 'sha256:' + sha256('synthetic fixture ' + purpose);

export function record(id, slug, label, observedAt, options = {}) {
  const sourceId = options.sourceId ?? 'fixture-a';
  return {
    id, url: 'https://' + slug + '.test/a1/entry%2Fcheck', label, sourceId,
    sourceRecord: ref(id), observedAt,
    verification: { status: 'verified', label, sourceId, method: 'synthetic-fixture',
      verifiedAt: options.verifiedAt ?? observedAt, evidence: ref(id + ' label') },
    ...(options.campaign ? { campaign: { namespace: 'fixture-campaigns', id: options.campaign, evidence: ref(options.campaign) } } : {})
  };
}

export function fixture() {
  const records = [
    record('train-1', 'trainalpha', 'phishing', '2025-01-01'),
    record('train-2', 'trainbeta', 'legitimate', '2025-01-02'),
    record('train-3', 'traingamma', 'legitimate', '2025-01-03'),
    record('val-1', 'validationalpha', 'phishing', '2025-02-01'),
    record('val-2', 'validationbeta', 'legitimate', '2025-02-02'),
    record('test-1', 'finalalpha', 'phishing', '2025-03-01'),
    record('test-2', 'finalbeta', 'legitimate', '2025-03-02'),
    record('test-3', 'finalgamma', 'legitimate', '2025-03-03'),
    record('cross-1', 'sharedalpha', 'phishing', '2025-01-03', { campaign: 'linked' }),
    record('cross-2', 'sharedbeta', 'phishing', '2025-02-04', { campaign: 'linked' }),
    record('cross-3', 'sharedbeta', 'phishing', '2025-02-05'),
    record('missing-date', 'undated-fixture', 'phishing', null),
    record('late-label', 'labeldelay', 'legitimate', '2025-01-07', { verifiedAt: '2025-02-03' })
  ];
  const variant = record('copy-1', 'trainalpha', 'phishing', '2025-01-04', { sourceId: 'fixture-b' });
  variant.url = variant.url.replace('https://', 'http://www.') + '?private-synthetic-marker=fixture#section';
  records.push(variant);
  const ledger = records.map(row => JSON.stringify(row)).join('\n') + '\n';
  const manifest = {
    schemaVersion: 1, kind: 'synthetic', dataset: 'phase5a-synthetic', revision: 'v1', seed: 'phase5a-v1',
    asOf: '2025-04-01T00:00:00Z', validationFrom: '2025-02-01', testFrom: '2025-03-01',
    recordsSha256: sha256(ledger), targets: [],
    sources: ['fixture-a', 'fixture-b'].map(id => ({
      id, publisher: 'ThreatDetection synthetic fixture generator', provenance: ref(id),
      license: 'Original synthetic test fixtures', permission: {
        evidence: ref(id + ' rights'), internalResearch: true, aggregateReporting: true, modelTraining: true
      }
    }))
  };
  return { records, ledger, manifest };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    if (process.argv.length !== 3) throw new Error('Expected one private output directory');
    const directory = resolve(process.argv[2]);
    const parent = await assertOutsideGit(await realpath(dirname(directory)));
    const destination = join(parent, basename(directory));
    const { manifest, ledger } = fixture();
    await mkdir(destination, { mode: 0o700 });
    await writeFile(join(destination, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n',
      { mode: 0o600, flag: 'wx' });
    await writeFile(join(destination, 'ledger.jsonl'), ledger, { mode: 0o600, flag: 'wx' });
    console.log('Private synthetic fixture and its manifest written.');
  } catch {
    console.error('Synthetic fixture creation failed a path or write check.');
    process.exitCode = 1;
  }
}
