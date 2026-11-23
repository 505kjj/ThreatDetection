import { createHash } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import { mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { pipeline } from 'node:stream/promises';
import { parseArgs } from 'node:util';
import { ingest, readManifest } from '../evaluation/dataset.mjs';
import { featureColumns, featureVersion, sha256 } from '../evaluation/features.mjs';
import { splitRecords, windows } from '../evaluation/splits.mjs';

const local = path => new URL(path, import.meta.url);
const repository = fileURLToPath(local('../'));

async function writePartition(directory, name, rows, expected) {
  const hash = createHash('sha256');
  function* lines() {
    for (const row of rows) {
      const group = sha256('phase3b-group\0' + row.group);
      const line = [row.label === 'phishing' ? 1 : 0, group, ...row.features].join('\t') + '\n';
      hash.update(line);
      yield line;
    }
  }
  const file = name + '.tsv';
  await pipeline(lines(), createWriteStream(join(directory, file), { flags: 'wx', mode: 0o600 }));
  return { file, sha256: hash.digest('hex'), ...expected };
}

async function prepare() {
  const { values } = parseArgs({ options: {
    'input-dir': { type: 'string' }, 'output-dir': { type: 'string' }
  } });
  if (!values['input-dir'] || !values['output-dir']) throw new Error('Both directories are required.');
  const output = resolve(values['output-dir']);
  const outputParent = await realpath(dirname(output));
  const repo = await realpath(repository);
  const relation = relative(repo, outputParent);
  if (!relation || (relation !== '..' && !relation.startsWith('..' + sep) && !isAbsolute(relation))) {
    throw new Error('Write the private dataset outside this Git worktree.');
  }
  const manifestFile = local('../evaluation/manifests/phiusiil-uci-967.json');
  const baselineFile = local('../evaluation/reports/phiusiil-uci-967.json');
  const manifest = await readManifest(manifestFile);
  const baselineBytes = await readFile(baselineFile);
  const baseline = JSON.parse(baselineBytes);
  const { rows, inputCounts } = await ingest(manifest, values['input-dir']);
  const { domainDisjoint } = splitRecords(rows, manifest.plan);
  const source = manifest.sources[0];
  const input = inputCounts[source.id];
  if (input.phishingLabels !== 100945 || input.legitimateLabels !== 134850 ||
      rows.length !== baseline.ingestion.retained) throw new Error('Input labels or row count changed.');
  const expected = baseline.retrospectiveDomainDisjoint.splitCounts;
  const assigned = new Map();
  for (const name of windows) {
    const records = domainDisjoint[name];
    let positives = 0;
    const groups = new Set();
    for (const row of records) {
      positives += Number(row.label === 'phishing');
      groups.add(row.group);
      if (assigned.has(row.group) && assigned.get(row.group) !== name) throw new Error('Domain overlap.');
      assigned.set(row.group, name);
    }
    if (positives !== expected[name].phishing || records.length - positives !== expected[name].legitimate ||
        groups.size !== expected[name].groups) throw new Error('Phase 3A split changed.');
  }
  await mkdir(output);
  const development = join(output, 'development');
  const holdout = join(output, 'holdout');
  await mkdir(development);
  await mkdir(holdout);
  const identity = { dataset: manifest.dataset, sourceSha256: source.sha256, splitSeed: manifest.plan.seed,
    referenceReportSha256: sha256(baselineBytes), featureVersion, featureColumns };
  const train = await writePartition(development, 'train', domainDisjoint.train, expected.train);
  const validation = await writePartition(development, 'validation', domainDisjoint.validation, expected.validation);
  const test = await writePartition(holdout, 'test', domainDisjoint.test, expected.test);
  await writeFile(join(development, 'manifest.json'), JSON.stringify({ ...identity, train, validation }, null, 2) + '\n',
    { flag: 'wx', mode: 0o600 });
  await writeFile(join(holdout, 'manifest.json'), JSON.stringify({ ...identity, test }, null, 2) + '\n',
    { flag: 'wx', mode: 0o600 });
  process.stdout.write(JSON.stringify({ ...identity, train, validation, holdoutSealed: true }) + '\n');
}

prepare().catch(() => {
  process.stderr.write('Cannot prepare the pinned Phase 3A dataset. Check paths, checksums, or split integrity.\n');
  process.exitCode = 1;
});
