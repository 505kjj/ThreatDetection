import { lstat, mkdir, readFile, realpath, stat, writeFile } from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { sha256 } from '../../evaluation/features.mjs';
import { historical } from '../phase3g/validate.mjs';
import { compile, prepare } from './prepare.mjs';

const fileLimit = 64 * 1024 * 1024;
const utf8 = new TextDecoder('utf-8', { fatal: true });
const json = value => JSON.stringify(value, null, 2) + '\n';
const jsonl = values => values.map(value => JSON.stringify(value) + '\n').join('');

export async function assertOutsideGit(path) {
  for (let dir = path; dirname(dir) !== dir; dir = dirname(dir)) {
    try {
      await lstat(join(dir, '.git'));
    } catch (error) {
      if (['ENOENT', 'ENOTDIR'].includes(error.code)) continue;
      throw error;
    }
    throw new Error('Private inputs and outputs must remain outside Git worktrees');
  }
  return path;
}

export async function readBytes(path, limit = fileLimit) {
  const details = await stat(path);
  if (!details.isFile() || details.size > limit) throw new Error('Private input exceeds file limits');
  const bytes = await readFile(path);
  if (bytes.length > limit) throw new Error('Private input exceeds file limits');
  return bytes;
}

async function write(path, bytes) {
  await writeFile(path, bytes, { flag: 'wx', mode: 0o600 });
  return sha256(bytes);
}

export async function run(manifestPath, ledgerPath, output, historyPaths = []) {
  const [manifestFile, ledgerFile, parent, ...prior] = await Promise.all(
    [manifestPath, ledgerPath, dirname(resolve(output)), ...historyPaths]
      .map(async path => assertOutsideGit(await realpath(path))));
  const destination = join(parent, basename(resolve(output)));
  const manifestBytes = await readBytes(manifestFile, 1024 * 1024);
  const manifest = JSON.parse(utf8.decode(manifestBytes));
  const config = compile(manifest);
  const bytes = await readBytes(ledgerFile);
  if (sha256(bytes) !== manifest.recordsSha256) throw new Error('Private records do not match manifest pin');
  const lines = utf8.decode(bytes).split(/\r?\n/);
  if (!lines.at(-1)) lines.pop();
  if (lines.length > 100000) throw new Error('Private ledger exceeds row limits');
  const records = lines.map(line => {
    if (line.length > 18000) return null;
    try { return JSON.parse(line); } catch { return null; }
  });
  const previous = prior.length ? await historical(prior) : null;
  const { report, views } = prepare(records, config, previous);
  await mkdir(destination, { mode: 0o700 });
  const development = join(destination, 'development');
  const final = join(destination, 'final');
  await Promise.all([mkdir(development, { mode: 0o700 }), mkdir(final, { mode: 0o700 })]);

  const artifacts = {};
  for (const [name, view] of Object.entries(views)) {
    const dir = name === 'test' ? final : development;
    const naturalFile = name + '.numeric.jsonl';
    const balancedFile = name + '.balanced-ids.json';
    artifacts[name] = {
      numericSha256: await write(join(dir, naturalFile), jsonl(view.natural)),
      balancedIdsSha256: await write(join(dir, balancedFile), json(view.balanced)),
      rows: view.natural.length, balancedRows: view.balanced.length
    };
  }
  if (config.kind === 'real') {
    const sealed = report.partitions.test;
    artifacts.test.profileSha256 = await write(join(final, 'test.profile.json'), json(sealed));
    const labels = Object.fromEntries(Object.entries(sealed.labels).map(([key, value]) => [key, value.rows]));
    report.partitions.test = { rows: sealed.rows, registrableDomains: sealed.registrableDomains,
      literalIps: sealed.literalIps, documentedCampaigns: sealed.documentedCampaigns,
      balancedRows: sealed.balancedRows, labels, featureDistributions: 'sealed-with-final-test' };
  }

  const inputs = { manifestSha256: sha256(manifestBytes), recordsSha256: manifest.recordsSha256,
    historicalDomainGroups: previous?.domains.size ?? null, historicalLexicalFamilies: previous?.families.size ?? null };
  const freeze = { inputs, dataset: config.dataset, revision: config.revision, kind: config.kind,
    seed: config.seed, testFrom: report.testFrom, validationFrom: report.validationFrom, artifacts,
    finalTestPolicy: 'custody-separated; open only after model selection and thresholds are frozen' };
  await write(join(destination, 'freeze.json'), json(freeze));
  await write(join(destination, 'report.json'), json(report));
  return report;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const args = process.argv.slice(2);
    if (![3, 8].includes(args.length)) throw new Error('Expected manifest, records, output, and optionally five historical paths');
    const report = await run(...args.slice(0, 3), args.slice(3));
    console.log(JSON.stringify({ dataset: report.dataset, kind: report.kind, inputRows: report.inputRows,
      usableRows: Object.values(report.partitions).reduce((sum, split) => sum + split.rows, 0),
      readyForReview: report.readyForReview }));
  } catch {
    console.error('Phase 5A stopped at an input, historical digest, path, or output validation check.');
    process.exitCode = 1;
  }
}
