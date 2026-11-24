import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { readFile, realpath, writeFile } from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { pathToFileURL } from 'node:url';
import { featureColumns, featureVersion, sha256 } from '../../evaluation/features.mjs';
import { assertOutsideGit } from './run.mjs';
import { distribution } from './profile.mjs';

const digest = /^[a-f0-9]{64}$/;
const numeric = /^\d+$/;
const read = async path => JSON.parse(await readFile(path, 'utf8'));
const published = name => new URL('../../docs/experiments/' + name, import.meta.url);
const pathLength = featureColumns.indexOf('path_length');
const hostnameLength = featureColumns.indexOf('hostname_length');

function emptyClass() {
  return { rows: 0, domainGroups: new Set(), features: featureColumns.map(() => []), urlLength: [] };
}

export async function previousPartition(path, spec, extended) {
  const groups = new Set();
  const dns = new Set();
  const ips = new Set();
  const classes = { '0': emptyClass(), '1': emptyClass() };
  const hash = createHash('sha256');
  const stream = createReadStream(path);
  stream.on('data', chunk => hash.update(chunk));
  for await (const line of createInterface({ input: stream, crlfDelay: Infinity })) {
    const fields = line.split('\t');
    const [label, group] = fields;
    const record = classes[label];
    const values = fields.slice(extended ? 4 : 2);
    if (!['0', '1'].includes(label) || !digest.test(group) || values.length !== featureColumns.length ||
        values.some(value => !numeric.test(value) || !Number.isSafeInteger(Number(value))) ||
        (extended && ((fields[2] && !digest.test(fields[2])) || !['0', '1'].includes(fields[3])))) {
      throw new Error('Unexpected numerical development export format');
    }
    const x = values.map(Number);
    record.rows++;
    groups.add(group);
    (x[2] === 1 ? ips : dns).add(group);
    record.domainGroups.add(group);
    x.forEach((value, index) => record.features[index].push(value));
    if (x[1] === 0 && x[2] === 0) {
      // The projection preserves all URL lengths for default-port DNS rows.
      record.urlLength.push((x[0] === 1 ? 8 : 7) + x[hostnameLength] + Math.max(1, x[pathLength]));
    }
  }
  const sha = hash.digest('hex');
  if (sha !== spec.sha256 || classes[1].rows !== spec.phishing ||
      classes[0].rows !== spec.legitimate || groups.size !== spec.groups) throw new Error('Development partition pin differs');

  function summarize(record) {
    return { rows: record.rows, distinctGroupingKeys: record.domainGroups.size,
      lexical: Object.fromEntries(featureColumns.map((name, i) => [name, distribution(record.features[i])])),
      canonicalUrlLengthDefaultPortDnsOnly: distribution(record.urlLength) };
  }

  return { groups, profile: { sha256: sha, rows: spec.phishing + spec.legitimate,
    distinctGroupingKeys: groups.size,
    registrableDomains: dns.size, literalIpAddresses: ips.size,
    observationRange: spec.firstDay ? [spec.firstDay, spec.lastDay] : null,
    labels: { phishing: summarize(classes[1]), legitimate: summarize(classes[0]) },
    tlds: 'not-preserved-in-numeric-input', pathPunctuation: 'not-preserved-in-numeric-input',
    financialLabels: 'not-verified', verificationTimestamps: 'not-preserved', documentedCampaigns: 'not-preserved' } };
}

export async function compare(uciDev, phreshDev) {
  const [uci, phresh, archive] = await Promise.all([read(published('phiusiil/development-report.json')),
    read(published('phase3d/summary.json')), read(published('phase3g/analysis.json'))]);
  for (const schema of [uci.dataset, phresh.dataset]) {
    if (schema.featureVersion !== featureVersion || JSON.stringify(schema.featureColumns) !== JSON.stringify(featureColumns)) {
      throw new Error('Published feature schema differs');
    }
  }
  const specs = [
    ['phiusiil-train', uciDev, 'train', uci.trainingPartition, false],
    ['phiusiil-validation', uciDev, 'validation', uci.calibrationPartition, false],
    ['phreshphish-train', phreshDev, 'train', phresh.dataset.partitions.train, true],
    ['phreshphish-validation', phreshDev, 'validation', phresh.dataset.partitions.validation, true],
  ];
  const profiles = {};
  const seen = new Set();
  for (const [key, folder, name, spec, extended] of specs) {
    const { groups, profile } = await previousPartition(join(folder, name + '.tsv'), spec, extended);
    for (const group of groups) {
      if (seen.has(group)) throw new Error('Development partitions share a grouping key');
      seen.add(group);
    }
    profiles[key] = profile;
  }
  const forest = archive.candidates['phresh-20000-path-forest'];
  const archiveBytes = await readFile(published('phase3g/analysis.json'));
  return {
    purpose: 'descriptive-reuse-of-pinned-development-data',
    featureVersion, featureColumns, combinedDistinctDevelopmentGroups: seen.size, profiles,
    historicalReference: {
      handling: 'published-aggregate-only; no raw or numeric test rows used for this comparison',
      phase3gAnalysisSha256: sha256(archiveBytes),
      generalPhishingRows: archive.input.archiveRows,
      archiveDistributions: archive.archiveFeatureDistributions,
      forestTrainingPositive: archive.developmentPositiveDistributions.forestTrainingPositive,
      archiveVsForestTrainingDistances: archive.featureKsDistancesFromArchive.forestTrainingPositive,
      frozenForestScores: forest.scoreDistribution
    }
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const [uci, phresh, output] = process.argv.slice(2);
    if (process.argv.length !== 5) throw new Error('Expected two development roots and a report path');
    const roots = await Promise.all([uci, phresh, dirname(resolve(output))]
      .map(async path => assertOutsideGit(await realpath(path))));
    const result = await compare(...roots.slice(0, 2));
    await writeFile(join(roots[2], basename(output)), JSON.stringify(result, null, 2) + '\n',
      { flag: 'wx', mode: 0o600 });
    console.log(JSON.stringify({ profiles: Object.keys(result.profiles),
      distinctDevelopmentGroups: result.combinedDistinctDevelopmentGroups }));
  } catch (error) {
    console.error('Could not verify the development projections or write the private report.');
    process.exitCode = 1;
  }
}
