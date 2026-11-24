import { createHash } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import { readFile, realpath } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { pathToFileURL } from 'node:url';
import { extractUrl, sha256 } from '../../evaluation/features.mjs';
import { domainPartition } from '../../evaluation/splits.mjs';
import { historical, urlIdentity } from '../phase3g/validate.mjs';
import { verifiedGroups } from '../phase3d/partition.mjs';
import { assertOutsideGit } from '../phase5a/run.mjs';

const source = JSON.parse(await readFile(new URL('../../evaluation/manifests/phiusiil-uci-967.json',
  import.meta.url), 'utf8')).sources[0];
const { parse } = createRequire(new URL('../../evaluation/package.json', import.meta.url))('csv-parse');
const hashPattern = /^[a-f0-9]{64}$/;
const line = value => JSON.stringify(value) + '\n';

async function output(path) {
  await assertOutsideGit(await realpath(dirname(resolve(path))));
  return createWriteStream(path, { flags: 'wx', mode: 0o600 });
}

async function* verifiedUci(input) {
  const digest = createHash('sha256');
  for await (const bytes of input) {
    digest.update(bytes);
    yield bytes;
  }
  if (digest.digest('hex') !== source.sha256) throw new Error('UCI input checksum differs');
}

async function reconstructUci(directory) {
  const parts = { train: new Map(), validation: new Map() };
  const prior = JSON.parse(await readFile(join(directory, 'manifest.json'), 'utf8'));
  if (prior.sourceSha256 !== source.sha256 || prior.splitSeed !== 'phase3a-v1') {
    throw new Error('UCI development manifest differs');
  }
  let ordinal = 0;
  await pipeline(Readable.from(verifiedUci(process.stdin)), parse({
    bom: true, skip_empty_lines: true, columns: true, max_record_size: 128 * 1024
  }), async records => {
    for await (const row of records) {
      const index = ordinal++;
      const parsed = extractUrl(row.URL, 'real');
      if (!parsed) continue;
      const partition = domainPartition(parsed.group, 'phase3a-v1');
      if (partition === 'test') continue;
      const label = row.label === '0' ? 1 : row.label === '1' ? 0 : null;
      if (label === null) continue;
      const previous = parts[partition].get(parsed.keyHash);
      if (previous) {
        if (previous.label !== label) previous.conflict = true;
        continue;
      }
      parts[partition].set(parsed.keyHash, { sourceId: row.FILENAME, ordinal: index, url: row.URL,
        label, partition, group: sha256('phase3b-group\0' + parsed.group), x: parsed.features });
    }
  });
  for (const [name, members] of Object.entries(parts)) {
    const digest = createHash('sha256');
    let count = 0;
    for (const row of members.values()) {
      if (row.conflict) continue;
      count++;
      digest.update([row.label, row.group, ...row.x].join('\t') + '\n');
    }
    if (digest.digest('hex') !== prior[name].sha256 || count !== prior[name].phishing + prior[name].legitimate) {
      throw new Error('Original UCI development representation fails exact replay');
    }
  }
  return parts;
}

async function exportUci(previous, destination) {
  const parts = await reconstructUci(previous);
  await pipeline(Readable.from((function* () {
    for (const members of Object.values(parts)) {
      for (const row of members.values()) if (!row.conflict) yield line(row);
    }
  })()), await output(destination));
  console.log(JSON.stringify(Object.fromEntries(Object.entries(parts)
    .map(([name, members]) => [name, [...members.values()].filter(row => !row.conflict).length]))));
}

async function exportPhresh(destination) {
  await pipeline(Readable.from((async function* () {
    for await (const text of byteLines(process.stdin)) {
      const row = JSON.parse(text);
      if (Object.keys(row).sort().join() !== 'sha256,url') {
        throw new Error('Unexpected custody input schema');
      }
      const { group, family, exact, alias } = urlIdentity(row.url, 'real') ?? {};
      const id = hashPattern.test(row.sha256) ? row.sha256 : undefined;
      yield line({ id, group, family: family || undefined, exact, alias });
    }
  })()), await output(destination));
}

export async function* byteLines(input) {
  const decoder = new TextDecoder('utf-8', { fatal: true });
  let pending = '';
  for await (const bytes of input) {
    const lines = (pending + decoder.decode(bytes, { stream: true })).split('\n');
    pending = lines.pop();
    yield* lines;
  }
  if (pending + decoder.decode()) throw new Error('Incomplete projection line');
}

async function exportHistory(destination, paths) {
  if (paths.length !== 5) throw new Error('Historical paths are required');
  const sets = await historical(paths, { evaluationOnly: true });
  await pipeline(Readable.from((function* () {
    for (const group of sets.domains) yield line({ group });
    for (const family of sets.families) yield line({ family });
  })()), await output(destination));
}

async function exportReplay(destination, [uci, phase3c, phase3d]) {
  if (!phase3d) throw new Error('Replay requires three prior cohort paths');
  const c = JSON.parse(await readFile(new URL('../../docs/experiments/phase3c/research.json', import.meta.url), 'utf8'));
  const d = JSON.parse(await readFile(new URL('../../docs/experiments/phase3d/summary.json', import.meta.url), 'utf8'));
  const ignored = new Set();
  for (const name of ['development', 'holdout']) {
    const folder = join(uci, name);
    const manifest = JSON.parse(await readFile(join(folder, 'manifest.json'), 'utf8'));
    if (manifest.sourceSha256 !== source.sha256) throw new Error('UCI source checksum differs');
    for (const key of name === 'development' ? ['train', 'validation'] : ['test']) {
      for (const digest of await verifiedGroups(join(folder, key + '.tsv'), manifest[key])) ignored.add(digest);
    }
  }
  for (const [name, spec] of Object.entries(c.source.partitions)) {
    for (const digest of await verifiedGroups(join(phase3c, name + '.tsv'), spec)) ignored.add(digest);
  }
  const families = new Set();
  const groups = await verifiedGroups(join(phase3d, 'test.tsv'), d.dataset.partitions.test, families);
  await pipeline(Readable.from((function* () {
    yield line({ firstTest: d.dataset.partitions.test.firstDay });
    for (const digest of ignored) yield line({ ignore: digest });
    for (const group of groups) yield line({ group });
    for (const family of families) yield line({ family });
  })()), await output(destination));
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const [mode, destination, ...args] = process.argv.slice(2);
    if (process.env.THREAT_PHASE3D_GUARDED !== '1') throw new Error('Missing resource guard');
    if (mode === 'phresh') await exportPhresh(destination);
    else if (mode === 'history' || mode === 'replay') {
      const paths = await Promise.all(args.map(async path => assertOutsideGit(await realpath(path))));
      if (mode === 'history') await exportHistory(destination, paths);
      else await exportReplay(destination, paths);
    }
    else if (mode === 'uci' && args.length === 1) {
      await exportUci(await assertOutsideGit(await realpath(args[0])), destination);
    } else throw new Error('Unknown custody mode');
  } catch (error) {
    const code = /^[A-Z_]+$/.test(error.code ?? '') ? ' ' + error.code : '';
    console.error('Custody export failed a schema, integrity, private path, or resource guard check (' + error.name + code + ').');
    process.exitCode = 1;
  }
}
