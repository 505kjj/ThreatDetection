import { createReadStream } from 'node:fs';
import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { join, relative, resolve, sep, isAbsolute } from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { destinationFor } from '../../extension/reputation.mjs';
import { parse } from '../../extension/vendor/tldts.mjs';
import { project } from '../phase3f/prepare.mjs';

const repo = fileURLToPath(new URL('../../', import.meta.url));
const frozenReport = new URL('../../docs/experiments/phase3f/summary.json', import.meta.url);

export async function fileDigest(input) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(input)) hash.update(chunk);
  return hash.digest('hex');
}

export function privatePath(input) {
  const path = resolve(input);
  const rel = relative(repo, path);
  if (!isAbsolute(rel) && !rel.startsWith('..' + sep)) throw new Error('Use an off-repo private path');
  return path;
}

export function descriptors(raw) {
  const destination = destinationFor(raw);
  const address = new URL(destination.key);
  const host = parse(destination.host, { allowPrivateDomains: false, extractHostname: false });
  const lastLabel = host.isIcann ? host.publicSuffix?.split('.').at(-1) : '';
  const tld = host.isIp ? 'ip-address' : /^[a-z0-9-]{2,24}$/.test(lastLabel ?? '') ? lastLabel : 'other';
  const pathPunctuation = (address.pathname.replace(/%[0-9a-f]{2}/gi, '').match(/[^a-z0-9/]/gi) ?? []).length;
  return { canonicalLength: address.href.length, pathPunctuation, tld };
}

export async function collect(cohort, archiveLedger) {
  const manifest = JSON.parse(await readFile(join(cohort, 'manifest.json'), 'utf8'));
  const frozen = JSON.parse(await readFile(frozenReport, 'utf8'));
  const numeric = join(cohort, 'numeric.jsonl');
  if (await fileDigest(numeric) !== manifest.numericSha256 || manifest.numericSha256 !== frozen.manifest.numericSha256 ||
      await fileDigest(archiveLedger) !== frozen.manifest.archiveLedgerSha256) {
    throw new Error('Frozen Phase 3F cohort or source ledger differs');
  }
  const rows = (await readFile(numeric, 'utf8')).trimEnd().split('\n').map(JSON.parse)
    .filter(row => row.cohort === 'general-transfer');
  const expected = new Map(rows.map(row => [row.id, row]));
  const selected = new Map();
  if (expected.size !== rows.length) throw new Error('Unexpected duplicate evidence identifiers');
  for await (const line of createInterface({ input: createReadStream(archiveLedger) })) {
    const source = JSON.parse(line);
    const match = expected.get(source.id);
    if (!match) continue;
    const projected = project(source);
    if (!projected || projected.group !== match.group || projected.family !== match.family ||
        projected.date !== match.date || projected.y !== match.y || projected.source !== match.source ||
        JSON.stringify(projected.x) !== JSON.stringify(match.x)) continue;
    const facts = descriptors(source.url);
    if (selected.has(source.id) && JSON.stringify(selected.get(source.id)) !== JSON.stringify(facts)) {
      throw new Error('More than one raw record matches a frozen row');
    }
    selected.set(source.id, facts);
  }
  if (selected.size !== expected.size) throw new Error('Frozen URL feature projection did not reproduce');
  return rows.map(row => ({ id: row.id, ...selected.get(row.id) }));
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    if (process.env.THREAT_PHASE3D_GUARDED !== '1' || process.argv.length !== 5) throw new Error('Bad arguments');
    const [cohort, archive, output] = process.argv.slice(2).map(privatePath);
    const rows = await collect(cohort, archive);
    await writeFile(output, rows.map(row => JSON.stringify(row)).join('\n') + '\n', { flag: 'wx', mode: 0o600 });
    console.log('Reprojected ' + rows.length + ' archived rows to their frozen feature vectors.');
  } catch {
    console.error('Archive descriptor generation failed an input, identity or privacy check.');
    process.exitCode = 1;
  }
}
