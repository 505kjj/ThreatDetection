import { readFile, realpath } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { assertOutsideGit } from '../phase5a/run.mjs';
import { brands, rows, targetName } from './cohort.mjs';

const extended = new Set([...brands, 'reserve bank of india', 'rbi', 'yes securities india ltd',
  'yes securities india limited', 'national payments corporation of india']);

export function classifyTarget(label, target) {
  if (label !== 'phish') return null;
  const name = targetName(target);
  if (name === 'sbi securities co ltd') return { status: 'foreignEntity', name };
  return extended.has(name) ? { status: 'candidate', name } : null;
}

export async function review(folder) {
  const manifest = JSON.parse(await readFile(join(folder, 'manifest.json'), 'utf8'));
  if (manifest.side !== 'train' || manifest.revision !== 'eca603e0ecd4f698f8d4d226c088659e72681239' ||
      manifest.shards.length !== 56) throw new Error('Full pinned development projection required');
  const report = { revision: manifest.revision, examined: 0, candidates: 0, independentlySupported: 0,
    targets: {}, foreignEntities: {} };
  for (const [index, spec] of manifest.shards.entries()) {
    if (spec.file !== 'train-' + String(index).padStart(3, '0') + '.jsonl') throw new Error('Unexpected shard');
    for await (const row of rows(join(folder, spec.file), spec.projectedSha256, spec.rows)) {
      report.examined++;
      const match = classifyTarget(row.label, row.target);
      if (!match) continue;
      const counts = match.status === 'candidate' ? report.targets : report.foreignEntities;
      if (match.status === 'candidate') report.candidates++;
      counts[match.name] = (counts[match.name] ?? 0) + 1;
    }
  }
  if (report.examined !== 498255) throw new Error('Incomplete source projection');
  return report;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    if (process.argv.length !== 3 || process.env.THREAT_PHASE3D_GUARDED !== '1') throw new Error('Invalid invocation');
    const folder = await assertOutsideGit(await realpath(process.argv[2]));
    console.log(JSON.stringify(await review(folder)));
  } catch {
    console.error('Financial target review stopped at an integrity, path or guard check.');
    process.exitCode = 1;
  }
}
