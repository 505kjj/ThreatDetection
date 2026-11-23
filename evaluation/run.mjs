import { writeFile } from 'node:fs/promises';
import { createWriteStream } from 'node:fs';
import { dirname } from 'node:path';
import { pipeline } from 'node:stream/promises';
import { parseArgs } from 'node:util';
import { EvaluationInputError, ingest, loadSnapshots, readManifest } from './dataset.mjs';
import { evaluate } from './evaluate.mjs';
import { featureVersion } from './features.mjs';
import { windows } from './splits.mjs';

async function main() {
  let args;
  try {
    ({ values: args } = parseArgs({ options: {
      manifest: { type: 'string' }, 'input-dir': { type: 'string' }, report: { type: 'string' },
      features: { type: 'string' }
    } }));
  } catch {
    throw new EvaluationInputError('Invalid arguments.');
  }
  if (!args.manifest) throw new EvaluationInputError('Use --manifest with a pinned evaluation manifest.');
  const manifest = await readManifest(args.manifest);
  const inputDir = args['input-dir'] ?? dirname(args.manifest);
  const data = await ingest(manifest, inputDir);
  const snapshots = await loadSnapshots(manifest, inputDir);
  const { splits, report } = evaluate(manifest, data, snapshots);
  if (args.features) {
    if (!windows.some(window => splits.chronological[window].length)) {
      throw new EvaluationInputError('Feature export requires dated, chronologically eligible records.');
    }
    function* vectors() {
      for (const split of windows) {
        for (const { label, features } of splits.chronological[split]) {
          yield JSON.stringify({ featureVersion, split, label, values: features }) + '\n';
        }
      }
    }
    await pipeline(vectors(), createWriteStream(args.features, { flags: 'wx', mode: 0o600 }));
  }
  const json = JSON.stringify(report, null, 2) + '\n';
  if (args.report) await writeFile(args.report, json, { flag: 'wx' });
  else process.stdout.write(json);
}

main().catch(error => {
  process.stderr.write((error instanceof EvaluationInputError ? error.message : 'Evaluation failed while processing a local artifact.') + '\n');
  process.exitCode = 1;
});
