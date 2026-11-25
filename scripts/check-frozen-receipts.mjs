import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { resolve, relative, isAbsolute } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const experiments = resolve(process.argv[2] ?? '');
if (!process.argv[2]) throw new Error('Provide the private experiments directory');
const registry = JSON.parse(readFileSync(resolve(root, 'docs/experiments/phase5g/frozen-models.json')));
const hash = data => createHash('sha256').update(data).digest('hex');
const gitHash = (revision, name) => hash(Buffer.from(execFileSync('git', ['show', `${revision}:${name}`],
  { cwd: root }).toString('utf8').replaceAll('\r\n', '\n')));
let count = 0;
function check(actual, expected, label) {
  if (actual !== expected) throw new Error(`Checksum mismatch: ${label}`);
  count++;
}
function privateFile(name, expected, bytes) {
  const file = resolve(experiments, name);
  const child = relative(experiments, file);
  if (child.startsWith('..') || isAbsolute(child)) throw new Error(`Invalid artifact path: ${name}`);
  if (bytes !== undefined && statSync(file).size !== bytes) throw new Error(`Size mismatch: ${name}`);
  check(hash(readFileSync(file)), expected, name);
}
for (const [name, expected] of Object.entries(registry.phase5dPreprocessingSha256))
  check(gitHash(registry.phase5dRevision, name), expected, name);
for (const [name, expected] of Object.entries(registry.preprocessingSha256))
  check(gitHash(registry.phase5fRevision, name), expected, name);
for (const [name, expected] of Object.entries(registry.evaluationCodeSha256))
  check(gitHash('ebe0f4f', name), expected, name);
check(gitHash(registry.phase5fRevision, 'docs/experiments/phase5f/results.json'), registry.phase5fReportSha256, 'Phase 5F report');
check(gitHash(registry.phase5fRevision, 'docs/experiments/phase5e/frozen-url.json'), registry.phase5eRegistrySha256, 'Phase 5E registry');
for (const [name, expected] of Object.entries(registry.historySha256)) privateFile(name, expected);
for (const entry of [...Object.values(registry.models), ...Object.values(registry.phase5fArtifacts)])
  if (entry.artifact) privateFile(entry.artifact, entry.sha256, entry.bytes);
const assets = JSON.parse(readFileSync(resolve(root, 'research/phase6a/assets.json')));
for (const asset of assets.assets) privateFile(`phase-6a-v1/${asset.filename}`, asset.sha256, asset.bytes);
const visualModel = JSON.parse(readFileSync(resolve(root, 'docs/experiments/phase6a/results.json'))).model;
privateFile('phase-6a-v1/mobilenetv3-small.safetensors', visualModel.sha256, visualModel.bytes);
console.log(`${count} receipt checks passed. Membership digests require their original verification procedure.`);
