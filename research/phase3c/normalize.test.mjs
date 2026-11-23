import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { sha256 } from '../../evaluation/features.mjs';

const group = host => sha256('phase3b-group\0' + host);
const runner = fileURLToPath(new URL('./normalize.mjs', import.meta.url));

test('external projection excludes UCI groups and overlapping windows without retaining URL secrets', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'threat-projection-test-'));
  t.after(() => {
    assert.match(relative(resolve(tmpdir()), resolve(directory)), /^threat-projection-test-[a-zA-Z0-9]+$/);
    return rm(directory, { recursive: true, force: true });
  });
  const uci = join(directory, 'uci');
  const output = join(directory, 'output');
  for (const [sub, names] of [['development', ['train', 'validation']], ['holdout', ['test']]]) {
    const folder = join(uci, sub);
    await mkdir(folder, { recursive: true });
    const manifest = { dataset: 'phiusiil-uci-967', splitSeed: 'phase3a-v1' };
    for (const name of names) {
      const file = name + '.tsv';
      const bytes = `0\t${group('known-fixture.github.io')}\t0\n`;
      await writeFile(join(folder, file), bytes);
      manifest[name] = { file, sha256: sha256(bytes) };
    }
    await writeFile(join(folder, 'manifest.json'), JSON.stringify(manifest));
  }
  const rows = [];
  for (let day = 1; day <= 4; day++) {
    const date = `2025-01-0${day}`;
    rows.push(['train', 'phish', date, `https://p-${day}-fixture.github.io/?fixtureSecret=q`]);
    rows.push(['train', 'benign', date, `https://n-${day}-fixture.github.io/`]);
  }
  rows.push(['train', 'phish', '2025-01-03', 'https://p-3-fixture.github.io/?other=private']);
  rows.push(['test', 'phish', '2025-02-01', 'https://known-fixture.github.io/']);
  rows.push(['test', 'phish', '2025-02-01', 'https://new-phish-fixture.github.io/']);
  rows.push(['test', 'benign', '2025-02-01', 'https://new-benign-fixture.github.io/']);
  const input = rows.map(row => JSON.stringify(row)).join('\n');
  const run = spawnSync(process.execPath, [runner, uci, output], { input, encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr);
  const report = JSON.parse(run.stdout);
  assert.equal(report.overlappingUciGroups, 1);
  assert.equal(report.counts.duplicateUrls, 1);
  assert.equal(report.partitions.train.rows, 6);
  assert.equal(report.partitions.calibration.rows, 2);
  assert.equal(report.partitions.test.rows, 2);
  assert.ok(report.partitions.calibration.lastDay < report.partitions.test.firstDay);
  assert.doesNotMatch(await readFile(join(output, 'train.tsv'), 'utf8'), /fixtureSecret|github\.io|private/);
});
