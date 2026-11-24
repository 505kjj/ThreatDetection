import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Readable } from 'node:stream';
import { extractUrl } from '../../evaluation/features.mjs';
import { assertDisjoint, candidate, deduplicate, split } from './cohort.mjs';
import { byteLines } from './custody.mjs';
import { classifyTarget } from './financial.mjs';

const make = (id, url, label = 1, source = 'fixture') =>
  candidate({ sourceId: id, url, label }, source, 'test-revision', 'synthetic');

test('canonical URL structure and IDs match existing offline conventions', () => {
  const raw = 'HTTPS://Example.test/A%2fFlow?fixture=token#marker';
  const row = make('1', raw);
  assert.equal(row.url, raw);
  assert.equal(row.normalizedUrl, 'https://example.test/A%2FFlow');
  assert.deepEqual(row.x, extractUrl(raw, 'synthetic').features);
  assert.equal(row.id, make('1', raw, 0).id);
  assert.notEqual(row.id, make('1', raw, 1, 'other-fixture').id);
  assert.equal(row.campaign, null);
  assert.equal(row.collectedAt, null);
  assert.equal(row.target, null);
  assert.equal(make('2', 'https://name:pass@example.test/a'), null);
});

test('alias groups remove exact duplicates, variants and conflicting labels', () => {
  const url = 'https://strucfixture.test/flow?test=1';
  const rows = [make('0', url), make('1', url), make('2', 'http://www.strucfixture.test/flow')];
  const other = [make('3', 'https://anotherfixture.test/'), make('4', 'https://anotherfixture.test/', 0, 'other')];
  const rejects = {};
  const input = new Map([[rows[0].identity.alias, rows], [other[0].identity.alias, other]]);
  assert.equal(rows[0].identity.alias, rows[2].identity.alias);
  assert.equal(deduplicate(input, rejects).length, 1);
  assert.deepEqual(rejects, { exactDuplicateRows: 1, nearDuplicateRows: 1, conflictingLabelRows: 2 });
});

test('component assignment is reproducible and confines domains and families', () => {
  const one = make('one', 'https://strucfixture.test/a');
  const two = make('two', 'https://sub.strucfixture.test/b');
  const three = make('three', 'https://strucfixture1.test/c');
  const input = [one, two, three, make('four', 'https://example.test/a')];
  const direct = split(input);
  assert.deepEqual(direct, split([...input].reverse()));
  assertDisjoint(direct);
  assert.equal(Object.values(direct).find(rows => rows.some(row => row.id === one.id)).length >= 3, true);
  assert.throws(() => assertDisjoint({ train: [one], validation: [two] }), /partition overlap/);
  assert.throws(() => assertDisjoint({ train: [one, one] }), /Duplicate ID/);
});

test('custody framing reads multibyte and final lines across a closing byte stream', async () => {
  const encoded = Buffer.from('a€\nb\n', 'utf8');
  const stream = Readable.from([encoded.subarray(0, 2), encoded.subarray(2, 5), encoded.subarray(5)]);
  const rows = [];
  for await (const line of byteLines(stream)) rows.push(line);
  assert.deepEqual(rows, ['a€', 'b']);
  await assert.rejects(async () => {
    for await (const _ of byteLines(Readable.from([Buffer.from('partial')]))) {
      assert.fail('Incomplete line must never be emitted');
    }
  }, /Incomplete projection line/);
});

test('financial metadata matches include exact Indian entities and disambiguate Japan SBI Securities', () => {
  assert.deepEqual(classifyTarget('phish', 'YES Securities (India) Ltd.'), {
    status: 'candidate', name: 'yes securities india ltd'
  });
  assert.deepEqual(classifyTarget('phish', 'SBI SECURITIES Co., Ltd.'), {
    status: 'foreignEntity', name: 'sbi securities co ltd'
  });
  assert.equal(classifyTarget('benign', 'NPCI'), null);
  assert.equal(classifyTarget('phish', 'unrelated sbi label'), null);
});
