import assert from 'node:assert/strict';
import { test } from 'node:test';
import { candidate } from '../phase5c/cohort.mjs';
import { fusionFit, match, temporal } from './prepare.mjs';

const row = (id, host, day) => candidate({
  sourceId: id, url: 'https://' + host + '/' + id, label: 1, date: day
}, 'fixture', 'frozen-reference', 'synthetic');

test('chronological cutoffs preserve dates and quarantine transitive family overlap', () => {
  const withDates = [
    row('old', 'samefamily.test', '2024-08-20'),
    row('bridge', 'samefamily2.test', '2024-09-01'),
    row('late', 'sub.samefamily2.test', '2024-10-01'),
    row('tune', 'tune.example.test', '2024-09-14'),
    row('calibrate', 'another.test', '2024-09-15'),
    row('unsupported', 'invalid.test', '2024-02-30'),
    row('far', 'last.test', '2024-11-01')
  ];
  const run = temporal(withDates);
  assert.deepEqual(run, temporal([...withDates].reverse()));
  assert.equal(run.invalidDate, 1);
  assert.equal(run.quarantined, 2);
  assert.equal(run.result.train.length, 0);
  assert.equal(run.result.tuning[0].sourceId, 'tune');
  assert.equal(run.result.calibration[0].collectedAt, '2024-09-15');
  assert.equal(run.result.near[0].sourceId, 'late');
  assert.equal(run.result.far[0].collectedAt, '2024-11-01');
});

test('publisher ID, canonical URL alias, group and family independently exclude rows', () => {
  const fixture = row('item', 'longfamily.test', '2024-08-20');
  for (const field of ['id', 'family', 'group', 'alias', 'exact']) {
    const sets = Object.fromEntries(['id', 'family', 'group', 'alias', 'exact'].map(key => [key, new Set()]));
    assert.equal(match(sets, fixture), false);
    sets[field].add(field === 'id' ? fixture.sourceId : fixture.identity[field]);
    assert.equal(match(sets, fixture), true);
  }
});

test('fusion uses both classes from components outside the sampled training view', () => {
  const train = Array.from({ length: 12 }, (_, i) => ({
    ...row(String(i), 'example-' + String(i) + '.test', '2024-08-20'),
    id: String(i).padStart(2, '0'),
    label: Number(i >= 6)
  }));
  const members = fusionFit(train, 4, 4);
  assert.deepEqual(members.map(row => row.id), ['02', '03', '08', '09']);
  assert.deepEqual(members.map(row => row.label), [0, 0, 1, 1]);
});
