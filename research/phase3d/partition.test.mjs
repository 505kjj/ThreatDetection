import assert from 'node:assert/strict';
import test from 'node:test';
import { campaignProxy, partition } from './partition.mjs';

test('preserves test time and removes overlapping registrable domains and lexical families', () => {
  const rows = [
    { side: 'test', date: '2025-09-01', group: 'a', family: 'family1' },
    { side: 'train', date: '2025-08-31', group: 'a', family: '' },
    { side: 'train', date: '2025-07-01', group: 'b', family: 'family1' },
    { side: 'train', date: '2025-09-02', group: 'c', family: '' },
    { side: 'train', date: '2025-01-01', group: 'd', family: '' },
    { side: 'train', date: '2025-02-01', group: 'e', family: 'family2' },
    { side: 'train', date: '2025-03-01', group: 'f', family: '' },
    { side: 'train', date: '2025-04-01', group: 'g', family: 'family2' },
  ];
  const groups = Object.fromEntries(Object.entries(partition(rows)).map(([key, cohort]) =>
    [key, cohort.map(r => r.group)]));
  assert.deepEqual(groups, { train: ['d', 'f'], validation: ['g'], test: ['a'] });
});

test('proxy connects variants across suffixes and abstains on short registrants', () => {
  assert.equal(campaignProxy('spearmint-41.test'), campaignProxy('spearmint-13.example'));
  assert.match(campaignProxy('spearmint-41.test'), /^[0-9a-f]{64}$/);
  assert.equal(campaignProxy('mint-41.test'), '');
});
