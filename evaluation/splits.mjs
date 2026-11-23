import { sha256 } from './features.mjs';

export const windows = ['train', 'validation', 'test'];

export function timestamp(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{3})?Z$/.test(value)) return null;
  const time = Date.parse(value);
  const iso = value.length === 20 ? value.slice(0, -1) + '.000Z' : value;
  if (!Number.isFinite(time) || new Date(time).toISOString() !== iso) return null;
  return time;
}

export function splitRecords(rows, plan) {
  const chronological = { train: [], validation: [], test: [] };
  const domainDisjoint = { train: [], validation: [], test: [] };
  const withheld = { undated: 0, seenInEarlierWindow: 0 };
  const first = new Map();
  const { trainBefore, testFrom, seed } = plan;
  const window = time => time < trainBefore ? 'train' : time < testFrom ? 'validation' : 'test';
  for (const { group, observedAt } of rows) {
    if (observedAt !== null && observedAt < (first.get(group) ?? Infinity)) first.set(group, observedAt);
  }
  const buckets = new Map();
  for (const row of rows) {
    if (!buckets.has(row.group)) {
      const fraction = Number.parseInt(sha256(seed + '\0' + row.group).slice(0, 8), 16) / 2 ** 32;
      buckets.set(row.group, fraction < 0.7 ? 'train' : fraction < 0.85 ? 'validation' : 'test');
    }
    domainDisjoint[buckets.get(row.group)].push(row);
    if (row.observedAt === null) {
      withheld.undated++;
      continue;
    }
    const partition = window(row.observedAt);
    if (partition === window(first.get(row.group))) chronological[partition].push(row);
    else withheld.seenInEarlierWindow++;
  }
  return { chronological, domainDisjoint, withheld };
}
