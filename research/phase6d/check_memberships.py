"""Recompute Phase 5F development membership digests without fitting or scoring."""

import argparse
from collections import Counter
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'research/phase5f'))
from replay import balanced, ids_sha256
from compare import load_matched
from grouping import grouped_views


def main(experiments):
    cohort = experiments / 'phase-5c-v1/cohort'
    source = experiments / 'phase-5e-v1'
    pools, _ = load_matched(cohort, [source / 'html-pilot-final', source / 'html-20k'])
    grouped, _ = grouped_views(pools)
    counts = Counter(row['label'] for row in grouped['train'])
    size = min(10000, counts[0], counts[1]) * 2
    grouped['train'] = balanced(grouped['train'], size)
    actual = {name: ids_sha256(rows) for name, rows in grouped.items()}
    expected = json.loads((ROOT / 'docs/experiments/phase5g/frozen-models.json').read_text())['groupedMembershipSha256']
    if actual != expected:
        raise ValueError('Grouped membership digests differ')
    print(json.dumps({'matchedPartitions': sorted(actual), 'trainRows': size}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('experiments', type=Path)
    main(parser.parse_args().experiments.resolve())
