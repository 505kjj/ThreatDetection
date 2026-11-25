"""Score only the frozen Phase 5E synthetic HTML fixtures for browser parity."""

import argparse
import json
from pathlib import Path
import sys

import joblib
from scipy.special import expit

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'research/phase5g'))
from frozen import REGISTRY, checked_artifact, dom_inputs, logistic_input
from replay import fixture_rows


def main(experiments, output):
    registry = json.loads(REGISTRY.read_text(encoding='utf-8'))
    artifacts = registry['phase5fArtifacts']
    models = {name: joblib.load(checked_artifact(experiments, artifacts[name]))
              for name in ('ngram', 'dom-weighted')}
    rows = list(fixture_rows())
    vector = dom_inputs(rows, 'weighted')
    url = models['ngram'].predict_proba([row['normalizedUrl'] for row in rows])[:, 1]
    dom = models['dom-weighted'].predict_proba(vector)[:, 1]
    scales = registry['phase5fParameters']['calibration']

    def calibrated(scores, key):
        slope, intercept = scales[key]
        return expit(slope * logistic_input(scores)[:, 0] + intercept)

    scores = 0.75 * calibrated(url, 'url-ngram') + 0.25 * calibrated(dom, 'dom-weighted')
    receipt = {'names': [row['id'] for row in rows], 'vectors': vector.tolist(),
               'scores': scores.tolist(), 'tolerance': 2e-6}
    with output.open('x', encoding='utf-8') as stream:
        json.dump(receipt, stream)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('experiments', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    if args.output.resolve().is_relative_to(ROOT):
        parser.error('Output must be outside the repository')
    main(args.experiments.resolve(), args.output)
