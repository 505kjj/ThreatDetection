"""Generate private synthetic near-threshold references from the frozen URL model."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import random
import string

import joblib
import numpy as np

ROOT = Path(__file__).resolve().parents[2]


def main(experiments, output):
    spec = json.loads((ROOT / 'docs/experiments/phase5e/frozen-url.json').read_text())['models']['ngram']
    path = (experiments / spec['artifact']).resolve()
    if not path.is_relative_to(experiments.resolve()):
        raise ValueError('Artifact outside experiments directory')
    data = path.read_bytes()
    if len(data) != spec['bytes'] or sha256(data).hexdigest() != spec['sha256']:
        raise ValueError('Frozen checkpoint differs')
    model = joblib.load(path)
    randomizer = random.Random(7143)
    parts = ['login', 'account', 'verify', 'bank', 'secure', 'payment', 'support', 'example']
    samples = []
    for _ in range(4000):
        host = '-'.join(randomizer.choices(parts, k=randomizer.randint(1, 3)))
        suffix = ''.join(randomizer.choices(string.ascii_lowercase + string.digits, k=randomizer.randint(2, 16)))
        samples.append(f'https://{host}-{suffix}.example.test/{randomizer.choice(parts)}')
    scores = model.predict_proba(samples)[:, 1]
    thresholds = [value for value in spec['operatingPoints'].values() if value is not None]
    indices = set(range(100))
    for threshold in thresholds:
        indices.update(np.argsort(np.abs(scores - threshold))[:20].tolist())
    indices = sorted(indices)
    result = {'fixtures': [samples[index] for index in indices], 'scores': scores[indices].tolist(),
              'tolerance': 1e-10, 'thresholds': spec['operatingPoints'],
              'minimumThresholdDistance': {str(value): float(np.min(np.abs(scores - value))) for value in thresholds},
              'generatedSyntheticCandidates': len(samples)}
    with output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2)
    print(json.dumps({'fixtures': len(indices), 'generated': len(samples),
                      'minimumThresholdDistance': result['minimumThresholdDistance']}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('experiments', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    if args.output.resolve().is_relative_to(ROOT.resolve()):
        parser.error('Output must be outside the repository')
    main(args.experiments, args.output)
