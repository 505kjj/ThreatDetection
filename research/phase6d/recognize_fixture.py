"""Compare synthetic browser-read pixels with frozen Phase 6A recognition."""

import argparse
import json
from pathlib import Path
import sys
from time import perf_counter

import numpy as np
from PIL import Image

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'research/phase6a'))
from fixtures import invented_mark
from vision import Extractor, METHODS, MobileNet, classify, interpret


def main(source, pixels, output):
    packet = json.loads(pixels.read_text())
    array = np.asarray(packet['pixels'], dtype=np.uint8).reshape(packet['height'], packet['width'], 4)
    start = perf_counter()
    extractor = Extractor(MobileNet(source / 'mobilenetv3-small.safetensors'))
    initialization = (perf_counter() - start) * 1000
    refs = [(f'invented-{i}', extractor.features(invented_mark(i))[0]) for i in range(3)]
    timings = []
    for _ in range(10):
        start = perf_counter()
        features, _ = extractor.features(Image.fromarray(array, 'RGBA'))
        decisions = {method: classify(features, refs, method) for method in METHODS}
        timings.append((perf_counter() - start) * 1000)
    expected = {method: classify(refs[0][1], refs, method) for method in METHODS}
    brands = {'invented-0': {'scopes': ['bank.example.test'], 'sharedHosts': []}}
    assert decisions == expected
    context = interpret('merchant.example.test', [decisions['phash']], brands)
    report = {'fictionalFixtures': 1, 'decisions': decisions, 'matchesOfflineDecisions': True,
              'merchantContext': context, 'initializationMs': initialization,
              'medianMs': float(np.median(timings)), 'p95Ms': float(np.percentile(timings, 95))}
    with output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
    print(json.dumps(report))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('pixels', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    if any(path.resolve().is_relative_to(ROOT.resolve()) for path in (args.source, args.pixels, args.output)):
        parser.error('All paths must be outside the repository')
    main(args.source, args.pixels, args.output)
