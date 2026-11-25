"""Run bounded offline visual baselines and publish no raw logo data."""

import argparse
from collections import Counter, defaultdict
from hashlib import file_digest, sha256
from itertools import combinations
import json
import os
from pathlib import Path
import subprocess
from time import perf_counter

import numpy as np
from PIL import __version__ as pillow_version
from fixtures import invented_mark, transformations
from vision import (Extractor, MAX_ENCODED, MobileNet, METHODS, THRESHOLDS, WEIGHT_BYTES,
                    WEIGHT_REVISION, WEIGHT_SHA256, classify, decode, encode,
                    interpret, letterbox)

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def private(value):
    path = Path(value).resolve()
    if any((parent / ".git").exists() for parent in (path, *path.parents)):
        raise ValueError("Use private paths outside Git")
    return path


def receipt(path, report):
    with path.open("x", encoding="utf-8", newline="\n") as target:
        json.dump(report, target, indent=2, allow_nan=False)
        target.write("\n")


def summary(values):
    return {"medianMs": float(np.median(values)), "p95Ms": float(np.percentile(values, 95))}


def assets(directory, brands, extractor):
    rows = json.loads((HERE / "assets.json").read_text(encoding="utf-8"))["assets"]
    parsed = []
    for row in rows:
        if row["brand"] not in brands or not row["usageBasis"]:
            raise ValueError("Unregistered or unreviewed financial reference")
        path = (directory / row["filename"]).resolve()
        if not path.is_relative_to(directory):
            raise ValueError("Reference escaped the private directory")
        with path.open("rb") as stream:
            data = stream.read(MAX_ENCODED + 1)
        if len(data) != row["bytes"] or sha256(data).hexdigest() != row["sha256"]:
            raise ValueError("Private reference does not match the frozen receipt")
        image = decode(data)
        features, _ = extractor.features(image)
        parsed.append((row, image, features))
    if len({row["family"] for row, _, _ in parsed}) != len(parsed):
        raise ValueError("This preflight expects one reference per original asset family")
    return parsed


def duplicate_audit(references):
    exact = near = 0
    for (a, _, first), (b, _, second) in combinations(references, 2):
        if a["sha256"] == b["sha256"] or first.normalized == second.normalized:
            exact += 1
        elif (first.phash ^ second.phash).bit_count() <= 4:
            near += 1
    if exact:
        raise ValueError("Exact reference duplicate would bias the asset-family test")
    return {"pairs": len(references) * (len(references) - 1) // 2, "exact": exact, "near": near,
            "nearMetric": "pHash Hamming distance <= 4"}


def private_index(path, references):
    payload = {}
    for i, (_, _, features) in enumerate(references):
        payload[f"phash_{i}"] = np.array([features.phash], dtype=np.uint64)
        payload[f"orb_{i}"] = features.orb if features.orb is not None else np.empty((0, 32), dtype=np.uint8)
        payload[f"mobilenet_{i}"] = features.mobilenet.astype(np.float32)
    with path.open("xb") as stream:
        np.savez_compressed(stream, **payload)
    return {method: sum(value.nbytes for key, value in payload.items() if key.startswith(method + "_"))
            for method in METHODS} | {"privateCompressedIndexBytes": path.stat().st_size}


def benchmark(extractor, references, controls=None):
    ref = [(asset["brand"], features) for asset, _, features in references]
    results = {name: defaultdict(Counter) for name in METHODS}
    timing = defaultdict(list)
    copies = Counter()
    cases = []
    for asset, image, reference in references:
        for variation, data in transformations(image).items():
            cases.append((variation, data, asset["brand"], reference))
    for name, data in (controls or {}).items():
        cases.append((name, data, None, None))
    for variation, data, label, original in cases:
        start = perf_counter()
        image = decode(data)
        decoded = perf_counter()
        features, stages = extractor.features(image)
        timing["decode"].append((decoded - start) * 1000)
        for stage, elapsed in stages.items():
            timing[stage].append(elapsed)
        if original is not None:
            copies["sameNormalizedPixels"] += features.normalized == original.normalized
            copies["withinFourHashBits"] += (features.phash ^ original.phash).bit_count() <= 4
        for method in METHODS:
            start = perf_counter()
            decision, brand = classify(features, ref, method)
            match_ms = (perf_counter() - start) * 1000
            timing[method + "MatchMs"].append(match_ms)
            extract = {"phash": "phashMs", "orb": "orbMs", "mobilenet": "mobileNetMs"}[method]
            timing[method + "EndToEndMs"].append(timing["decode"][-1] + stages["normalizeMs"] + stages[extract] + match_ms)
            if decision != "recognized":
                outcome = decision
            elif label is None:
                outcome = "false-match"
            else:
                outcome = "correct" if brand == label else "wrong-brand"
            results[method][variation][outcome] += 1
    return {"rows": len(cases), "transformations": results, "sameFamilyCollisionProbe": dict(copies),
            "timing": {stage: summary(values) for stage, values in timing.items()}}


def contexts(registered, references):
    names = [row["brand"] for row, _, _ in references]
    reports = {}
    for method in METHODS:
        ref = [(row["brand"], features) for row, _, features in references]
        actual = [classify(features, ref, method) for _, _, features in references]
        first = actual[0]
        if not names:
            continue
        scope = registered[names[0]]["scopes"][0]
        reports[method] = {
            "sameBrandScope": interpret(scope, [first], registered),
            "syntheticMerchantReference": interpret("merchant.example.test", [first], registered),
            "twoKnownCandidates": interpret("merchant.example.test", actual[:2], registered),
            "absentCandidates": interpret(scope, [], registered),
        }
    return reports


def browser_export(output, model, fixtures):
    import onnx
    from PIL import Image

    path = output / "embedding.onnx"
    sample = model.torch.zeros((1, 3, 224, 224), dtype=model.torch.float32)
    model.torch.onnx.export(model.model, sample, str(path), dynamo=False, opset_version=17,
                            input_names=["pixels"], output_names=["embedding"])
    onnx.checker.check_model(str(path))
    expected = []
    for i, (_, image, features) in enumerate(fixtures):
        name = f"fixture-{i}.png"
        normalized = f"normalized-{i}.png"
        (output / name).write_bytes(encode(image))
        (output / normalized).write_bytes(encode(Image.fromarray(letterbox(image))))
        expected.append({"name": name, "normalized": normalized, "vector": features.mobilenet.tolist()})
    receipt(output / "browser-vectors.json", expected)
    with path.open("rb") as stream:
        return {"modelBytes": path.stat().st_size, "sha256": file_digest(stream, "sha256").hexdigest(),
                "syntheticFixtures": len(fixtures)}


def run(source, output, export_browser):
    import cv2
    import timm

    registry = json.loads(subprocess.check_output(["node", str(HERE / "domains.mjs")], cwd=ROOT))
    brands = {row["name"]: row for row in registry["brands"]}
    model = MobileNet(source / "mobilenetv3-small.safetensors")
    extractor = Extractor(model)
    references = assets(source, brands, extractor)
    generated = []
    for i in range(3):
        image = invented_mark(i)
        generated.append(({"brand": "invented-" + str(i)}, image, extractor.features(image)[0]))
    output.mkdir()
    storage = private_index(output / "visual-index.npz", references)
    unknown = encode(invented_mark(3))
    unrelated = {f"unrelated-invented-{i}": encode(item[1]) for i, item in enumerate(generated)}
    report = {"registry": registry,
              "approvedAssetManifestSha256": sha256((HERE / "assets.json").read_bytes().replace(b"\r\n", b"\n")).hexdigest(),
              "referenceCounts": {name: sum(row["brand"] == name for row, _, _ in references) for name in brands},
              "referencePairCollisions": duplicate_audit(references), "thresholds": THRESHOLDS,
              "referenceStorage": storage, "realReferencesSyntheticTransformations": benchmark(extractor, references, unrelated),
              "fictionalMarks": benchmark(extractor, generated, {"similar-unrelated-mark": unknown}),
              "offlineContextDiagnostics": contexts(brands, references),
              "model": {"revision": WEIGHT_REVISION, "sha256": WEIGHT_SHA256, "bytes": WEIGHT_BYTES,
                        "license": "Apache-2.0", "embeddingDimensions": references[0][2].mobilenet.size},
              "runtime": {"pillow": pillow_version, "opencv": cv2.__version__, "timm": timm.__version__,
                          "torch": str(model.torch.__version__), "numpy": np.__version__},
              "independentVisualRows": 0, "independentPairedRows": 0, "siameseTrained": False}
    if export_browser:
        report["browserExport"] = browser_export(output, model, generated)
    receipt(output / "results.json", report)
    print(f"Benchmarked {len(references)} reviewed financial references and {len(generated)} fictional marks")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=private)
    parser.add_argument("output", type=private)
    parser.add_argument("--export-browser", action="store_true")
    args = parser.parse_args()
    if os.environ.get("THREAT_PHASE3D_GUARDED") != "1":
        parser.error("Use the Windows Job Object guard")
    run(**vars(args))
