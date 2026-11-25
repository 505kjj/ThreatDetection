"""Export frozen XGBoost trees and synthetic numerical reference predictions."""

import argparse
from hashlib import sha256
import json
from pathlib import Path

import joblib
import numpy as np

ROOT = Path(__file__).resolve().parents[2]


def main(experiments, output):
    url = json.loads((ROOT / "docs/experiments/phase5e/frozen-url.json").read_text())["models"]["xgboost"]
    registry = json.loads((ROOT / "docs/experiments/phase5g/frozen-models.json").read_text())
    dom = registry["phase5fArtifacts"]["dom-weighted"]
    output.mkdir(parents=True, exist_ok=False)
    for name, spec in (("url", url), ("dom", dom)):
        source = (experiments / spec["artifact"]).resolve()
        if not source.is_relative_to(experiments.resolve()):
            raise ValueError("Artifact is outside private experiments directory")
        data = source.read_bytes()
        if len(data) != spec["bytes"] or sha256(data).hexdigest() != spec["sha256"]:
            raise ValueError("Frozen model checksum or size differs")
        model = joblib.load(source)
        booster = model.get_booster()
        config = json.loads(booster.save_config())["learner"]
        if config["learner_train_param"]["objective"] != "binary:logistic":
            raise ValueError("Unexpected model objective")
        base = json.loads(config["learner_model_param"]["base_score"])[0]
        width = booster.num_features()
        vectors = np.array([[float((i * (j + 3)) % 11) for j in range(width)]
                            for i in range(12)], dtype=np.float32)
        converted = {"schema": "phase6c-xgboost-v1", "sourceSha256": spec["sha256"],
                     "baseScore": base, "features": width,
                     "trees": [json.loads(tree) for tree in booster.get_dump(dump_format="json")]}
        (output / f"{name}.json").write_text(json.dumps(converted, separators=(",", ":")), encoding="utf-8")
        reference = {"vectors": vectors.tolist(), "scores": model.predict_proba(vectors)[:, 1].tolist(),
                     "tolerance": 2e-6, "thresholds": spec.get("operatingPoints", {})}
        (output / f"{name}-reference.json").write_text(json.dumps(reference, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"model": name, "features": width, "bytes": (output / f"{name}.json").stat().st_size}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("experiments", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.output.resolve().is_relative_to(ROOT.resolve()):
        parser.error("Output must be outside the repository")
    main(args.experiments, args.output)
