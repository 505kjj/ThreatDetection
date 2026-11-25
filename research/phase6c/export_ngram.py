"""Export the frozen Phase 5C n-gram model for private offline browser research."""

import argparse
from hashlib import sha256
import json
from pathlib import Path

import joblib

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = [
    "https://example.test/", "http://bank.example.test/login", "https://example.test/a/a/a",
    "https://xn--bcher-kva.example.test/%C3%BCber", "https://example.test/path%20space",
    "https://example.test/" + "a" * 256, "https://127.0.0.1:8443/payment",
    "https://example.test/AbC-123", "https://example.test/", "https://example.test/a%2Fb",
]


def main(experiments, output):
    receipt = json.loads((ROOT / "docs/experiments/phase5e/frozen-url.json").read_text())
    spec = receipt["models"]["ngram"]
    source = (experiments / spec["artifact"]).resolve()
    if not source.is_relative_to(experiments.resolve()):
        raise ValueError("Artifact is outside the private experiments directory")
    data = source.read_bytes()
    if len(data) != spec["bytes"] or sha256(data).hexdigest() != spec["sha256"]:
        raise ValueError("Frozen model checksum or size differs")
    model = joblib.load(source)
    vectorizer, classifier = (step[1] for step in model.steps)
    if (vectorizer.analyzer != "char" or vectorizer.ngram_range != (2, 5)
            or vectorizer.lowercase or not vectorizer.sublinear_tf or vectorizer.norm != "l2"
            or list(classifier.classes_) != [0, 1]):
        raise ValueError("Unexpected frozen pipeline configuration")
    vocabulary = sorted(vectorizer.vocabulary_.items(), key=lambda item: item[1])
    converted = {
        "schema": "phase6c-char-tfidf-logistic-v1", "sourceSha256": spec["sha256"],
        "terms": [term for term, _ in vocabulary], "idf": vectorizer.idf_.tolist(),
        "coefficients": classifier.coef_[0].tolist(), "intercept": float(classifier.intercept_[0]),
        "thresholds": spec["operatingPoints"],
    }
    output.mkdir(parents=True, exist_ok=False)
    (output / "model.json").write_text(json.dumps(converted, ensure_ascii=True, separators=(",", ":")), encoding="utf-8")
    reference = {"fixtures": FIXTURES, "scores": model.predict_proba(FIXTURES)[:, 1].tolist(),
                 "tolerance": 1e-10, "thresholds": spec["operatingPoints"]}
    (output / "reference.json").write_text(json.dumps(reference, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"sourceSha256": spec["sha256"], "terms": len(vocabulary),
                      "convertedBytes": (output / "model.json").stat().st_size, "fixtures": len(FIXTURES)}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("experiments", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.output.resolve().is_relative_to(ROOT.resolve()):
        parser.error("Output must be outside the repository")
    main(args.experiments, args.output)
