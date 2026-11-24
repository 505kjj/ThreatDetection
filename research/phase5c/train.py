"""Train one offline model on a frozen Phase 5C cohort under the Windows guard."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
from time import perf_counter

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from threadpoolctl import threadpool_limits

from paths import private

RESEARCH = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(RESEARCH), str(RESEARCH / "phase3d")]
from benchmark import model_for
from experiment_metrics import classify, negative_domain_scores, ranking, threshold_at_target

MODELS = ("logistic", "forest", "xgboost", "ngram", "cnn")
VERSION = "phase5c-development-v1"
PARTITIONS = ("train", "tuning", "calibration", "validation", "uci-validation")
TARGETS = (0.01, 0.001)
SEED = 143


def ids_sha256(rows):
    return sha256("".join(row["id"] + "\n" for row in rows).encode("ascii")).hexdigest()


def load_partition(folder, manifest, partition):
    spec = manifest["partitions"][partition]
    digest = sha256()
    rows = []
    with (folder / (partition + ".jsonl")).open("rb") as stream:
        for line in stream:
            digest.update(line)
            row = json.loads(line)
            if (row["partition"] != partition or row["label"] not in (0, 1)
                    or len(row["x"]) != 14 or len(row["id"]) != 64):
                raise ValueError("Unexpected canonical partition schema")
            rows.append(row)
    if (digest.hexdigest() != spec["sha256"] or len(rows) != spec["rows"]
            or len({row["id"] for row in rows}) != len(rows)):
        raise ValueError("Frozen partition failed checksum, count, or uniqueness check")
    return rows


def balanced(rows, size):
    if size % 2 or size < 2:
        raise ValueError("Require a positive even sample size")
    subsets = [[row for row in rows if row["label"] == value][:size // 2] for value in (0, 1)]
    if any(len(group) != size // 2 for group in subsets):
        raise ValueError("Insufficient balanced training capacity")
    return sorted(subsets[0] + subsets[1], key=lambda row: row["id"])


def build_input(name, rows):
    if name == "cnn":
        from sequence import represent
        return np.stack([represent(row, "cnn")[2] for row in rows])
    if name == "ngram":
        return [row["normalizedUrl"] for row in rows]
    return np.asarray([row["x"] for row in rows], dtype=np.float32)


def labels(rows):
    return np.asarray([row["label"] for row in rows], dtype=np.int8)


def fit_model(name, train, tuning, output, preflight):
    x = build_input(name, train)
    y = labels(train)
    metadata = {}
    if name == "cnn":
        import torch
        from sequence import CharacterCNN, fit, predict
        torch.set_num_threads(2)
        torch.set_num_interop_threads(1)
        tuning_input, tuning_labels = build_input(name, tuning), labels(tuning)
        start = perf_counter()
        model, metadata = fit(x, y, tuning_input, tuning_labels, epochs=2 if preflight else 8)
        elapsed = perf_counter() - start
        artifact = output / "model.pt"
        torch.save(model.state_dict(), artifact)
        loaded = CharacterCNN()
        loaded.load_state_dict(torch.load(artifact, weights_only=True, map_location="cpu"))
        np.testing.assert_array_equal(predict(model, x[:5]), predict(loaded, x[:5]))

        def score(values):
            return predict(loaded, values)
    else:
        model = (make_pipeline(TfidfVectorizer(analyzer="char", ngram_range=(2, 5), lowercase=False,
                                              min_df=2, max_features=100_000, sublinear_tf=True),
                               LogisticRegression(C=1, max_iter=200, random_state=SEED))
                 if name == "ngram" else model_for(name))
        start = perf_counter()
        model.fit(x, y)
        elapsed = perf_counter() - start
        artifact = output / "model.joblib"
        joblib.dump(model, artifact, compress=3)
        loaded = joblib.load(artifact)
        if not np.allclose(model.predict_proba(x[:5]), loaded.predict_proba(x[:5]), rtol=0, atol=1e-12):
            raise ValueError("Reloaded model changed inference beyond floating-point tolerance")

        def score(values):
            return loaded.predict_proba(values)[:, 1]
    return score, {"fitSeconds": elapsed, "modelBytes": artifact.stat().st_size,
                   "modelSha256": sha256(artifact.read_bytes()).hexdigest(), **metadata}


def evaluate(rows, scores, cutoffs):
    y = labels(rows)
    groups = np.array([row["identity"]["group"] for row in rows])
    operating = classify(y, scores, groups, 0.5)
    return {"rows": len(y), "phishing": int(y.sum()), "idsSha256": ids_sha256(rows),
            **ranking(y, scores), "atHalf": operating,
            "confusionMatrix": [[operating["tn"], operating["fp"]], [operating["fn"], operating["tp"]]],
            "atCalibratedConstraints": {
                str(target): None if result["threshold"] is None else classify(y, scores, groups, result["threshold"])
                for target, result in cutoffs.items()
            }}


def run(cohort, size, name, output, preflight):
    manifest_path = cohort / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    if manifest["version"] != VERSION or manifest["featureVersion"] != "url-lexical-v1":
        raise ValueError("Unexpected cohort version")
    train = balanced(load_partition(cohort, manifest, "train"), size)
    needed = PARTITIONS[1:4] if preflight else PARTITIONS[1:]
    data = {part: load_partition(cohort, manifest, part) for part in needed}
    if preflight:
        data = {part: rows[:1000] for part, rows in data.items()}
    output.mkdir(mode=0o700)
    with threadpool_limits(limits=2):
        score, metadata = fit_model(name, train, data["tuning"], output, preflight)
        calibration = data["calibration"]
        negative = negative_domain_scores(labels(calibration), score(build_input(name, calibration)),
                                          np.array([row["identity"]["group"] for row in calibration]))
        cutoffs = {target: threshold_at_target(negative, target, 0.05) for target in TARGETS}
        evaluation = {part: evaluate(rows, score(build_input(name, rows)), cutoffs)
                      for part, rows in data.items() if part.endswith("validation")}
        validation = data["validation"]
        # Warmed single-example model input and prediction, sampling across the same stable IDs.
        sample = [validation[i] for i in np.linspace(0, len(validation) - 1, 300, dtype=int)]
        for row in sample[:10]:
            score(build_input(name, [row]))
        latency = []
        for row in sample:
            start = perf_counter()
            score(build_input(name, [row]))
            latency.append((perf_counter() - start) * 1000)
    report = {"model": name, "trainRows": size, "trainIdsSha256": ids_sha256(train),
              "cohortSha256": sha256(manifest_path.read_bytes()).hexdigest(), "preflight": preflight,
              "latencyMedianMs": float(np.median(latency)), "latencyP95Ms": float(np.percentile(latency, 95)),
              "calibration": cutoffs, "evaluation": evaluation, **metadata}
    (output / "result.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps({"model": name, "trainRows": size, "fitSeconds": metadata["fitSeconds"],
                      "validationAveragePrecision": evaluation["validation"]["prAucAveragePrecision"]}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cohort", type=private)
    parser.add_argument("size", type=int)
    parser.add_argument("model", choices=MODELS)
    parser.add_argument("output", type=private)
    parser.add_argument("--preflight", action="store_true")
    args = parser.parse_args()
    if os.environ.get("THREAT_PHASE3D_GUARDED") != "1":
        parser.error("Use the Windows Job Object resource guard")
    run(args.cohort, args.size, args.model, args.output, args.preflight)
