"""Score the pinned single model and all three fusion artifacts without fitting or tuning."""

import argparse
from collections import Counter
import json
import os
from pathlib import Path
from statistics import median
import sys
from time import perf_counter, process_time
import tracemalloc

import joblib
import numpy as np
from scipy.stats import beta
from threadpoolctl import threadpool_limits

from cohort import PHASE3D, PROTOCOL, checksum, private, read, write

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from experiment_metrics import classify, ranking, ratio
from phase3d.benchmark import FEATURES, HOST, predict


def exact_interval(success, total):
    if not total:
        return None
    return [float(beta.ppf(0.025, success, total - success + 1)) if success else 0.0,
            float(beta.ppf(0.975, success + 1, total - success)) if success < total else 1.0]


def metrics(labels, groups, probabilities, threshold):
    result = classify(labels, probabilities, groups, threshold)
    result["recallBinomial95"] = exact_interval(result["tp"], result["tp"] + result["fn"])
    result["urlFprBinomial95"] = exact_interval(result["fp"], result["fp"] + result["tn"])
    result["precisionBinomial95"] = exact_interval(result["tp"], result["tp"] + result["fp"])
    return result


def pair_difference(labels, groups, old, new, samples, seed):
    positives = labels == 1
    negatives = ~positives
    added = new & ~old
    lost = old & ~new
    old_error = old != positives
    new_error = new != positives
    errors = (np.std(old_error) > 0 and np.std(new_error) > 0)
    result = {
        "extraPhish": int(np.sum(added & positives)), "lostPhish": int(np.sum(lost & positives)),
        "extraFalsePositives": int(np.sum(added & negatives)), "avoidedFalsePositives": int(np.sum(lost & negatives)),
        "disagree": int(np.sum(added | lost)), "sharedErrors": int(np.sum(old_error & new_error)),
        "errorCorrelation": float(np.corrcoef(old_error, new_error)[0, 1]) if errors else None,
    }
    if positives.any():
        _, index = np.unique(groups[positives], return_inverse=True)
        counts = np.bincount(index)
        delta = np.bincount(index, weights=new[positives].astype(int) - old[positives].astype(int))
        if len(counts) > 1:
            rng = np.random.default_rng(seed)
            values = []
            for _ in range(samples):
                draw = rng.integers(0, len(counts), size=len(counts))
                values.append(delta[draw].sum() / counts[draw].sum())
            result["pairedRecallDeltaDomainBootstrap95"] = [float(v) for v in np.quantile(values, [0.025, 0.975])]
        else:
            result["pairedRecallDeltaDomainBootstrap95"] = None
        result["recallDelta"] = ratio(result["extraPhish"] - result["lostPhish"], int(positives.sum()))
    else:
        result["recallDelta"] = None
        result["pairedRecallDeltaDomainBootstrap95"] = None
    return result


def time_inference(bundle, vectors):
    predict(bundle, vectors[:1])
    timings = []
    cpu_start = process_time()
    for index in range(128):
        sample = vectors[index % len(vectors):index % len(vectors) + 1]
        start = perf_counter()
        predict(bundle, sample)
        timings.append((perf_counter() - start) * 1000)
    cpu_ms = (process_time() - cpu_start) * 1_000 / len(timings)
    tracemalloc.start()
    try:
        predict(bundle, vectors[:256])
        traced_peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    return {"p50Ms": median(timings), "p95Ms": float(np.quantile(timings, .95)),
            "processCpuMsPerRow": cpu_ms, "pythonTracedBytesBatchUpTo256": traced_peak}


def artifact(models, name, previous, single):
    expected = previous["candidates"][name]["fit"]
    path = models / name / "model.joblib"
    if path.stat().st_size != expected["modelBytes"] or checksum(path) != expected["artifactSha256"]:
        raise ValueError("Checksum or size differs for frozen candidate")
    start = perf_counter()
    bundle = joblib.load(path)
    load_ms = (perf_counter() - start) * 1_000
    if tuple(bundle["columns"]) != (FEATURES["path"] if single else HOST):
        raise ValueError("Frozen artifact feature columns differ")
    thresholds = {str(entry["targetNegativeDomainFpr"]): entry["threshold"] for entry in expected["cutoffs"]}
    if any(thresholds[k] is None for k in ("0.001", "0.01")):
        raise ValueError("A required original cutoff is unavailable")
    return bundle, thresholds, {"storageBytes": path.stat().st_size, "loadMs": load_ms, "sha256": expected["artifactSha256"]}


def compare(rows, scores, thresholds, config):
    y = np.array([row["y"] for row in rows], dtype=np.int8)
    groups = np.array([row["group"] for row in rows])
    amber = np.array([row["amber"] for row in rows], dtype=bool)
    individual = config["candidateOrder"][0]
    points = [str(config[key]) for key in ("primaryDomainTarget", "secondaryDomainTarget")]
    candidates = {}
    for name, values in scores.items():
        findings = {"ranking": ranking(y, values) if len(set(y)) == 2 else None, "cutoffs": {}}
        for point in points:
            threshold = thresholds[name][point]
            called = values >= threshold
            old = scores[individual] >= thresholds[individual][point]
            findings["cutoffs"][point] = {
                "metrics": metrics(y, groups, values, threshold),
                "comparedWithRandomForest": pair_difference(
                    y, groups, old, called, config["limits"]["pairedBootstrapResamples"], config["limits"]["seed"]),
                "advisoryOnlyUnionMetrics": metrics(y, groups, np.logical_or(amber, called), .5),
                "mlAddsToBrandAdvisoryPhish": int(np.sum(called & ~amber & (y == 1))),
                "mlAddsToBrandAdvisoryFalsePositives": int(np.sum(called & ~amber & (y == 0))),
            }
        candidates[name] = findings
    return {
        "support": {"phishing": int(y.sum()), "legitimate": int((y == 0).sum()), "domains": int(len(set(groups))),
                    "positiveDomains": int(len(set(groups[y == 1]))), "negativeDomains": int(len(set(groups[y == 0]))),
                    "firstDay": min(row["date"] for row in rows), "lastDay": max(row["date"] for row in rows)},
        "brandAmber": metrics(y, groups, amber, .5),
        "candidates": candidates,
    }


def execute(cohort, models, output):
    config = read(PROTOCOL)
    previous = read(PHASE3D)
    frozen = read(cohort / "frozen.json")
    numeric = cohort / "numeric.jsonl"
    if (frozen["protocolSha256"] != checksum(PROTOCOL) or frozen["phase3dSummarySha256"] != checksum(PHASE3D)
            or frozen["projection"]["sha256"] != checksum(numeric)
            or frozen["projection"]["featureVersion"] != config["featureVersion"]
            or frozen["projection"]["featureColumns"] != previous["dataset"]["featureColumns"]):
        raise ValueError("Frozen data, model reference or feature version changed")
    output.mkdir()
    write(output / "opened.json", {"cohortFreezeSha256": checksum(cohort / "frozen.json")})
    rows = [json.loads(line) for line in numeric.read_text(encoding="utf-8").splitlines() if line]
    x = np.array([row["x"] for row in rows], dtype=np.float32)
    if x.shape != (len(rows), 14) or not np.isfinite(x).all() or np.any((x < 0) | (x > 8192)):
        raise ValueError("Invalid numeric test cohort")
    single = config["candidateOrder"][0]
    scores, thresholds, runtime = {}, {}, {}
    for name in config["candidateOrder"]:
        bundle, thresholds[name], resource = artifact(models, name, previous, single == name)
        scores[name] = predict(bundle, x)
        if not np.isfinite(scores[name]).all() or np.any((scores[name] < 0) | (scores[name] > 1)):
            raise ValueError("Invalid frozen model predictions")
        runtime[name] = resource | time_inference(bundle, x)
    cohorts = {}
    for name in ("external", "india-control", "bank-token-stratum"):
        mask = np.array([row["cohort"] == name or (name == "bank-token-stratum" and row["cohort"] == "external"
                         and (row["brand"] == "bank-token" or row["y"] == 0)) for row in rows])
        if mask.any():
            represented = [row for row, retained in zip(rows, mask, strict=True) if retained]
            cohorts[name] = compare(represented, {k: v[mask] for k, v in scores.items()}, thresholds, config)
    primary = str(config["primaryDomainTarget"])
    private_cases = []
    old = scores[single] >= thresholds[single][primary]
    for name in config["candidateOrder"][1:]:
        new = scores[name] >= thresholds[name][primary]
        for index in np.flatnonzero(old != new):
            item = rows[index]
            private_cases.append({"id": item["id"], "cohort": item["cohort"], "brand": item["brand"],
                                  "source": item["source"], "label": item["y"],
                                  "singleFlagged": bool(old[index]), "fusionFlagged": bool(new[index]), "candidate": name})
    write(output / "paired-cases.json", private_cases)
    report = {
        "freeze": frozen, "caseFileSha256": checksum(output / "paired-cases.json"),
        "indianCoverage": {"verifiedPhishing": 0, "officialControlsByBrand":
                           dict(Counter(row["brand"] for row in rows if row["cohort"] == "india-control"))},
        "cohorts": cohorts, "frozenCutoffs": thresholds, "runtime": runtime,
        "reputation": {"status": "unsupported", "reason": "No independent time-valid historical snapshots"},
        "incrementalOverFullProtection": None,
        "realisticPrevalence": {"status": "unsupported", "reason": "Case-control sources lack traffic prevalence"},
    }
    write(output / "summary.json", report)
    print(json.dumps({"cohorts": {k: v["support"] for k, v in cohorts.items()}, "privatePairedRecords": len(private_cases)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("cohort", "models", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get("THREAT_PHASE3D_GUARDED") != "1":
        parser.error("Run inside the Windows resource guard")
    with threadpool_limits(limits=1):
        execute(*(private(path) for path in (args.cohort, args.models, args.output)))


if __name__ == "__main__":
    main()
