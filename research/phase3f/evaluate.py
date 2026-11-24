"""Evaluate four frozen research artifacts on separately reported external cohorts."""

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import sys

import numpy as np
from threadpoolctl import threadpool_limits

ROOT = Path(__file__).resolve().parents[2]
PROTOCOL = Path(__file__).with_name("protocol.json")
PHASE3D = ROOT / "docs/experiments/phase3d/summary.json"
PHASE3E = ROOT / "docs/experiments/phase3e/summary.json"
sys.path.insert(0, str(ROOT / "research/phase3e"))

from cohort import checksum, private, read, write
from score import artifact, compare, time_inference
from phase3d.benchmark import predict


def suppress_single_class(result):
    """Precision, F1 and AP on a one-class convenience sample are not efficacy estimates."""
    support = result["support"]
    if support["phishing"] and support["legitimate"]:
        return result
    matrices = [result["brandAmber"]]
    for candidate in result["candidates"].values():
        matrices.extend(point[key] for point in candidate["cutoffs"].values()
                        for key in ("metrics", "advisoryOnlyUnionMetrics"))
    for matrix in matrices:
        for key in ("precision", "f1", "precisionBinomial95"):
            matrix[key] = None
    return result


def detection_counts(scores, thresholds, labels, plan):
    primary = str(plan["primaryDomainTarget"])
    secondary = str(plan["secondaryDomainTarget"])
    first, *fusion = plan["candidateOrder"]
    labels = labels.astype(bool)
    output = {}
    for point in (primary, secondary):
        decisions = {name: scores[name] >= thresholds[name][point] for name in plan["candidateOrder"]}
        any_fusion = np.logical_or.reduce([decisions[name] for name in fusion])
        output[point] = {
            "missedByAll": int((labels & ~decisions[first] & ~any_fusion).sum()),
            "detectedOnlyByAnyFusion": int((labels & ~decisions[first] & any_fusion).sum()),
            "detectedOnlyByRandomForest": int((labels & decisions[first] & ~any_fusion).sum()),
        }
    return output


def disagreement_cases(rows, scores, thresholds, plan):
    point = str(plan["primaryDomainTarget"])
    first, *fusion = plan["candidateOrder"]
    calls = {name: scores[name] >= thresholds[name][point] for name in plan["candidateOrder"]}
    stable = np.logical_and.reduce([calls[first] == calls[name] for name in fusion])
    for index, row in enumerate(rows):
        if not stable[index] or (row["y"] and not calls[first][index]):
            yield {"evidenceId": row["id"], "cohort": row["cohort"], "source": row["source"],
                   "label": row["y"], "calls": {name: bool(values[index]) for name, values in calls.items()}}


def execute(cohort, models, output):
    plan, prior, earlier = map(read, (PROTOCOL, PHASE3D, PHASE3E))
    manifest = read(cohort / "manifest.json")
    data = cohort / "numeric.jsonl"
    expected = {
        "protocolSha256": checksum(PROTOCOL), "phase3dSummarySha256": checksum(PHASE3D),
        "phase3eSummarySha256": checksum(PHASE3E), "numericSha256": checksum(data),
        "featureVersion": plan["featureVersion"], "featureColumns": prior["dataset"]["featureColumns"],
    }
    if any(manifest[key] != value for key, value in expected.items()):
        raise ValueError("Frozen file or schema digest differs")
    bundles, cutoffs, runtime = {}, {}, {}
    for index, name in enumerate(plan["candidateOrder"]):
        bundle, cutoff, activity = artifact(models, name, prior, single=index == 0)
        if (cutoff != earlier["frozenCutoffs"][name]
                or activity["sha256"] != earlier["runtime"][name]["sha256"]):
            raise ValueError("Candidate differs from Phase 3E")
        bundles[name], cutoffs[name], runtime[name] = bundle, cutoff, activity
    output.mkdir()
    write(cohort / "scoring-receipt.json", {"manifestSha256": checksum(cohort / "manifest.json")})
    rows = [json.loads(line) for line in data.read_text(encoding="utf-8").splitlines() if line]
    x = np.array([row["x"] for row in rows], dtype=np.float32)
    if x.shape != (len(rows), 14) or not np.isfinite(x).all() or np.any((x < 0) | (x > 8192)):
        raise ValueError("Invalid numeric cohort")
    probabilities = {}
    for name, bundle in bundles.items():
        scores = predict(bundle, x)
        if not np.isfinite(scores).all() or np.any((scores < 0) | (scores > 1)):
            raise ValueError("Invalid frozen probabilities")
        probabilities[name] = scores
        # Keep candidate-level performance measurements if the next stage is interrupted.
        runtime[name] |= time_inference(bundle, x)
        write(output / (name + "-runtime.json"), runtime[name])
    cohorts = {}
    for name in ("general-transfer", "india-control"):
        mask = np.array([row["cohort"] == name for row in rows])
        if not mask.any():
            continue
        members = [row for row, belongs in zip(rows, mask, strict=True) if belongs]
        scores = {key: values[mask] for key, values in probabilities.items()}
        finding = suppress_single_class(compare(members, scores, cutoffs, plan))
        finding["countsByKind"] = dict(Counter(row["kind"] for row in members))
        finding["knownCampaignIds"] = 0
        finding["observedLexicalFamilies"] = len({row["family"] for row in members if row["family"]})
        if name == "india-control":
            finding["controlsByBrand"] = dict(Counter(row["brand"] for row in members))
        else:
            finding["jointDetections"] = detection_counts(
                scores, cutoffs, np.array([row["y"] for row in members]), plan)
        cohorts[name] = finding
    cases = output / "private-disagreements.json"
    write(cases, list(disagreement_cases(rows, probabilities, cutoffs, plan)))
    result = {
        "manifest": manifest, "frozenCutoffs": cutoffs, "cohorts": cohorts, "runtime": runtime,
        "privateDisagreementReportSha256": checksum(cases),
        "financialPhishing": {"indianVerified": 0, "nonIndianVerified": 0},
        "historicalReputation": {"status": "unsupported", "reason": "No independent time-valid snapshot for either cohort"},
        "incrementalOverCombinedRules": None,
    }
    write(output / "summary.json", result)
    print(json.dumps({name: finding["support"] for name, finding in cohorts.items()}), flush=True)


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    for item in ("cohort", "models", "output"):
        cli.add_argument("--" + item, type=Path, required=True)
    args = cli.parse_args()
    if os.environ.get("THREAT_PHASE3D_GUARDED") != "1":
        cli.error("Run through the Windows research resource guard")
    with threadpool_limits(limits=1):
        execute(*(private(path) for path in (args.cohort, args.models, args.output)))


if __name__ == "__main__":
    main()
