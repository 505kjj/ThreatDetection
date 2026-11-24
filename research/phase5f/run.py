"""Run research-only Phase 5F on the pinned Phase 5E development views."""

import argparse
from collections import Counter
import json
import os

import numpy as np
from threadpoolctl import threadpool_limits

from replay import (ROOT, balanced, control_results, fixture_rows, hash_file, ids_sha256, load_models,
                    predict_models, read, replay, thresholds, upstream_controls, verify)
from compare import load_matched
from evaluate import load_partition, private
from grouping import collision_audit, grouped_views, signatures
from fusion_lab import (Lab, auth, explanations, latency, ngram_explanations, operating_summary,
                        selective_outcomes, strata, valid_content)
from metrics import evaluate, labels


def unavailable(cohort, projections, partition):
    failures = {}
    for directory in projections:
        for spec in read(directory / "manifest.json")["completedShards"]:
            with (directory / spec["file"]).open(encoding="utf-8") as stream:
                for line in stream:
                    row = json.loads(line)
                    if row["partition"] == partition and row["status"] != "usable":
                        failures[row["id"]] = row["status"]
    rows = load_partition(cohort, read(cohort / "manifest.json"), partition)
    return [row | {"contentStatus": failures[row["id"]]} for row in rows if row["id"] in failures]


def score_grouped(pools, unavailable_rows, fixtures, result_dir):
    grouped, grouping = grouped_views(pools)
    counts = Counter(row["label"] for row in grouped["train"])
    size = min(10000, *[counts[label] for label in (0, 1)]) * 2
    if size < 1000 or any(len(set(labels(grouped[part]))) != 2 for part in ("tuning", "calibration", "validation")):
        raise ValueError("Structural grouping left insufficient development support")
    train = balanced(grouped["train"], size)
    tuning, calibration, validation = (grouped[part] for part in ("tuning", "calibration", "validation"))
    lab = Lab(train, tuning, result_dir)
    print(f"Fitted grouped models on {len(train)} class-balanced rows", flush=True)
    tuning_scores, _ = lab.score(tuning)
    cal_scores, _ = lab.score(calibration)
    validation_scores, routed = lab.score(validation)
    candidates = ("url-ngram", "url-blend", "url-xgboost")
    # Determine the reference on tuning. The operating thresholds below are calibration-only.
    tuning_results = {name: evaluate(tuning, tuning_scores[name], thresholds(tuning, tuning_scores[name]),
                                    with_intervals=False) for name in candidates}
    def selection_key(name):
        point = tuning_results[name]["atConstraints"]["0.01"]
        return (-1 if point is None else point["recall"], tuning_results[name]["prAucAveragePrecision"])
    strongest = max(candidates, key=selection_key)
    cuts = {name: thresholds(calibration, values) for name, values in cal_scores.items()}
    evaluation = {name: evaluate(validation, values, cuts[name]) for name, values in validation_scores.items()}
    fixture_scores, fixture_routes = lab.score(fixtures)
    missing_scores, missing_route = lab.score(validation + unavailable_rows)
    inclusive = validation + unavailable_rows
    one_percent = cuts["selective"]["0.01"]["threshold"]
    references = {key: operating_summary(validation, validation_scores, cuts, key)
                  for key in ("url-ngram", "url-blend", "adaptive")}
    missing_summary = {}
    if unavailable_rows and len(set(labels(unavailable_rows))) == 2:
        start = len(validation)
        missing_summary = {key: evaluate(unavailable_rows, missing_scores[key][start:], cuts[key], with_intervals=False)
                           for key in (strongest, "selective")}
    return {"grouping": grouping, "rows": {"train": len(train), "tuning": len(tuning),
            "calibration": len(calibration), "validation": len(validation)},
            "memberships": {name: ids_sha256(rows) for name, rows in (grouped | {"train": train}).items()},
            "fit": lab.fit, "fusionFit": lab.fusion_metadata, "checkpointBytes": lab.artifact_sizes,
            "weightedBenignTrainingRows": sum(not row["label"] and auth(row) for row in train),
            "strongestUrlOnlyOnTuning": strongest, "tuningSelection": tuning_results,
            "thresholds": cuts, "evaluation": evaluation, "pairedComparisonsByReference": references,
            "diagnosticControls": control_results(fixtures, fixture_scores, cuts),
            "diagnosticRouting": {row["id"]: bool(route) for row, route in zip(fixtures, fixture_routes, strict=True)},
            "benignStrata": strata(validation, validation_scores, cuts),
            "explanations": {
                "weightedDom": explanations(lab, validation, validation_scores["dom-weighted"],
                                            cuts["dom-weighted"]["0.01"]["threshold"]),
                "urlNgram": ngram_explanations(lab, validation, validation_scores["url-ngram"],
                                              cuts["url-ngram"]["0.01"]["threshold"])},
            "latency": latency(lab, validation, validation_scores),
            "routing": {"matchedRouted": int(routed.sum()), "matchedRows": len(validation),
                        "inclusiveRouted": int(missing_route.sum()), "inclusiveRows": len(inclusive),
                        "attemptsWithoutUsableContent": int((missing_route & ~valid_content(inclusive)).sum()),
                        "unusableContentStatuses": dict(Counter(row["contentStatus"] for row in unavailable_rows)),
                        "unusableContentEvaluation": missing_summary,
                        "inclusiveUrlReference": evaluate(inclusive, missing_scores[strongest], cuts[strongest]),
                        "inclusiveSelective": evaluate(inclusive, missing_scores["selective"], cuts["selective"]),
                        "abstentionCurve": selective_outcomes(inclusive, missing_scores["selective"], one_percent,
                                                              missing_route, valid_content(inclusive))}}


def run(experiments, directory, replay_only):
    old = experiments / "phase-5e-v1"
    public = read(ROOT / "docs" / "experiments" / "phase5e" / "results.json")
    prior = read(old / "model-20k" / "results.json")
    verify(public["scale20k"], prior)
    if hash_file(old / "model-20k" / "membership.json") != prior["membershipSha256"]:
        raise ValueError("Private Phase 5E membership receipt differs")
    cohort = experiments / "phase-5c-v1" / "cohort"
    projections = [old / name for name in ("html-pilot-final", "html-20k")]
    pools, audit = load_matched(cohort, projections)
    verify(prior["audit"], audit)
    directory.mkdir()
    with threadpool_limits(limits=2):
        controls = list(fixture_rows())
        models = load_models(old / "model-20k", prior)
        reproduced = replay(models, prior, pools, public["sensitivity"], signatures)
        cuts = {name: spec["thresholds"] for name, spec in prior["models"].items()}
        scores = predict_models(models, prior, controls)
        diagnosis = control_results(controls, scores, cuts)
        for key, expected in public["syntheticControls"]["scale20k"]["fabricatedControls"].items():
            verify(expected, diagnosis["dom-xgboost"][key])
        report = {"replay": reproduced, "phase5eControls": diagnosis,
                  "upstreamFrozenUrlControls": upstream_controls(experiments, controls),
                  "phase5eBenignStrata": strata(pools["validation"], predict_models(models, prior, pools["validation"]), cuts),
                  "collisionAudit": collision_audit(balanced(pools["train"], prior["rows"]), pools["validation"])}
        if not replay_only:
            report["grouped"] = score_grouped(pools, unavailable(cohort, projections, "validation"), controls, directory)
    with (directory / "results.json").open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, allow_nan=False)
        stream.write("\n")
    print(f"Verified {len(reproduced['reproduced'])} frozen Phase 5E candidates and eight fixtures", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("experiments", type=private)
    parser.add_argument("directory", type=private)
    parser.add_argument("--replay-only", action="store_true")
    args = parser.parse_args()
    if os.environ.get("THREAT_PHASE3D_GUARDED") != "1":
        parser.error("Use the Windows Job Object resource guard")
    run(**vars(args))
