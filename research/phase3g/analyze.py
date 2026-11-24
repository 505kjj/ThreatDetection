"""Audit the frozen Phase 3F archive without fitting models or selecting cutoffs."""

import argparse
from collections import Counter
from itertools import combinations
import json
import os
from pathlib import Path
import subprocess
import sys

import numpy as np
from scipy.stats import ks_2samp
from threadpoolctl import threadpool_limits

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "research/phase3e"))
from cohort import checksum, private, read, write
from score import artifact, exact_interval, metrics, pair_difference
from phase3d.benchmark import load, predict, prepare, train_data

OLD = ROOT / "docs/experiments/phase3f/summary.json"
DEVELOPMENT = ROOT / "docs/experiments/phase3d/summary.json"
PLAN = ROOT / "research/phase3f/protocol.json"
LEVELS = ("0.001", "0.01")


def verify_reproduction(receipt, reproduction, published):
    if set(reproduction) != set(published):
        raise ValueError("Reproduction schema differs")
    for key in sorted(set(published) - {"runtime"}):
        if reproduction[key] != published[key]:
            raise ValueError(f"Phase 3F reproduction differs in {key}")
    for name, runtime in published["runtime"].items():
        if any(reproduction["runtime"][name][k] != runtime[k] for k in ("sha256", "storageBytes")):
            raise ValueError("Reproduced model identity differs")
    if receipt["manifestSha256"] is None:
        raise ValueError("Missing reproduction receipt")


def direct_probability(model, rows):
    if list(model.classes_) != [0, 1]:
        raise ValueError("Frozen positive-label mapping differs")
    return model.predict_proba(rows)[:, 1].astype(np.float64)


def audit_scoring(bundle, data):
    columns = tuple(bundle["columns"])
    initial = data[:, columns]
    for model in bundle["models"]:
        if model.n_features_in_ != len(columns):
            raise ValueError("Base model width differs")
        if hasattr(model, "named_steps"):
            scaler = model.named_steps["standardscaler"]
            if scaler.mean_.shape != (len(columns),) or not np.isfinite(scaler.scale_).all() or np.any(scaler.scale_ <= 0):
                raise ValueError("Frozen standardization is invalid")
    members = [direct_probability(model, initial) for model in bundle["models"]]
    if bundle["mode"] == "single":
        reference, = members
    elif bundle["mode"] == "stack":
        reference = direct_probability(bundle["stack"], np.column_stack(members))
    elif bundle["mode"] == "blend":
        weights = np.asarray(bundle["weights"])
        if (len(weights) != len(members) or len(weights) != len(bundle["calibrators"])
                or np.any(weights < 0) or not np.isclose(weights.sum(), 1, atol=1e-12, rtol=0)):
            raise ValueError("Frozen blend weights are invalid")
        calibrated = [direct_probability(calibrator, score[:, None])
                      for calibrator, score in zip(bundle["calibrators"], members, strict=True)]
        reference = sum(weight * score for weight, score in zip(weights, calibrated, strict=True))
    else:
        raise ValueError("Unknown artifact mode")
    observed = predict(bundle, data)
    if not np.isfinite(observed).all() or np.any((observed < 0) | (observed > 1)):
        raise ValueError("Frozen scores are invalid")
    np.testing.assert_allclose(reference, observed, rtol=0, atol=1e-12)
    return observed, float(np.max(np.abs(reference - observed)))


def distribution(values, probability=False):
    if not len(values):
        return None
    quantiles = (10, 50, 90, 99) if probability else (10, 50, 90)
    return {
        "count": len(values), **{f"p{q}": round(float(v), 6)
                                for q, v in zip(quantiles, np.percentile(values, quantiles), strict=True)},
        "fractionZero": round(float(np.mean(values == 0)), 6),
    }


def summarize_columns(x, names):
    return {name: distribution(x[:, index]) for index, name in enumerate(names)}


def part(values, upper, labels):
    return np.asarray(labels)[np.searchsorted(upper, values, side="right")]


def feature_groups(x, extras, names):
    f = {name: x[:, index] for index, name in enumerate(names)}
    host_digits, path_digits = f["host_digits"] > 0, f["path_digits"] > 0
    raw_tld = np.array([row["tld"] for row in extras])
    if any(not isinstance(row["tld"], str) or len(row["tld"]) > 24 for row in extras):
        raise ValueError("Descriptor suffix is invalid")
    top = sorted(Counter(raw_tld).items(), key=lambda item: (-item[1], item[0]))
    published_tlds = {key for key, count in top if count >= 40 and key != "other"}
    # Publish the six biggest buckets with enough support. Remaining labels share "other".
    published_tlds = {key for key, _ in [item for item in top if item[0] in published_tlds][:6]}
    return {
        "canonicalUrlLength": part([r["canonicalLength"] for r in extras], [40, 80, 150],
                                   ["under-40", "40-79", "80-149", "150-plus"]),
        "hostnameLength": part(f["hostname_length"], [16, 25, 40], ["under-16", "16-24", "25-39", "40-plus"]),
        "subdomains": part(f["subdomain_labels"], [1, 2], ["none", "one", "two-plus"]),
        "digits": np.select([host_digits & path_digits, host_digits, path_digits],
                            ["host-and-path", "host-only", "path-only"], default="none"),
        "pathLength": part(f["path_length"], [1, 40, 80], ["root", "1-39", "40-79", "80-plus"]),
        "pathPunctuation": np.where([r["pathPunctuation"] > 0 for r in extras], "any", "none"),
        "hostnameHyphen": np.where(f["host_hyphens"] > 0, "any", "none"),
        "pathPercentEscape": np.where(f["path_percent_escapes"] > 0, "any", "none"),
        "topLevelDomain": np.where(np.isin(raw_tld, list(published_tlds)), raw_tld, "other"),
    }


def supports(calls):
    n = len(calls)
    hits = int(calls.sum())
    return {"count": n, "detected": hits, "missed": n - hits, "recall": hits / n if n else None,
            "exact95": exact_interval(hits, n)}


def overlap(decisions, groups, plan):
    order = list(decisions)
    matrix = np.column_stack(list(decisions.values()))
    patterns = Counter("".join("1" if v else "0" for v in row) for row in matrix)
    result = {}
    for a, b in combinations(order, 2):
        pair = pair_difference(np.ones(len(groups)), groups, decisions[a], decisions[b],
                               plan["limits"]["pairedBootstrapResamples"], plan["limits"]["seed"])
        result[f"{a}/{b}"] = {
            "bothDetected": int(np.sum(decisions[a] & decisions[b])),
            "bothMissed": pair["sharedErrors"], "leftOnly": pair["lostPhish"], "rightOnly": pair["extraPhish"],
            "errorCorrelation": pair["errorCorrelation"], "rightMinusLeftRecall95": pair["pairedRecallDeltaDomainBootstrap95"],
        }
    return {"modelOrder": order, "decisionPatterns": dict(sorted(patterns.items())), "pairs": result}


def reference_sets(out, uci, phase3d, published):
    phresh = phase3d / "phresh"
    if read(phresh / "manifest.json") != published["dataset"]:
        raise ValueError("Phase 3D reference dataset manifest differs")
    # This existing entry point rebuilds development arrays. It neither reads the final test nor fits anything.
    prepare(out, uci, phresh)
    for name in ("uci", "phresh", "validation"):
        rebuilt = load(out / f"prepared/{name}.npz")
        baseline = load(phase3d / f"prepared/{name}.npz")
        for field in ("x", "y", "groups", "families"):
            np.testing.assert_array_equal(getattr(rebuilt, field), getattr(baseline, field))
    rf = train_data(out, "phresh", 20000)
    fusion = train_data(out, "mixed", 20000)
    validation = load(out / "prepared/validation.npz")
    return {"forestTrainingPositive": rf.x[rf.y == 1, :14],
            "fusionTrainingPositive": fusion.x[fusion.y == 1, :14],
            "calibrationPositive": validation.x[validation.y == 1, :14]}, validation


def execute(args):
    old = read(OLD)
    published = read(DEVELOPMENT)
    plan = read(PLAN)
    reproduction = private(args.reproduction)
    cohort, output = map(private, (args.cohort, args.output))
    manifest = read(cohort / "manifest.json")
    previous_check = checksum(cohort / "manifest.json")
    receipt = read(cohort / "scoring-receipt.json")
    if (receipt["manifestSha256"] != previous_check or manifest != old["manifest"]
            or checksum(cohort / "numeric.jsonl") != manifest["numericSha256"]):
        raise ValueError("Phase 3F cohort does not match its frozen receipt")
    verify_reproduction(receipt, read(reproduction / "summary.json"), old)
    if checksum(reproduction / "private-disagreements.json") != old["privateDisagreementReportSha256"]:
        raise ValueError("Reproduced individual decisions differ")
    output.mkdir()
    extra_file = output / "private-descriptors.jsonl"
    cmd = ["node", str(Path(__file__).with_name("describe.mjs")), str(cohort), str(private(args.ledger)), str(extra_file)]
    subprocess.run(cmd, check=True)
    rows = [item for line in (cohort / "numeric.jsonl").read_text(encoding="utf-8").splitlines()
            if (item := json.loads(line))["cohort"] == "general-transfer"]
    extras = [json.loads(line) for line in extra_file.read_text(encoding="utf-8").splitlines()]
    for row, facts in zip(rows, extras, strict=True):
        if row["id"] != facts["id"] or row["y"] != 1:
            raise ValueError("Archive descriptors do not match expected rows")
    x = np.array([row["x"] for row in rows], dtype=np.float32)
    groups = np.array([row["group"] for row in rows])
    names = manifest["featureColumns"]
    if len(rows) != 2000 or len(set(groups)) != 2000 or x.shape != (2000, 14):
        raise ValueError("The analysis requires the full frozen archive")
    references, validation = reference_sets(output, private(args.uci), private(args.phase3d), published)
    buckets = feature_groups(x, extras, names)
    archive_controls, stage_results, reductions = {}, {level: {} for level in LEVELS}, {}
    for index, name in enumerate(plan["candidateOrder"]):
        bundle, thresholds, identity = artifact(private(args.models), name, published, single=index == 0)
        if thresholds != old["frozenCutoffs"][name] or identity["sha256"] != old["runtime"][name]["sha256"]:
            raise ValueError("Phase 3F artifacts or cutoffs changed")
        frozen_probabilities, error = audit_scoring(bundle, x)
        validation_scores = predict(bundle, validation.x[:, :14])
        if not thresholds[LEVELS[0]] > thresholds[LEVELS[1]]:
            raise ValueError("Invalid cutoff ordering")
        details = {
            "modelArtifactSha256": identity["sha256"], "usedFeatures": [names[column] for column in bundle["columns"]],
            "fittedPreprocessors": [step for member in bundle["models"] if hasattr(member, "named_steps")
                                    for step in member.named_steps],
            "scoreReconstructionMaxAbsError": error,
            "scoreDistribution": {
                "archive": distribution(frozen_probabilities, True),
                "calibrationPhishing": distribution(validation_scores[validation.y == 1], True),
                "calibrationLegitimate": distribution(validation_scores[validation.y == 0], True),
            },
            "operatingPoints": {},
        }
        for level in LEVELS:
            choice = thresholds[level]
            decisions = frozen_probabilities >= choice
            stage_results[level][name] = decisions
            previous = old["cohorts"]["general-transfer"]["candidates"][name]["cutoffs"][level]["metrics"]
            summary = supports(decisions)
            if (summary["detected"], summary["missed"]) != (previous["tp"], previous["fn"]):
                raise ValueError("Archive threshold counts did not reproduce")
            validation_metric = metrics(validation.y, validation.groups, validation_scores, choice)
            fitted = published["candidates"][name]["fit"]
            original_validation = next(item for item in fitted["validationAtCutoffs"]
                                       if item and item["threshold"] == choice)
            for key in ("tp", "tn", "fp", "fn", "falseAlertDomains"):
                if validation_metric[key] != original_validation[key]:
                    raise ValueError("Archived Phase 3D validation decisions differ")
            details["operatingPoints"][level] = summary | {
                "savedCutoff": choice,
                "within005BelowCutoff": int(np.sum((frozen_probabilities < choice) & (frozen_probabilities >= choice - .05))),
                "calibrationPositive": supports(validation_scores[validation.y == 1] >= choice),
                "featureGroups": {group: {str(bucket): supports(decisions[assignment == bucket])
                                          for bucket in sorted(set(assignment))}
                                  for group, assignment in buckets.items()},
            }
        primary = stage_results[LEVELS[0]][name]
        reductions[name] = {
            "detected": summarize_columns(x[primary], names), "missed": summarize_columns(x[~primary], names),
        }
        archive_controls[name] = details
    score_drift = {name: {feature: round(float(ks_2samp(x[:, index], reference[:, index]).statistic), 6)
                          for index, feature in enumerate(names)} for name, reference in references.items()}
    cases = output / "private-case-outcomes.jsonl"
    with cases.open("x", encoding="utf-8", newline="\n") as stream:
        for i, row in enumerate(rows):
            data = {"evidenceId": row["id"], "byCutoff": {
                level: [name for name, calls in stage_results[level].items() if calls[i]] for level in LEVELS}}
            stream.write(json.dumps(data) + "\n")
    summary = {
        "input": {"phase3fSummarySha256": checksum(OLD), "frozenManifestSha256": previous_check,
                  "numericSha256": manifest["numericSha256"], "archiveRows": len(rows), "distinctDomains": len(set(groups)),
                  "calibrationPhishingRows": int(np.sum(validation.y == 1)),
                  "calibrationLegitimateRows": int(np.sum(validation.y == 0))},
        "baselineReproduced": True, "featureVectorsReprojected": len(rows), "calibrationDecisionsReproduced": True,
        "candidates": archive_controls, "overlap": {k: overlap(v, groups, plan) for k, v in stage_results.items()},
        "archiveFeatureDistributions": summarize_columns(x, names) | {
            "canonicalUrlLength": distribution(np.array([r["canonicalLength"] for r in extras])),
            "pathPunctuation": distribution(np.array([r["pathPunctuation"] for r in extras])),
        },
        "primaryDetectedMissedDistributions": reductions,
        "developmentPositiveDistributions": {k: summarize_columns(v, names) for k, v in references.items()},
        "featureKsDistancesFromArchive": score_drift,
        "privateCaseReportSha256": checksum(cases),
    }
    write(output / "summary.json", summary)
    print("Verified Phase 3F reprojection, Phase 3D reference cohorts and all unchanged cutoff decisions.", flush=True)


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    for name in ("cohort", "ledger", "reproduction", "uci", "phase3d", "models", "output"):
        cli.add_argument("--" + name, type=Path, required=True)
    args = cli.parse_args()
    if os.environ.get("THREAT_PHASE3D_GUARDED") != "1":
        cli.error("Run through the Windows research resource guard")
    with threadpool_limits(limits=1):
        execute(args)


if __name__ == "__main__":
    main()
