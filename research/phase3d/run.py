"""Execute the registered workload sequentially, freezing the final scoring plan."""

import argparse
from hashlib import file_digest
import json
from pathlib import Path
import sys
from time import sleep

from resource_guard import GIB, run as guarded_run


ROOT = Path(__file__).resolve().parents[2]
MODEL_WORKER = Path(__file__).with_name("benchmark.py")


def digest(path):
    with path.open("rb") as stream:
        return file_digest(stream, "sha256").hexdigest()


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def save(path, value):
    stage = path.with_suffix(".tmp")
    with stage.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")
    stage.replace(path)


def private(path):
    path = path.resolve()
    if path.is_relative_to(ROOT):
        raise ValueError("Run inputs and outputs must be outside Git")
    return path


def execute(run, name, *arguments):
    metrics = run / "resources" / (name + ".json")
    print(f"Starting {name}", flush=True)
    if metrics.exists():
        result = read(metrics)
    else:
        result = guarded_run([sys.executable, "-u", str(MODEL_WORKER), *map(str, arguments), "--run", str(run)])
        save(metrics, result)
        print(f"{name} resource usage: {json.dumps(result)}", flush=True)
        sleep(1)
    if result["exitCode"] or result["resourceViolations"]:
        raise RuntimeError(f"{name} stopped or exceeded the research budget; saved results are intact")
    return result


def run_plan(run, uci, phresh):
    config_path = Path(__file__).with_name("plan.json")
    config = read(config_path)
    (run / "resources").mkdir(exist_ok=True)
    (run / "candidates").mkdir(exist_ok=True)
    frozen_path = run / "frozen.json"
    if frozen_path.exists():
        raise RuntimeError("A frozen plan already exists; use the saved output for verification")
    execute(run, "prepare", "prepare", "--uci", uci, "--phresh", phresh)
    capacity = read(run / "prepared/capacity.json")
    limits = {key: 2 * min(counts.values()) for key, counts in capacity.items()}
    limits["mixed"] = 4 * min(min(counts.values()) for counts in capacity.values())
    previous = []
    skipped = []
    cohort_sizes = {name: [] for name in limits}
    candidates = {}

    def register(name):
        report = run / "candidates" / name / "validation.json"
        candidates[name] = digest(report)

    for count in config["sampleSizes"]:
        cohorts = ("mixed",) if count == config["sampleSizes"][0] else ("uci", "phresh", "mixed")
        for cohort in cohorts:
            if count > limits[cohort]:
                skipped.append({"cohort": cohort, "requestedRows": count, "maxBalancedRows": limits[cohort],
                                "reason": "insufficient unique, unambiguous training domains"})
                continue
            if count == 100000 and (not previous or any(
                    item["peakJobCommitBytes"] >= 4 * GIB or (item["hostCpuMeanPercent"] or 0) > 30
                    for item in previous)):
                skipped.append({"cohort": cohort, "requestedRows": count,
                                "reason": "smaller training levels did not leave the registered resource margin"})
                continue
            for model in config["models"]:
                name = f"{cohort}-{count}-host-{model}"
                previous.append(execute(run, name, "fit", "--cohort", cohort, "--count", count, "--model", model))
                register(name)
            cohort_sizes[cohort].append(count)
    # Use only validation AP to select the model for the paired PhreshPhish ablation.
    if cohort_sizes["phresh"]:
        ablation_cohort = "phresh"
        ablation_count = min(cohort_sizes["phresh"])
    elif limits["phresh"] >= config["sampleSizes"][0]:
        ablation_cohort = "phresh"
        ablation_count = config["sampleSizes"][0]
        for model in config["models"]:
            base = f"phresh-{ablation_count}-host-{model}"
            execute(run, base, "fit", "--cohort", "phresh", "--count", ablation_count, "--model", model)
            register(base)
    else:
        ablation_cohort = None
        skipped.append({"task": "feature ablation", "reason": "insufficient independent PhreshPhish training rows"})
    if ablation_cohort:
        selected = max(config["models"], key=lambda name: read(run / "candidates" /
                       f"{ablation_cohort}-{ablation_count}-host-{name}/validation.json")["validation"]["prAucAveragePrecision"])
        for feature in ("path", "brand"):
            name = f"{ablation_cohort}-{ablation_count}-{feature}-{selected}"
            execute(run, name, "fit", "--cohort", ablation_cohort, "--count", ablation_count,
                    "--model", selected, "--features", feature)
            register(name)
    if cohort_sizes["mixed"]:
        # Cap the 16 sequential fusion fits at 20k so the user's laptop can stay responsive.
        fusion_count = max(n for n in cohort_sizes["mixed"] if n <= config["fusionMaxRows"])
        execute(run, f"fusion-mixed-{fusion_count}", "fusion", "--cohort", "mixed", "--count", fusion_count)
        for name in ("two", "four", "stack"):
            register(f"fusion-mixed-{fusion_count}-{name}")
    else:
        skipped.append({"task": "fusion", "reason": "insufficient independent mixed-domain training rows"})
    if not candidates:
        raise RuntimeError("The validated inputs did not support any registered candidates")
    scored = {name: read(run / "candidates" / name / "validation.json") for name in candidates}
    preferred = max(scored, key=lambda name: (
        (scored[name]["validationAtCutoffs"][0] or {}).get("recall") or 0,
        scored[name]["validation"]["prAucAveragePrecision"], -scored[name]["modelBytes"],
    ))
    frozen = {
        "configSha256": digest(config_path), "testSha256": read(phresh / "manifest.json")["partitions"]["test"]["sha256"],
        "validationPreferred": preferred, "candidates": candidates, "skipped": skipped,
        "balancedCapacity": limits, "completedScales": cohort_sizes,
    }
    save(frozen_path, frozen)
    execute(run, "final", "final", "--phresh", phresh, "--plan", frozen_path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("run", "uci", "phresh"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    run_plan(private(args.run), private(args.uci), private(args.phresh))


if __name__ == "__main__":
    main()
