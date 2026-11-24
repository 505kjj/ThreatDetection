"""Run and compare matched Phase 5C model workers under separate Windows jobs."""

import argparse
import json
from pathlib import Path
import sys

from paths import private
from train import MODELS

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "phase3d"))
from resource_guard import run as guarded_run


def run(cohort, size, output):
    preflight = size == 1000
    worker = Path(__file__).with_name("train.py")
    output.mkdir(mode=0o700)
    combined = []
    identity = None
    for model in MODELS:
        target = output / model
        command = [sys.executable, "-u", str(worker), str(cohort), str(size), model, str(target)]
        if preflight:
            command.append("--preflight")
        resources = guarded_run(command)
        (output / (model + "-resources.json")).write_text(json.dumps(resources, indent=2), encoding="utf-8")
        if resources["exitCode"] or resources["resourceViolations"] or resources["logicalCpuAffinityCount"] != 2:
            raise RuntimeError(f"{model} worker failed the resource or completion check")
        report = json.loads((target / "result.json").read_bytes())
        matches = {"cohort": report["cohortSha256"], "train": report["trainIdsSha256"],
                   **{key: value["idsSha256"] for key, value in report["evaluation"].items()}}
        if identity is None:
            identity = matches
        if identity != matches:
            raise ValueError("Model workers used different cohort members")
        combined.append(report | {"resources": resources})
    (output / "summary.json").write_text(json.dumps(combined, indent=2, allow_nan=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cohort", type=private)
    parser.add_argument("size", type=int, choices=(1000, 20000, 50000, 100000))
    parser.add_argument("output", type=private)
    args = parser.parse_args()
    run(args.cohort, args.size, args.output)
