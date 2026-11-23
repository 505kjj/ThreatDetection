"""Verify the saved Phase 3D artifacts and render compact reporting outputs."""

import argparse
from hashlib import file_digest
import importlib.metadata
import json
import os
from pathlib import Path
import platform

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


ROOT = Path(__file__).resolve().parents[2]


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def digest(path):
    with path.open("rb") as stream:
        return file_digest(stream, "sha256").hexdigest()


def summary(run):
    plan = read(run / "frozen.json")
    config = Path(__file__).with_name("plan.json")
    projection = read(run / "phresh/manifest.json")
    marker = read(run / "final/opened.json")
    if (digest(config) != plan["configSha256"] or marker["planSha256"] != digest(run / "frozen.json")
            or marker["testSha256"] != plan["testSha256"]
            or digest(run / "phresh/test.tsv") != plan["testSha256"]):
        raise ValueError("Saved final plan and cohort no longer match")
    resources = {p.stem: read(p) for p in sorted((run / "resources").glob("*.json"))}
    resources["projection"] = read(run / "projection-final-resources.json")
    if any(item["exitCode"] or item["resourceViolations"] for item in resources.values()):
        raise ValueError("A saved job failed or exceeded policy")
    records = {}
    for name, checksum in plan["candidates"].items():
        directory = run / "candidates" / name
        validation = directory / "validation.json"
        if digest(validation) != checksum:
            raise ValueError("Validation report checksum does not match frozen plan")
        fit = read(validation)
        if digest(directory / "model.joblib") != fit["artifactSha256"]:
            raise ValueError("Local model no longer matches frozen digest")
        final = read(run / "final" / (name + ".json"))
        if final["candidate"] != name:
            raise ValueError("Test report candidate mismatch")
        observed = final["testAtHalf"]
        if (observed["tp"] + observed["fn"] != projection["partitions"]["test"]["phishing"]
                or observed["tn"] + observed["fp"] != projection["partitions"]["test"]["legitimate"]):
            raise ValueError("Test confusion matrix counts differ from the reserved test")
        records[name] = {"fit": fit, "final": final}
    return {
        "plan": plan,
        "configuration": read(config),
        "dataset": projection,
        "preparedTrainingDomains": read(run / "prepared/capacity.json"),
        "versions": {"python": platform.python_version(), **{name: importlib.metadata.version(name)
                     for name in ("numpy", "scipy", "scikit-learn", "xgboost-cpu", "joblib", "matplotlib")}},
        "resources": resources,
        "candidates": records,
    }


def learning_curves(report, path):
    colors = ("#1f77b4", "#f28e2b", "#228b60")
    fig, axes = plt.subplots(2, 2, figsize=(9, 6), sharex=True, sharey=True, layout="constrained")
    cohorts = report["plan"]["completedScales"]
    cohort = "mixed" if len(cohorts["mixed"]) > 1 else max(cohorts, key=lambda name: len(cohorts[name]))
    sizes = cohorts[cohort]
    for axis, model in zip(axes.flat, report["configuration"]["models"], strict=True):
        records = [report["candidates"][f"{cohort}-{size}-host-{model}"] for size in sizes]
        series = [
            ("Training", [r["fit"]["trainingAP"] for r in records]),
            ("Development validation", [r["fit"]["validation"]["prAucAveragePrecision"] for r in records]),
            ("Frozen external test", [r["final"]["test"]["prAucAveragePrecision"] for r in records]),
        ]
        axis.set_xscale("log")
        axis.set_xticks(sizes, [f"{size // 1000}k" for size in sizes])
        axis.set_title({"logistic": "Logistic Regression", "forest": "Random Forest",
                        "xgboost": "XGBoost", "mlp": "Small MLP"}[model])
        axis.grid(alpha=0.25)
        for (label, values), color in zip(series, colors, strict=True):
            axis.plot(sizes, values, marker="o", color=color, label=label, linewidth=1.8)
    handles, labels = axes[0, 0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="outside upper center", ncols=3, frameon=False,
               title=f"Phase 3D hostname model scaling ({cohort} cohort)")
    fig.supxlabel("Balanced training URLs (log scale)")
    fig.supylabel("Average precision")
    fig.savefig(path, dpi=150)
    plt.close(fig)


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--run", type=Path, required=True)
    args = cli.parse_args()
    if os.environ.get("THREAT_PHASE3D_GUARDED") != "1":
        cli.error("Use the Phase 3D resource guard")
    run = args.run.resolve()
    if run.is_relative_to(ROOT):
        cli.error("Use a private run directory")
    report = summary(run)
    with (run / "summary.json").open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, allow_nan=False, separators=(",", ":"))
        stream.write("\n")
    learning_curves(report, run / "learning-curves.png")


if __name__ == "__main__":
    main()
