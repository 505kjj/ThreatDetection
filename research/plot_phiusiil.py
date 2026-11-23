"""Render the cross-validation learning and early-stopping curves from aggregate data."""

import argparse
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter

from experiment_data import read_json


TITLES = {
    "logistic_regression": "Logistic regression", "random_forest": "Random forest",
    "xgboost": "XGBoost", "mlp": "Small MLP",
}
COLORS = ("#526274", "#136f67")


def plot_curves(report, output):
    scores = report["crossValidation"]
    fig, panels = plt.subplots(2, 2, figsize=(9, 6.4), sharey=True, layout="constrained")
    fig.suptitle("Phishing URL learning curves · PhiUSIIL", fontsize=16, fontweight="bold")
    for axis, (name, title) in zip(panels.flat, TITLES.items(), strict=True):
        points = scores[name]["learningCurveOuterFold1"]
        n = [point["trainingRows"] for point in points]
        for (key, label), color in zip([("trainingAveragePrecision", "Outer training"),
                                         ("validationAveragePrecision", "Grouped validation")], COLORS, strict=True):
            axis.plot(n, [point[key] for point in points], marker="o", color=color, label=label, linewidth=2)
        axis.set_title(title, loc="left", fontweight="bold")
        axis.xaxis.set_major_formatter(FuncFormatter(lambda value, _: f"{value / 1000:.0f}k"))
        axis.set_xticks(n)
        axis.grid(axis="y", color="#dbe3e8")
    panels[0, 0].legend(loc="upper right", frameon=False)
    fig.supxlabel("Outer training rows (nested registrable-domain subsets)")
    fig.supylabel("Average precision")
    fig.savefig(output / "learning-curves.png", dpi=150)
    plt.close(fig)

    fig, panels = plt.subplots(1, 2, figsize=(9, 3.8), layout="constrained")
    fig.suptitle("Group-isolated early stopping · outer fold 1", fontsize=15, fontweight="bold")
    for axis, name in zip(panels, ("xgboost", "mlp"), strict=True):
        trace = scores[name]["earlyStopTraceOuterFold1"]
        candidate = scores[name]["candidates"][scores[name]["selectedCandidate"]]
        rounds = candidate["folds"][0]["selectedRounds"]
        for (key, label), color in zip([("fitLogLoss", "Inner fit"),
                                         ("stopLogLoss", "Inner stopping")], COLORS, strict=True):
            values = trace[key]
            axis.plot(range(1, len(values) + 1), values, color=color, label=label, linewidth=2)
        axis.axvline(rounds, color="#9e5722", linewidth=1.4, linestyle="--", label="Selected step")
        axis.set_title(TITLES[name], loc="left", fontweight="bold")
        axis.set_xlabel("Boosting round" if name == "xgboost" else "Epoch")
        axis.set_ylabel("Log loss")
        axis.grid(axis="y", color="#dbe3e8")
    panels[0].legend(frameon=False)
    fig.savefig(output / "early-stopping.png", dpi=150)
    plt.close(fig)


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--development-report", type=Path, required=True)
    cli.add_argument("--output-dir", type=Path, required=True)
    args = cli.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    plot_curves(read_json(args.development_report), args.output_dir)
