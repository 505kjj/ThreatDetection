"""Offline evaluation and dependence-aware uncertainty estimates."""

import json

import numpy as np
from scipy.stats import beta
from sklearn.metrics import brier_score_loss

from shared import SEED, ids_sha256, labels, protocol_bytes
from experiment_metrics import classify, negative_domain_scores, ranking, threshold_at_target

CONFIG = json.loads(protocol_bytes())
TARGETS = CONFIG["domainFprTargets"]


def group_labels(rows):
    return np.array([row["identity"]["group"] for row in rows])


def cutoffs(y, scores, groups):
    negative = negative_domain_scores(y, scores, groups)
    return {str(target): threshold_at_target(negative, target, CONFIG["calibrationRisk"]) for target in TARGETS}


def calibration(y, scores):
    bin_number = np.minimum((scores * 10).astype(int), 9)
    count = np.bincount(bin_number, minlength=10)
    actual = np.bincount(bin_number, weights=y, minlength=10)
    predicted = np.bincount(bin_number, weights=scores, minlength=10)
    return {"brier": float(brier_score_loss(y, scores)),
            "ece10EqualWidth": float(np.abs(actual - predicted).sum() / len(y))}


def intervals(y, pred, blocks, result, draws=200):
    """Resample whole domains for URL-level metrics and use exact domain-FPR intervals."""
    groups = int(blocks.max()) + 1
    cells = 2 * y + pred
    counts = np.bincount(4 * blocks + cells, minlength=groups * 4).reshape(groups, 4)
    generator = np.random.default_rng(SEED)
    samples = np.empty((draws, 4))
    for i in range(draws):
        samples[i] = counts[generator.integers(groups, size=groups)].sum(axis=0)
    tn, fp, fn, tp = samples.T
    ratios = {"recall95": (tp, tp + fn), "precision95": (tp, tp + fp),
              "f1_95": (2 * tp, 2 * tp + fn + fp), "urlFpr95": (fp, fp + tn)}
    estimates = {}
    for key, (numerator, denominator) in ratios.items():
        valid = denominator != 0
        estimates[key] = (np.quantile(numerator[valid] / denominator[valid], [0.025, 0.975]).tolist()
                          if valid.any() else None)
    alerts = result["falseAlertDomains"]
    negatives = result["legitimateDomains"]
    estimates["domainFpr95"] = [
        float(beta.ppf(0.025, alerts, negatives - alerts + 1)) if alerts else 0.0,
        float(beta.ppf(0.975, alerts + 1, negatives - alerts)) if alerts < negatives else 1.0,
    ]
    return estimates


def ranking_intervals(y, scores, blocks, draws=200):
    order = np.argsort(-scores, kind="stable")
    thresholds = np.r_[np.flatnonzero(np.diff(scores[order])), len(order) - 1]
    sorted_groups = blocks[order]
    positive = y[order] == 1
    groups = int(blocks.max()) + 1
    rng = np.random.default_rng(SEED)
    measurements = []
    # Within a draw, all URLs from a sampled domain share its multiplicity.
    # Grouping tied scores reproduces threshold-based ROC and average precision.
    for _ in range(draws):
        multiplicity = np.bincount(rng.integers(groups, size=groups), minlength=groups)
        weights = multiplicity[sorted_groups]
        tp = np.cumsum(weights * positive)[thresholds]
        fp = np.cumsum(weights * ~positive)[thresholds]
        if tp[-1] == 0 or fp[-1] == 0:
            continue
        precision = np.divide(tp, tp + fp, out=np.zeros(tp.shape), where=tp + fp > 0)
        recall = tp / tp[-1]
        average_precision = np.diff(recall, prepend=0) @ precision
        roc_auc = np.trapezoid(np.r_[0, recall], np.r_[0, fp / fp[-1]])
        measurements.append([average_precision, roc_auc])
    if not measurements:
        return {"prAuc95": None, "rocAuc95": None}
    bounds = np.quantile(measurements, [0.025, 0.975], axis=0)
    return {"prAuc95": bounds[:, 0].tolist(), "rocAuc95": bounds[:, 1].tolist()}


def at_threshold(y, scores, groups, block, threshold, with_intervals):
    result = classify(y, scores, groups, threshold)
    if with_intervals:
        result["intervals"] = intervals(y, (scores >= threshold).astype(np.int8), block, result)
    return result


def evaluate(rows, scores, thresholds, *, with_intervals=True):
    y = labels(rows)
    if len(set(y)) != 2 or len(y) != len(scores) or not np.isfinite(scores).all():
        raise ValueError("Evaluation requires finite aligned scores and both labels")
    groups = group_labels(rows)
    _, blocks = np.unique(groups, return_inverse=True)
    default = at_threshold(y, scores, groups, blocks, 0.5, with_intervals)
    ranking_bounds = ranking_intervals(y, scores, blocks) if with_intervals else None
    return {"rows": len(y), "positive": int(y.sum()), "idsSha256": ids_sha256(rows),
            **ranking(y, scores), "rankingIntervals": ranking_bounds, **calibration(y, scores), "atHalf": default,
            "atConstraints": {
                target: None if cut["threshold"] is None else
                at_threshold(y, scores, groups, blocks, cut["threshold"], with_intervals)
                for target, cut in thresholds.items()
            }}


def disagreement(y, first, second, first_cut, second_cut):
    first_positive = first >= first_cut
    second_positive = second >= second_cut
    first_error = first_positive != y
    second_error = second_positive != y
    return {"predictionDisagreement": int((first_positive != second_positive).sum()),
            "bothErrors": int((first_error & second_error).sum()),
            "firstOnlyErrors": int((first_error & ~second_error).sum()),
            "secondOnlyErrors": int((~first_error & second_error).sum()),
            "firstOnlyTruePositives": int(((y == 1) & first_positive & ~second_positive).sum()),
            "secondOnlyTruePositives": int(((y == 1) & ~first_positive & second_positive).sum()),
            "bothFalsePositives": int(((y == 0) & first_positive & second_positive).sum())}


def paired_recall(rows, candidate, candidate_cut, reference, reference_cut):
    if candidate_cut is None or reference_cut is None:
        return None
    positive = labels(rows) == 1
    _, blocks = np.unique(group_labels(rows), return_inverse=True)
    signed = positive * ((candidate >= candidate_cut).astype(int) - (reference >= reference_cut))
    denominators = np.bincount(blocks, weights=positive)
    deltas = np.bincount(blocks, weights=signed)
    rng = np.random.default_rng(SEED)
    estimates = []
    for _ in range(200):
        drawn = rng.integers(len(deltas), size=len(deltas))
        total = denominators[drawn].sum()
        if total:
            estimates.append(deltas[drawn].sum() / total)
    return {"delta": float(deltas.sum() / denominators.sum()),
            "delta95": np.quantile(estimates, [0.025, 0.975]).tolist()}
