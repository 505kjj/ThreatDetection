"""Aggregate measures for frozen scores, including negative-only controls."""

from itertools import combinations

import numpy as np

from frozen import URL_MODELS
from experiment_metrics import classify
from metrics import calibration, disagreement, group_labels, intervals, labels, paired_recall, ranking, ranking_intervals


def prevalence_precision(recall, fpr, prevalence):
    if recall is None or fpr is None:
        return None
    tp, fp = recall * prevalence, fpr * (1 - prevalence)
    return tp / (tp + fp) if tp + fp else None


def evaluate(rows, scores, operating_points, prevalences):
    if not rows:
        return {"rows": 0, "status": "empty"}
    y, groups = labels(rows), group_labels(rows)
    _, blocks = np.unique(groups, return_inverse=True)
    both_classes = len(set(y)) == 2
    has_benign = np.any(y == 0)
    results = {}
    for name, values in scores.items():
        if len(values) != len(rows) or not np.isfinite(values).all() or np.any((values < 0) | (values > 1)):
            raise ValueError("Invalid model score vector")
        points = {}
        for target, point in operating_points[name].items():
            if point is None:
                points[target] = None
                continue
            values_at_point = classify(y, values, groups, point)
            if has_benign:
                values_at_point["intervals"] = intervals(y, (values >= point).astype(np.int8), blocks, values_at_point)
            values_at_point["scenarioPrecisionFromUrlRates"] = {
                str(p): prevalence_precision(values_at_point["recall"], values_at_point["falsePositiveRate"], p)
                for p in prevalences}
            points[target] = values_at_point
        results[name] = {"ranking": (ranking(y, values) | ranking_intervals(y, values, blocks)) if both_classes else None,
                         "calibration": calibration(y, values) if both_classes else None, "operatingPoints": points}
    comparisons = {}
    for first, second in combinations(scores, 2):
        if first not in URL_MODELS and second not in URL_MODELS:
            continue
        common = operating_points[first].keys() & operating_points[second].keys()
        points = {}
        for target in sorted(common):
            a, b = operating_points[first][target], operating_points[second][target]
            if a is None or b is None:
                points[target] = None
                continue
            fp_a = results[first]["operatingPoints"][target]["negativeDomainFalsePositiveRate"]
            fp_b = results[second]["operatingPoints"][target]["negativeDomainFalsePositiveRate"]
            points[target] = disagreement(y, scores[first], scores[second], a, b) | {
                "pairedRecall": paired_recall(rows, scores[second], b, scores[first], a) if np.any(y == 1) else None,
                "observedDomainFprDelta": None if fp_a is None or fp_b is None else fp_b - fp_a}
        comparisons[f"{first}+{second}"] = points
    return {"rows": len(rows), "phishing": int(y.sum()), "benign": int((y == 0).sum()),
            "domains": len(set(groups)), "phishingDomains": len(set(groups[y == 1])),
            "benignDomains": len(set(groups[y == 0])), "models": results, "paired": comparisons}
