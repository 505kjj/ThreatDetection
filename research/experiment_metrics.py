"""Score probabilities and lock conservative, domain-level false-alert thresholds."""

import numpy as np
from scipy.stats import beta, binom
from sklearn.metrics import average_precision_score, log_loss, roc_auc_score


def ranking(labels, scores):
    return {
        "prAucAveragePrecision": float(average_precision_score(labels, scores)),
        "rocAuc": float(roc_auc_score(labels, scores)),
        "logLoss": float(log_loss(labels, scores, labels=[0, 1])),
    }


def ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def negative_domain_scores(labels, scores, groups):
    negative = labels == 0
    _, index = np.unique(groups[negative], return_inverse=True)
    maxima = np.full(int(index.max()) + 1 if index.size else 0, -np.inf)
    np.maximum.at(maxima, index, scores[negative])
    return maxima


def threshold_at_target(negative_scores, target, risk):
    n = len(negative_scores)
    ranks = np.arange(n)
    supported = ranks[binom.cdf(ranks, n, target) <= risk]
    if not supported.size:
        return {"targetNegativeDomainFpr": target, "calibrationDomains": n, "threshold": None}
    k = int(supported[-1])
    boundary = np.sort(negative_scores)[::-1][k]
    threshold = float(np.nextafter(boundary, np.inf))
    return {
        "targetNegativeDomainFpr": target, "calibrationRisk": risk, "calibrationDomains": n,
        "maximumAllowedCalibrationFalseAlertDomains": k,
        "observedCalibrationFalseAlertDomains": int(np.count_nonzero(negative_scores >= threshold)),
        "threshold": threshold,
    }


def classify(labels, scores, groups, threshold):
    scores = np.asarray(scores, dtype=np.float64)
    positive = labels == 1
    predicted = scores >= threshold
    tp = int(np.count_nonzero(positive & predicted))
    fp = int(np.count_nonzero(~positive & predicted))
    tn = int(np.count_nonzero(~positive & ~predicted))
    fn = int(np.count_nonzero(positive & ~predicted))
    domain_maxima = negative_domain_scores(labels, scores, groups)
    domains = len(domain_maxima)
    false_domains = int(np.count_nonzero(domain_maxima >= threshold))
    upper = None
    if domains:
        upper = 1.0 if false_domains == domains else float(beta.ppf(0.95, false_domains + 1, domains - false_domains))
    return {
        "threshold": threshold, "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": ratio(tp, tp + fp), "recall": ratio(tp, tp + fn),
        "f1": ratio(2 * tp, 2 * tp + fp + fn), "falsePositiveRate": ratio(fp, fp + tn),
        "falseAlertDomains": false_domains, "legitimateDomains": domains,
        "negativeDomainFalsePositiveRate": ratio(false_domains, domains),
        "negativeDomainFpr95Upper": upper,
    }
