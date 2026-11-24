"""Choose a complementary pair on a dedicated development fitting view."""

from itertools import combinations

import numpy as np
from scipy.special import logit
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score

from metrics import CONFIG, cutoffs, disagreement
from shared import SEED


def logistic_input(scores):
    return logit(np.clip(np.asarray(scores, dtype=np.float64), 1e-6, 1 - 1e-6)).reshape(-1, 1)


def platt(y, scores):
    model = LogisticRegression(C=1, random_state=SEED).fit(logistic_input(scores), y)
    return model


def probability(model, scores):
    return model.predict_proba(logistic_input(scores))[:, 1]


def pairwise(y, predictions, thresholds):
    result = {}
    for first, second in combinations(predictions, 2):
        if thresholds[first] is None or thresholds[second] is None:
            result[f"{first}+{second}"] = None
        else:
            result[f"{first}+{second}"] = disagreement(
                y, predictions[first], predictions[second], thresholds[first], thresholds[second])
    return result


def blend(first, second, weight):
    if first.shape != second.shape or not 0 <= weight <= 1:
        raise ValueError("Fusion needs aligned vectors and a valid weight")
    return weight * first + (1 - weight) * second


def select(y, groups, scores):
    reference = CONFIG["fusionReference"]
    target = str(CONFIG["fusionSelectionDomainFpr"])
    models = {name: platt(y, values) for name, values in scores.items()}
    calibrated = {name: probability(models[name], values) for name, values in scores.items()}
    thresholds = {name: cutoffs(y, values, groups)[target]["threshold"] for name, values in calibrated.items()}
    pairs = pairwise(y, calibrated, thresholds)
    trials = []
    for partner in CONFIG["fusionPartners"]:
        if thresholds[reference] is None or thresholds[partner] is None:
            continue
        contrast = disagreement(y, calibrated[reference], calibrated[partner], thresholds[reference], thresholds[partner])
        exclusive = contrast["secondOnlyTruePositives"] / y.sum()
        if exclusive < CONFIG["fusionPartnerMinExclusiveRecall"]:
            continue
        for weight in CONFIG["fusionCandidateWeightsOnReference"]:
            values = blend(calibrated[reference], calibrated[partner], weight)
            threshold = cutoffs(y, values, groups)[target]["threshold"]
            recall = ((values >= threshold) & (y == 1)).sum() / y.sum()
            trials.append({"reference": reference, "partner": partner, "referenceWeight": weight,
                           "partnerExclusiveRecall": float(exclusive), "fittingRecall": float(recall),
                           "fittingAveragePrecision": float(average_precision_score(y, values))})
    winner = max(trials, key=lambda trial: (trial["fittingRecall"], trial["fittingAveragePrecision"]), default=None)
    return models, {"pairs": pairs, "thresholds": thresholds, "trials": trials, "selected": winner}
