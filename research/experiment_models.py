"""CPU model fitting with group-isolated early stopping."""

from copy import deepcopy
from dataclasses import dataclass

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import log_loss
from sklearn.model_selection import GroupShuffleSplit
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier


@dataclass
class Fit:
    estimator: object
    rounds: int | None = None
    trace: dict | None = None


def stop_partition(x, y, groups, seed):
    splitter = GroupShuffleSplit(n_splits=1, test_size=0.125, random_state=seed)
    train, stop = next(splitter.split(x, y, groups))
    if np.intersect1d(groups[train], groups[stop]).size or set(y[train]) != {0, 1} or set(y[stop]) != {0, 1}:
        raise ValueError("Early-stopping groups or label coverage are invalid.")
    return train, stop


def fit_model(name, params, x, y, groups, seed, workers, fixed_rounds=None):
    options = dict(params)
    if name == "logistic_regression":
        estimator = make_pipeline(StandardScaler(), LogisticRegression(random_state=seed, **options))
        return Fit(estimator.fit(x, y))
    if name == "random_forest":
        return Fit(RandomForestClassifier(random_state=seed, n_jobs=workers, **options).fit(x, y))
    if name == "xgboost":
        patience = options.pop("patience")
        if fixed_rounds is not None:
            options["n_estimators"] = fixed_rounds
        estimator = XGBClassifier(
            device="cpu", tree_method="hist", n_jobs=workers, random_state=seed,
            objective="binary:logistic", eval_metric="logloss",
            early_stopping_rounds=patience if fixed_rounds is None else None, **options,
        )
        if fixed_rounds is not None:
            return Fit(estimator.fit(x, y), fixed_rounds)
        train, stop = stop_partition(x, y, groups, seed)
        estimator.fit(x[train], y[train], eval_set=[(x[train], y[train]), (x[stop], y[stop])], verbose=False)
        trace = estimator.evals_result()
        return Fit(estimator, estimator.best_iteration + 1, {
            "fitLogLoss": trace["validation_0"]["logloss"], "stopLogLoss": trace["validation_1"]["logloss"],
        })
    if name != "mlp":
        raise ValueError("Unsupported experimental model.")
    maximum = options.pop("max_epochs")
    patience = options.pop("patience")
    options["hidden_layer_sizes"] = tuple(options["hidden_layer_sizes"])
    estimator = MLPClassifier(random_state=seed, early_stopping=False, **options)
    if fixed_rounds is not None:
        scaler = StandardScaler().fit(x)
        fitted = scaler.transform(x)
        for _ in range(fixed_rounds):
            estimator.partial_fit(fitted, y, classes=[0, 1])
        return Fit(make_pipeline(scaler, estimator), fixed_rounds)
    train, stop = stop_partition(x, y, groups, seed)
    scaler = StandardScaler().fit(x[train])
    fitted, stopping = scaler.transform(x[train]), scaler.transform(x[stop])
    fit_loss, stop_loss = [], []
    best_loss, best_round, best_model = np.inf, 0, None
    for epoch in range(1, maximum + 1):
        estimator.partial_fit(fitted, y[train], classes=[0, 1])
        fit_loss.append(float(log_loss(y[train], estimator.predict_proba(fitted)[:, 1], labels=[0, 1])))
        loss = float(log_loss(y[stop], estimator.predict_proba(stopping)[:, 1], labels=[0, 1]))
        stop_loss.append(loss)
        if loss < best_loss - 0.0001:
            best_loss, best_round, best_model = loss, epoch, deepcopy(estimator)
        if epoch - best_round >= patience:
            break
    return Fit(make_pipeline(scaler, best_model), best_round, {"fitLogLoss": fit_loss, "stopLogLoss": stop_loss})
