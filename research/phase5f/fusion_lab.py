"""Fit grouped offline classifiers, fusion rules, and selective decisions."""

from time import perf_counter

import joblib
import numpy as np
from scipy.special import expit
from sklearn.linear_model import LogisticRegression
from xgboost import DMatrix

from replay import FEATURES, GROUPS, balanced, build_input, hash_file, model_input, thresholds
from benchmark import model_for
from experiment_metrics import classify
from fusion import logistic_input, platt, probability
from metrics import disagreement, evaluate, group_labels, labels, paired_recall
from train import fit_model

ROLES = {"password": ("inputs_password",), "payment": ("inputs_payment",),
         "crossOriginForm": ("actions_external",), "iframe": ("iframe_external",),
         "externalLinks": ("links_external_ratio",), "refresh": ("refresh",),
         "scripts": ("scripts",), "smallDom": ()}
RELATIONSHIPS = ("externalActionShare", "localActionShare", "passwordFormShare", "paymentFormShare",
                 "externalFrameShare", "hasAuthContext")
REDUCED = tuple(key for key in FEATURES if key not in (*GROUPS["title"], "elements", "depth",
                                                       "scripts", "links", "links_external_ratio"))


def stratum(row, name):
    dom = row.get("dom")
    if dom is None:
        return False
    return dom["elements"] <= 20 if name == "smallDom" else any(dom[key] > 0 for key in ROLES[name])


def auth(row):
    return any(stratum(row, key) for key in ("password", "payment", "crossOriginForm", "iframe"))


def context_vector(row):
    dom = row["dom"]
    forms = max(dom["forms"], 1)
    return [dom["actions_external"] / forms, dom["actions_local"] / forms, dom["password_forms"] / forms,
            dom["payment_forms"] / forms, dom["iframe_external"] / max(dom["iframe"], 1), float(auth(row))]


def dom_inputs(rows, mode):
    columns = REDUCED if mode == "reduced" else FEATURES
    values = model_input(rows, columns)
    if mode in ("context", "weighted"):
        return np.column_stack((values, [context_vector(row) for row in rows]))
    return values


def sizes(path, keys):
    return sum((path / key / "model.joblib").stat().st_size for key in set(keys))


def training_weights(rows):
    # Match total class weight while increasing influence of observed benign auth structures.
    weights = np.array([3.0 if row["label"] == 0 and auth(row) else 1.0 for row in rows])
    negative = labels(rows) == 0
    weights[negative] *= negative.sum() / weights[negative].sum()
    return weights


def valid_content(rows):
    return np.array([row.get("dom") is not None for row in rows], dtype=bool)


class Lab:
    def __init__(self, train, tuning, path):
        self.dom_models = {}
        self.url_models = {}
        self.url_checkpoint = path / "ngram" / "model.joblib"
        self.fit = {}
        for name in ("ngram", "xgboost"):
            dest = path / name
            dest.mkdir()
            self.url_models[name], self.fit[name] = fit_model(name, train, tuning, dest, False)
        for mode in ("full", "reduced", "regularized", "context", "weighted"):
            name = "dom-" + mode
            dest = path / name
            dest.mkdir()
            model = model_for("xgboost")
            if mode in ("regularized", "context", "weighted"):
                model.set_params(max_depth=4, reg_lambda=3)
            start = perf_counter()
            model.fit(dom_inputs(train, mode), labels(train),
                      sample_weight=training_weights(train) if mode == "weighted" else None)
            checkpoint = dest / "model.joblib"
            joblib.dump(model, checkpoint, compress=3)
            self.dom_models[mode] = joblib.load(checkpoint)
            self.fit[name] = {"fitSeconds": perf_counter() - start, "modelBytes": checkpoint.stat().st_size,
                              "modelSha256": hash_file(checkpoint)}
        scores = self.base(tuning)
        self.scales = {key: platt(labels(tuning), value) for key, value in scores.items()}
        url = self.scale("url-ngram", scores["url-ngram"])
        dom = self.scale("dom-weighted", scores["dom-weighted"])
        self.stack = LogisticRegression(C=0.25, random_state=143).fit(self.stack_features(tuning, url, dom), labels(tuning))
        threshold = thresholds(tuning, url)["0.01"]["threshold"]
        self.center = 0.8 if threshold is None else min(threshold, 1.0)
        self.width = 0.20
        self.dom_upper = np.quantile(dom_inputs(train, "full"), 0.995, axis=0)
        self.dom_variable = self.dom_upper > 0
        self.dependencies = {"url-ngram": ["ngram"], "url-xgboost": ["xgboost"],
                             "url-blend": ["ngram", "xgboost"], "fixed": ["ngram", "dom-weighted"],
                             "stack": ["ngram", "dom-weighted"], "adaptive": ["ngram", "dom-weighted"],
                             "selective": ["ngram", "dom-weighted"]}
        self.dependencies.update({f"dom-{mode}": [f"dom-{mode}"] for mode in self.dom_models})
        self.artifact_sizes = {name: sizes(path, keys) for name, keys in self.dependencies.items()}
        fusion = {"calibration": {key: [float(model.coef_[0, 0]), float(model.intercept_[0])]
                                  for key, model in self.scales.items()},
                  "stackCoefficients": self.stack.coef_[0].tolist(), "stackIntercept": float(self.stack.intercept_[0]),
                  "routeCenter": self.center, "routeHalfWidth": self.width, "domUpperQuantile": self.dom_upper.tolist()}
        joblib.dump(fusion, path / "fusion.joblib", compress=3)
        self.fusion_metadata = fusion | {"artifactBytes": (path / "fusion.joblib").stat().st_size,
                                         "artifactSha256": hash_file(path / "fusion.joblib")}

    def url(self, name, rows):
        return self.url_models[name](build_input(name, rows)).astype(np.float64)

    def dom(self, mode, rows):
        return self.dom_models[mode].predict_proba(dom_inputs(rows, mode))[:, 1].astype(np.float64)

    def base(self, rows):
        return {"url-ngram": self.url("ngram", rows), "url-xgboost": self.url("xgboost", rows)} | {
            "dom-" + mode: self.dom(mode, rows) for mode in self.dom_models}

    def scale(self, name, values):
        return probability(self.scales[name], values)

    @staticmethod
    def stack_features(rows, url, dom):
        context = np.array([auth(row) for row in rows], dtype=float)
        dom_logit = logistic_input(dom)[:, 0]
        return np.column_stack((logistic_input(url), dom_logit, context, context * dom_logit))

    def adaptive(self, rows, url, dom):
        numeric = dom_inputs(rows, "full")
        exceeds = (numeric[:, self.dom_variable] > self.dom_upper[self.dom_variable]).sum(axis=1)
        # Downweight evidence on apparent auth, outlying counts, and model disagreement.
        weight = np.where(np.array([auth(row) for row in rows]), 0.15, 0.35)
        weight *= np.where(exceeds >= 2, 0.0, 1.0)
        weight *= np.where(abs(url - dom) > 0.55, 0.5, 1.0)
        return url + weight * (dom - url)

    def route(self, url):
        return abs(url - self.center) <= self.width

    def score(self, rows):
        first = self.url("ngram", rows)
        second = self.url("xgboost", rows)
        url = self.scale("url-ngram", first)
        available = valid_content(rows)
        scores = {"url-ngram": first, "url-xgboost": second,
                  "url-blend": 0.75 * url + 0.25 * self.scale("url-xgboost", second)}
        content = [row for row, keep in zip(rows, available, strict=True) if keep]
        for mode in self.dom_models:
            scores["dom-" + mode] = np.full(len(rows), np.nan)
            if content:
                scores["dom-" + mode][available] = self.dom(mode, content)
        for key in ("fixed", "stack", "adaptive", "selective"):
            scores[key] = url.copy()
        route = self.route(url)
        if content:
            dom = self.scale("dom-weighted", scores["dom-weighted"][available])
            selected_url = url[available]
            scores["fixed"][available] = 0.75 * selected_url + 0.25 * dom
            scores["stack"][available] = self.stack.predict_proba(self.stack_features(content, selected_url, dom))[:, 1]
            scores["adaptive"][available] = self.adaptive(content, selected_url, dom)
            scores["selective"][available & route] = scores["adaptive"][available & route]
        return scores, route

    def online_shape(self, name, row):
        if name.startswith("dom-"):
            return self.dom(name.removeprefix("dom-"), [row])[0], True
        if name == "url-xgboost":
            return self.url("xgboost", [row])[0], False
        first = self.url("ngram", [row])
        if name == "url-ngram":
            return first[0], False
        url = self.scale("url-ngram", first)
        if name == "url-blend":
            second = self.scale("url-xgboost", self.url("xgboost", [row]))
            return (0.75 * url + 0.25 * second)[0], False
        if name == "selective" and not self.route(url)[0]:
            return url[0], False
        dom = self.scale("dom-weighted", self.dom("weighted", [row]))
        if name == "fixed":
            value = 0.75 * url + 0.25 * dom
        elif name == "stack":
            value = self.stack.predict_proba(self.stack_features([row], url, dom))[:, 1]
        else:
            value = self.adaptive([row], url, dom)
        return value[0], True


def latency(lab, rows, scores):
    positions = np.linspace(0, len(rows) - 1, min(200, len(rows)), dtype=int)
    report = {}
    for name in scores:
        compute, paired = [], []
        for i in positions[:5]:
            lab.online_shape(name, rows[i])
        used = 0
        for i in positions:
            start = perf_counter()
            score, content = lab.online_shape(name, rows[i])
            elapsed = (perf_counter() - start) * 1000
            if abs(score - scores[name][i]) > 1e-6:
                raise ValueError("Conditional inference differs from bulk scoring")
            compute.append(elapsed)
            paired.append(elapsed + (rows[i]["timings"]["pipelineMs"] if content else 0))
            used += content
        report[name] = {"medianComputeMs": float(np.median(compute)), "p95ComputeMs": float(np.percentile(compute, 95)),
                        "medianWithProjectionMs": float(np.median(paired)), "p95WithProjectionMs": float(np.percentile(paired, 95)),
                        "measuredRows": len(positions), "contentUses": used}
    return report


def operating_summary(rows, scores, cuts, reference_name):
    grouped = [row | {"identity": row["identity"] | {"group": row["structuralComponent"]}} for row in rows]
    y = labels(rows)
    comparisons = {}
    for name, values in scores.items():
        by_target = {}
        for target, point in cuts[name].items():
            threshold, reference = point["threshold"], cuts[reference_name][target]["threshold"]
            if threshold is None or reference is None:
                by_target[target] = None
                continue
            by_target[target] = disagreement(y, scores[reference_name], values, reference, threshold) | {
                "domainPairedRecall": paired_recall(rows, values, threshold, scores[reference_name], reference),
                "structuralComponentPairedRecall": paired_recall(grouped, values, threshold, scores[reference_name], reference)}
        comparisons[name] = by_target
    return comparisons


def selective_outcomes(rows, scores, threshold, route, usable):
    if threshold is None:
        return None
    y, groups = labels(rows), group_labels(rows)
    curve = []
    for tolerance in (0.0, 0.025, 0.05, 0.10, 0.20):
        uncertain = (abs(scores - threshold) < tolerance) | (route & ~usable)
        high = (scores >= threshold) & ~uncertain
        known = ~uncertain
        errors = ((y == 1) != high) & known
        observed = classify(y, high.astype(float), groups, 0.5)
        curve.append({"buffer": tolerance, "coverage": float(known.mean()), "abstention": float(uncertain.mean()),
                      "elevatedRiskRows": int(high.sum()), "lowRiskRows": int((known & ~high).sum()),
                      "uncertainRows": int(uncertain.sum()),
                      "abstainedPhishing": int(((y == 1) & uncertain).sum()),
                      "classifiedError": float(errors.sum() / known.sum()) if known.any() else None,
                      "overallRecall": observed["recall"], "urlFpr": observed["falsePositiveRate"],
                      "domainFpr": observed["negativeDomainFalsePositiveRate"]})
    return curve


def strata(rows, scores, cuts):
    result = {}
    for name in ROLES:
        order = [i for i, row in enumerate(rows) if not row["label"] and stratum(row, name)]
        groups = {rows[i]["identity"]["group"] for i in order}
        output = {}
        for model, values in scores.items():
            thresholds_ = {"fixed": 0.5, **{key: item["threshold"] for key, item in cuts[model].items()}}
            output[model] = {}
            for target, point in thresholds_.items():
                alerted = [] if point is None else [i for i in order if values[i] >= point]
                output[model][target] = None if point is None else {
                    "urls": len(alerted), "domains": len({rows[i]["identity"]["group"] for i in alerted})}
        result[name] = {"rows": len(order), "domains": len(groups), "alerts": output}
    return result


def explanations(lab, rows, values, threshold):
    negative = [(i, row) for i, row in enumerate(rows) if row["label"] == 0]
    if threshold is None:
        return None
    flagged = [row for i, row in negative if values[i] >= threshold]
    other = [row for i, row in negative if values[i] < threshold][:len(flagged)]
    if not flagged or not other:
        return None
    estimator = lab.dom_models["weighted"]
    columns = FEATURES + RELATIONSHIPS
    def aggregate(members):
        contributions = estimator.get_booster().predict(DMatrix(dom_inputs(members, "weighted")), pred_contribs=True)
        raw = contributions[:, :-1]
        means = np.mean(raw, axis=0)
        order = np.argsort(-np.mean(abs(raw), axis=0))[:8]
        return {columns[i]: {"meanSignedLogOdds": float(means[i]), "meanAbsoluteLogOdds": float(np.mean(abs(raw[:, i])))}
                for i in order}
    return {"falsePositiveRows": len(flagged), "nonAlertedComparisonRows": len(other),
            "alerted": aggregate(flagged), "nonAlerted": aggregate(other)}


def ngram_explanations(lab, rows, values, threshold):
    if threshold is None:
        return None
    positives = values >= threshold
    members = [row for row, flagged in zip(rows, positives, strict=True) if flagged and not row["label"]]
    if not members:
        return None
    vectorizer, linear = joblib.load(lab.url_checkpoint).steps
    vectorizer, linear = vectorizer[1], linear[1]
    by_length = np.fromiter(map(len, vectorizer.get_feature_names_out()), dtype=int)
    contribution = vectorizer.transform(build_input("ngram", members)).multiply(linear.coef_[0]).tocsr()
    return {"falsePositiveRows": len(members), "byNgramLength": {
        str(size): {"meanSignedLogOdds": float(contribution[:, by_length == size].sum() / len(members)),
                    "meanAbsoluteLogOdds": float(abs(contribution[:, by_length == size]).sum() / len(members))}
        for size in range(2, 6)}}
