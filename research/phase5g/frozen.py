"""Verify the frozen Phase 5G registry and restore the existing models offline."""

import json
from pathlib import Path
import subprocess
import sys
from hashlib import sha256
from importlib import import_module

import joblib
import numpy as np
from scipy.special import expit

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "research" / "phase5f"))
from replay import apply_fusion, build_input, hash_file, read, repository_hash, scorer, verify
from fusion_lab import auth, dom_inputs, Lab
from fusion import logistic_input

DOCS = ROOT / "docs" / "experiments"
REGISTRY = DOCS / "phase5g" / "frozen-models.json"
F_REVISION = "a09394be5689b421c610d2679aa4cd7e6f3f2872"
URL_MODELS = ("ngram", "cnn", "xgboost", "fusion", "mixed")
MULTIMODAL = ("fixed", "stack", "adaptive")
F_PREPROCESSING = (
    "evaluation/features.mjs", "extension/reputation.mjs", "extension/vendor/tldts.mjs",
    "research/phase5e/feature-schema.json", "research/phase5e/acquire.py", "research/phase5e/dom.mjs",
    "research/phase5e/parse.mjs", "research/phase5e/worker.mjs", "research/phase5e/package-lock.json",
    "research/phase5f/fusion_lab.py", "research/phase5f/grouping.py",
    "research/phase5c/sequence.py", "research/phase5c/train.py", "research/phase5d/evaluate.py",
)
HISTORY = {
    "phase-5c-v1/cohort/manifest.json": "b05c458d47a7840a484419bb2f20953728e9171cb7557eb3158b6a43ccee86ac",
    "phase-5c-v1/history.jsonl": "0ad23e05daf64f7bf6a85e937c5a9f064e153c3c5e6002bafdb9c0ca3a0248ed",
    "phase-5c-v1/phresh-custody-final/manifest.json": "e1a576f186ba6c23c217c562f5175edb420cc33671c70c6cd106a1ad9eb1f033",
    "phase-5d-v1/prepared-balanced-fusion/auxiliary/manifest.json": "8bcc81ffe4465f4648336e8e42f0257f89f83f22f176c01deac0832a468f4d6b",
    "phase-5d-v1/prepared/temporal/manifest.json": "34e4b65539aea1dc862f3b18308c9eb2e27d2f4700353f6b2247758ce9b02675",
}
EVALUATION_CODE = (
    "research/phase3g/validate.mjs", "research/phase3d/partition.mjs", "research/phase3e/prepare.mjs",
    "extension/impersonation.mjs", "extension/financial-domains.mjs",
    "research/phase5g/project.mjs", "research/phase5g/protocol.json", "research/phase5g/frozen.py",
    "research/phase5g/preflight.py", "research/phase5g/custodian.py", "research/phase5g/aggregate.py",
)


def git_digest(revision, name):
    data = subprocess.check_output(["git", "show", f"{revision}:{name}"], cwd=ROOT)
    return sha256(data.replace(b"\r\n", b"\n")).hexdigest()


def checked_artifact(experiments, entry):
    path = (experiments / entry["artifact"]).resolve()
    if (not path.is_relative_to(experiments) or path.stat().st_size != entry["bytes"]
            or hash_file(path) != entry["sha256"]):
        raise ValueError("Frozen artifact does not match its receipt")
    return path


def thresholds(spec):
    return {"fixed": 0.5, **{target: point["threshold"] for target, point in spec.items()}}


def freeze(experiments):
    prior_path = "docs/experiments/phase5e/frozen-url.json"
    prior = read(ROOT / prior_path)
    if repository_hash(prior_path) != git_digest(F_REVISION, prior_path):
        raise ValueError("Upstream freeze receipt changed")
    if repository_hash("docs/experiments/phase5d/results.json") != prior["sourceReportSha256"]:
        raise ValueError("Phase 5D result receipt changed")
    for name, expected in prior["preprocessingSha256"].items():
        if git_digest(prior["revision"], name) != expected:
            raise ValueError("Historical upstream preprocessing does not match")
    hashes = {name: repository_hash(name) for name in F_PREPROCESSING}
    if any(git_digest(F_REVISION, name) != actual for name, actual in hashes.items()):
        raise ValueError("Phase 5F preprocessing does not match its Git revision")
    for name, expected in HISTORY.items():
        if hash_file(experiments / name) != expected:
            raise ValueError("Frozen historical input does not match")
    report_name = "docs/experiments/phase5f/results.json"
    if repository_hash(report_name) != git_digest(F_REVISION, report_name):
        raise ValueError("Phase 5F report does not match its Git revision")
    source = "phase-5f-v1/main-final"
    report = read(ROOT / report_name)
    verify(report, read(experiments / source / "results.json"))
    grouped = report["grouped"]
    models = {name: prior["models"][name] | {"modality": "url"} for name in URL_MODELS}
    artifacts = {}
    for name, fit in grouped["fit"].items():
        artifacts[name] = {"artifact": f"{source}/{name}/model.joblib", "sha256": fit["modelSha256"],
                           "bytes": fit["modelBytes"]}
    fusion = grouped["fusionFit"]
    artifacts["fusion"] = {"artifact": f"{source}/fusion.joblib", "sha256": fusion["artifactSha256"],
                           "bytes": fusion["artifactBytes"]}
    for entry in (*models.values(), *artifacts.values()):
        if "artifact" in entry:
            checked_artifact(experiments, entry)
    fit = joblib.load(checked_artifact(experiments, artifacts["fusion"]))
    verify(fit, {key: fusion[key] for key in fit})
    for name in MULTIMODAL:
        models[name] = {"modality": "url-dom", "trainingRows": grouped["rows"]["train"],
                        "components": ["phase5f-ngram", "phase5f-dom-weighted", "phase5f-fusion"],
                        "operatingPoints": thresholds(grouped["thresholds"][name])}
    return {"schema": "phase5g-frozen-v1", "phase5dRevision": prior["revision"], "phase5fRevision": F_REVISION,
            "phase5fReportSha256": repository_hash(report_name), "phase5eRegistrySha256": repository_hash(prior_path),
            "runtimeVersions": {name: str(import_module(name).__version__)
                                for name in ("numpy", "scipy", "sklearn", "xgboost", "torch", "joblib")},
            "phase5dPreprocessingSha256": prior["preprocessingSha256"], "preprocessingSha256": hashes,
            "evaluationCodeSha256": {name: repository_hash(name) for name in EVALUATION_CODE},
            "historySha256": HISTORY, "groupedMembershipSha256": grouped["memberships"],
            "phase5fArtifacts": artifacts, "models": models, "phase5fParameters": fit | {
                "fixedWeights": {"url": 0.75, "dom": 0.25}, "adaptiveWeights": {"auth": 0.15, "other": 0.35,
                "outlyingFeatureLimit": 2, "disagreementCut": 0.55, "disagreementMultiplier": 0.5}}}


class Frozen:
    def __init__(self, experiments, registry):
        self.spec = registry["models"]
        self.url = {}
        for name in URL_MODELS:
            item = self.spec[name]
            if "artifact" in item:
                artifact = checked_artifact(experiments, item)
                self.url[name] = scorer(item["kind"], artifact.parent, {"modelSha256": item["sha256"]})
        paths = registry["phase5fArtifacts"]
        self.f_ngram = joblib.load(checked_artifact(experiments, paths["ngram"]))
        self.f_dom = joblib.load(checked_artifact(experiments, paths["dom-weighted"]))
        self.parameters = registry["phase5fParameters"]

    def url_scores(self, rows):
        scores = {name: model(rows) for name, model in self.url.items()}
        scores["fusion"] = apply_fusion(scores, self.spec["fusion"])
        return scores

    def scale(self, name, values):
        weight, intercept = self.parameters["calibration"][name]
        return expit(weight * logistic_input(values)[:, 0] + intercept)

    def fallback(self, rows):
        raw = self.f_ngram.predict_proba(build_input("ngram", rows))[:, 1]
        return self.scale("url-ngram", raw)

    def multimodal_scores(self, rows):
        if any(row.get("dom") is None for row in rows):
            raise ValueError("Multimodal scoring requires complete paired content")
        p = self.parameters
        url = self.fallback(rows)
        dom = self.scale("dom-weighted", self.f_dom.predict_proba(dom_inputs(rows, "weighted"))[:, 1])
        fixed = p["fixedWeights"]["url"] * url + p["fixedWeights"]["dom"] * dom
        stack = expit(Lab.stack_features(rows, url, dom) @ np.array(p["stackCoefficients"]) + p["stackIntercept"])
        limit = np.asarray(p["domUpperQuantile"])
        variable = limit > 0
        exceeds = (dom_inputs(rows, "full")[:, variable] > limit[variable]).sum(axis=1)
        config = p["adaptiveWeights"]
        weight = np.where(np.array([auth(row) for row in rows]), config["auth"], config["other"])
        weight *= np.where(exceeds >= config["outlyingFeatureLimit"], 0.0, 1.0)
        weight *= np.where(abs(url - dom) > config["disagreementCut"], config["disagreementMultiplier"], 1.0)
        return {"fixed": fixed, "stack": stack, "adaptive": url + weight * (dom - url)}


def write(path, report):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, indent=2, allow_nan=False)
        stream.write("\n")
