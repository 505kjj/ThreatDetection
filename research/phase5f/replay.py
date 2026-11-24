"""Replay checksummed Phase 5E predictions and privacy-safe diagnostic controls."""

import json
from pathlib import Path
import subprocess
import sys

import joblib
import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "research" / "phase5e")]
from compare import FEATURES, GROUPS, balanced, build_input, hash_file, ids_sha256, model_input, read
from freeze_url import apply_fusion, repository_hash
from evaluate import scorer, thresholds
from metrics import evaluate, paired_recall


def load_models(directory, report):
    models = {}
    for name, spec in report["models"].items():
        if "componentScales" in spec["fit"]:
            continue
        path = directory / name / "model.joblib"
        if hash_file(path) != spec["fit"]["modelSha256"]:
            raise ValueError("Phase 5E checkpoint checksum differs")
        models[name] = joblib.load(path)
    return models


def blend_scores(scores, fit):
    first, second = fit["componentScales"]
    weight = fit["referenceWeight"]
    return apply_fusion({"ngram": scores[first], second: scores[second]}, {
        "components": {"ngram": weight, second: 1 - weight},
        "probabilityScales": {"ngram": fit["componentScales"][first], second: fit["componentScales"][second]},
    })


def predict_models(models, report, rows):
    scores = {}
    for name, model in models.items():
        if name in ("url-ngram", "url-xgboost"):
            data = build_input(name.removeprefix("url-"), rows)
        else:
            removed = GROUPS.get(name.removeprefix("ablation-"), ())
            data = model_input(rows, [key for key in FEATURES if key not in removed], name == "url-dom-xgboost")
        scores[name] = model.predict_proba(data)[:, 1].astype(np.float64)
    for name in ("url-fusion", "url-dom-fusion"):
        scores[name] = blend_scores(scores, report["models"][name]["fit"])
    return scores


def verify(expected, observed):
    if isinstance(expected, dict):
        if expected.keys() != observed.keys():
            raise ValueError("Replay metric fields differ")
        for key in expected:
            verify(expected[key], observed[key])
    elif isinstance(expected, list):
        if len(expected) != len(observed):
            raise ValueError("Replay metric list differs")
        for first, second in zip(expected, observed, strict=True):
            verify(first, second)
    elif isinstance(expected, float) and observed is not None:
        if not np.isclose(expected, observed, rtol=0, atol=1e-7):
            raise ValueError("Phase 5E numerical replay differs")
    elif expected != observed:
        raise ValueError("Phase 5E replay differs")


def replay(models, report, pools, prior_sensitivity, signatures):
    train = balanced(pools["train"], report["rows"])
    views = pools | {"train": train}
    verify(report["identities"], {name: ids_sha256(rows) for name, rows in views.items()})
    rows = views["validation"]
    cal = predict_models(models, report, views["calibration"])
    scores = predict_models(models, report, rows)
    results = {}
    for name, values in scores.items():
        spec = report["models"][name]
        verify(spec["thresholds"], thresholds(views["calibration"], cal[name]))
        results[name] = evaluate(rows, values, spec["thresholds"])
        verify(spec["evaluation"], results[name])
    train_vectors = {signatures(row)[0] for row in train}
    mask = np.array([signatures(row)[0] not in train_vectors for row in rows])
    subset = [row for row, keep in zip(rows, mask, strict=True) if keep]
    first, second = (report["models"][name]["thresholds"] for name in ("url-ngram", "url-dom-fusion"))
    url, blend = (scores[name][mask] for name in ("url-ngram", "url-dom-fusion"))
    sensitivity = {"coverage": {"rows": len(subset), "positive": sum(row["label"] for row in subset),
                                "validationRows": len(rows), "excludedRepeatedVectors": int((~mask).sum())},
                   "url": evaluate(subset, url, first), "urlDomBlend": evaluate(subset, blend, second),
                   "pairedRecallAtOnePercent": paired_recall(subset, blend, second["0.01"]["threshold"],
                                                            url, first["0.01"]["threshold"])}
    verify(prior_sensitivity, sensitivity)
    return {"identities": report["identities"], "reproduced": results, "unseenExactVector": sensitivity}


def fixture_rows():
    from research.phase5e.acquire import HtmlWorker

    data = json.loads(subprocess.check_output(["node", "--input-type=module", "-e", """
        import {FIXTURES, ORIGIN} from './research/phase5e/fixtures.mjs';
        import {extractUrl} from './evaluation/features.mjs';
        import {destinationFor} from './extension/reputation.mjs';
        FIXTURES['dynamic-login-materialized'] = FIXTURES['dynamic-login'].replace(
          '</main>', '<form><input type="password"></form></main>');
        process.stdout.write(JSON.stringify(Object.entries(FIXTURES).map(([name, html]) => {
          const url = `${ORIGIN}/${name}`;
          return [name, html, destinationFor(url).key, extractUrl(url, 'synthetic').features];
        })));
    """], cwd=ROOT, encoding="utf-8"))
    with HtmlWorker() as worker:
        for name, html, url, vector in data:
            projection = worker.analyze(name, html, url)
            if projection["status"] != "usable":
                raise ValueError("Diagnostic fixture failed preprocessing")
            yield {"id": name, "partition": "diagnostic", "normalizedUrl": url,
                   "x": vector, "dom": projection["features"]}


def control_results(rows, scores, cuts):
    return {name: {row["id"]: {"score": float(value), "atHalf": bool(value >= 0.5),
                               "atConstraints": {key: None if point["threshold"] is None else
                                                 bool(value >= point["threshold"])
                                                 for key, point in cuts[name].items()}}
                   for row, value in zip(rows, values, strict=True)} for name, values in scores.items()}


def upstream_controls(experiments, rows):
    receipt = read(ROOT / "docs" / "experiments" / "phase5e" / "frozen-url.json")
    for path, expected in receipt["preprocessingSha256"].items():
        if path == "research/phase5d/evaluate.py":
            # Phase 5E moved neural imports into their call sites. Check the historical pin too.
            import hashlib
            current = subprocess.check_output(["git", "show", f'{receipt["revision"]}:{path}'], cwd=ROOT)
            actual = hashlib.sha256(current.replace(b"\r\n", b"\n")).hexdigest()
        else:
            actual = repository_hash(path)
        if actual != expected:
            raise ValueError("Upstream preprocessing checksum differs")
    scores = {}
    cuts = {}
    for name, spec in receipt["models"].items():
        if name == "fusion":
            scores[name] = apply_fusion(scores, spec)
        else:
            artifact = experiments / spec["artifact"]
            scores[name] = scorer(spec["kind"], artifact.parent, {"modelSha256": spec["sha256"]})(rows)
        cuts[name] = {key: {"threshold": point} for key, point in spec["operatingPoints"].items() if key != "fixed"}
    return control_results(rows, scores, cuts)
