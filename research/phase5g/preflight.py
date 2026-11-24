"""Recheck freezes, sealed-archive documentation and prior benign controls offline."""

import argparse
import json
import os
import subprocess
from collections import Counter
from time import perf_counter
from zipfile import ZipFile

import numpy as np
from threadpoolctl import threadpool_limits

from frozen import DOCS, MULTIMODAL, ROOT, URL_MODELS, Frozen, freeze, read, hash_file, verify, write
from aggregate import evaluate
from paths import private
from replay import balanced, control_results, fixture_rows, ids_sha256
from compare import load_matched
from grouping import grouped_views
from metrics import evaluate as development_metrics

PROTOCOL = ROOT / "research" / "phase5g" / "protocol.json"


def inspect_phishvn(archive, protocol):
    policy = protocol["phishvn"]
    if archive.stat().st_size != policy["bytes"] or hash_file(archive) != policy["sha256"]:
        raise ValueError("PhishVN open archive does not match the publisher pin")
    if policy["lastEligibleSourceObservationDay"] >= protocol["minObservedDay"]:
        raise ValueError("PhishVN chronology needs a new eligibility review")
    with ZipFile(archive) as source:
        documents = {}
        for name in ("docs/schema.md", "docs/data_sources.md", "LICENSE", "CITATION.cff"):
            info = source.getinfo(name)
            if info.file_size > 64 * 1024:
                raise ValueError("Public archive documentation exceeded its bound")
            documents[name] = source.read(info).decode("utf-8")
        if (policy["lastEligibleSourceObservationDay"] not in documents["docs/data_sources.md"]
                or "scraped_at" not in documents["docs/schema.md"]
                or "CC BY 4.0" not in documents["LICENSE"]
                or f'doi: {policy["doi"]}' not in documents["CITATION.cff"]
                or 'given-names: Thai' not in documents["CITATION.cff"]
                or 'family-names: "Nguyen Vu"' not in documents["CITATION.cff"]):
            raise ValueError("PhishVN publisher documentation differs from the preflight")
        entries = len(source.infolist())
    return {"status": "ineligible-for-registered-forward-test", "release": policy, "zipEntries": entries,
            "publisherDocumentationMembersOpened": len(documents), "protectedRowsOpened": 0, "rowsScored": 0,
            "forwardWindowFirstDay": protocol["minObservedDay"]}


def project_urls(urls):
    data = "".join(json.dumps(url, ensure_ascii=True) + "\n" for url in urls)
    result = subprocess.run(["node", str(ROOT / "research" / "phase5g" / "project.mjs")], input=data,
                            text=True, encoding="utf-8", capture_output=True, check=False)
    if result.returncode:
        raise ValueError("Private URL projection failed")
    projected = [json.loads(line) for line in result.stdout.splitlines()]
    if len(projected) != len(urls):
        raise ValueError("Private URL projection length differs")
    return projected


def score_controls(models, points, experiments, prevalences):
    directory = experiments / "phase-3e-v1"
    ledger = directory / "official-controls.jsonl"
    evidence = directory / "official-cohort" / "frozen.json"
    if (hash_file(ledger) != "5509ff9c5378bcc44d6d115f042045b2f01139aa9c0005f8a1e0ee1657ade9ad"
            or hash_file(evidence) != "0ef4cd9e7e30c4d504484bda0a537e5fcaabfe8103a8dcb35d34cfe24bb56b6e"):
        raise ValueError("Phase 3E official control ledger changed")
    source = [json.loads(line) for line in ledger.read_text(encoding="utf-8-sig").splitlines()]
    if any(row["source"] != "official-india" or row["cohort"] != "india-control" or row["label"] != 0
           or not row["license"].startswith("Internal analysis of public factual URL locators") for row in source):
        raise ValueError("Earlier control ledger provenance differs")
    canonical = project_urls([row["url"] for row in source])
    if any(row is None for row in canonical):
        raise ValueError("Earlier official control URL no longer projects")
    rows = [row | {"id": item["id"], "partition": "historical-control", "label": 0}
            for row, item in zip(canonical, source, strict=True)]
    url = models.url_scores(rows)
    url["financial-rules"] = np.array([row["amber"] for row in rows], dtype=float)
    cuts = {name: points[name] for name in URL_MODELS} | {"financial-rules": {"fixed": 0.5}}
    findings = evaluate(rows, url, cuts, prevalences)
    fallback = models.fallback(rows)
    finding_fallback = evaluate(rows, {key: fallback for key in MULTIMODAL},
                                {key: points[key] for key in MULTIMODAL}, prevalences)
    return {"status": "previously-observed-url-only-controls", "ledgerSha256": hash_file(ledger),
            "phase3eControlFreezeSha256": hash_file(evidence), "dateCounts": dict(Counter(row["observedDay"] for row in source)),
            "providerCount": len({row["brand"] for row in source}), "missingDomRows": len(rows),
            "urlAndFinancialRules": findings, "urlFallbackAtMultimodalCuts": finding_fallback,
            "freshIndependent": False}


def replay_development(models, experiments, expected):
    directory = experiments / "phase-5e-v1"
    projections = [directory / name for name in ("html-pilot-final", "html-20k")]
    for path, manifest in zip(projections, read(DOCS / "phase5e" / "results.json")["projections"], strict=True):
        verify(manifest, read(path / "manifest.json"))
    pools, audit = load_matched(experiments / "phase-5c-v1" / "cohort", projections)
    verify(read(DOCS / "phase5e" / "results.json")["scale20k"]["audit"], audit)
    grouped, report = grouped_views(pools)
    verify(expected["grouping"], report)
    grouped["train"] = balanced(grouped["train"], expected["rows"]["train"])
    verify(expected["memberships"], {part: ids_sha256(rows) for part, rows in grouped.items()})
    rows = grouped["validation"]
    for name, scores in models.multimodal_scores(rows).items():
        actual = development_metrics(rows, scores, expected["thresholds"][name])
        verify(expected["evaluation"][name], actual)
    return {"viewsVerified": len(grouped), "validationRows": len(rows), "multimodalCandidatesReplayed": list(MULTIMODAL)}


def preflight(experiments, output):
    protocol = read(PROTOCOL)
    output.mkdir()
    with threadpool_limits(limits=2):
        start = perf_counter()
        registry = freeze(experiments)
        write(output / "frozen-models.json", registry)
        models = Frozen(experiments, registry)
        restored_seconds = perf_counter() - start
        archive = experiments / "phase-5f-v1" / "PhishVN_v3.1.1_open.zip"
        eligibility = inspect_phishvn(archive, protocol)
        spec = {name: item["operatingPoints"] for name, item in registry["models"].items()}
        fixtures = list(fixture_rows())
        scores = models.url_scores(fixtures) | models.multimodal_scores(fixtures)
        expected = read(DOCS / "phase5f" / "results.json")
        cuts = {name: {key: {"threshold": point} for key, point in spec[name].items() if key != "fixed"}
                for name in scores}
        fixtures_report = control_results(fixtures, scores, cuts)
        for name in URL_MODELS:
            verify(expected["upstreamFrozenUrlControls"][name], fixtures_report[name])
        for name in MULTIMODAL:
            verify(expected["grouped"]["diagnosticControls"][name], fixtures_report[name])
        verification = replay_development(models, experiments, expected["grouped"])
        controls = score_controls(models, spec, experiments, protocol["prevalenceScenarios"])
    write(output / "preflight.json", {"registrySha256": hash_file(output / "frozen-models.json"),
                                      "restorationAndVerificationSeconds": restored_seconds,
                                      "developmentVerification": verification,
                                      "phishvn": eligibility, "historicalControls": controls,
                                      "syntheticDiagnosticReplay": fixtures_report,
                                      "freshIndependentRowsScored": 0, "freshPairedRowsScored": 0,
                                      "independentFinancialPositives": {"india": 0, "outsideIndia": 0}})
    print("Verified eight frozen candidates, eight diagnostic fixtures, and historical URL-only controls", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("experiments", type=private)
    parser.add_argument("output", type=private)
    args = parser.parse_args()
    if os.environ.get("THREAT_PHASE3D_GUARDED") != "1":
        parser.error("Use the Windows Job Object resource guard")
    preflight(**vars(args))
