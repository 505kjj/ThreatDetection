"""Score a signed, adjudicated external cohort once inside custodian-controlled storage."""

import argparse
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta
from hashlib import sha256
import json
import os
import re
import subprocess

from threadpoolctl import threadpool_limits

from frozen import DOCS, HISTORY, MULTIMODAL, REGISTRY, ROOT, URL_MODELS, Frozen, freeze, hash_file, read, verify, write
from research.phase5g.preflight import PROTOCOL, project_urls
from aggregate import evaluate
from paths import private
from compare import load_matched
from grouping import AXES, FAMILY_COLUMNS, signatures
from research.phase5e.acquire import HtmlWorker

IDENTITIES = ("exact", "alias", "group", "family", "campaign")
COHORTS = ("general-phishing", "india-financial", "non-india-financial", "benign-auth-payment")
CHECKS = ("independentCustody", "authorizedResearchAndAggregates", "labelAdjudication",
          "sourceLineageReview", "campaignOverlapReview", "priorEvaluationExposureReview")
HEX = re.compile(r"[a-f0-9]{64}\Z")


def is_digest(value):
    return isinstance(value, str) and HEX.fullmatch(value) is not None


def utc_day(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", value):
        return None
    try:
        return datetime.fromisoformat(value).date().isoformat()
    except ValueError:
        return None


def stable_hash(path):
    return sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def check_receipt(receipt, state, protocol, registry, ledger, release, evidence):
    if (receipt.get("schema") != protocol["schema"] or receipt.get("registrySha256") != stable_hash(registry)
            or receipt.get("protocolSha256") != stable_hash(PROTOCOL)
            or release.stat().st_size > 512 * 1024 * 1024 or receipt.get("sourceArtifactSha256") != hash_file(release)
            or ledger.stat().st_size > protocol["maxLedgerBytes"] or receipt.get("ledgerSha256") != hash_file(ledger)
            or any(receipt.get("checks", {}).get(name) is not True for name in CHECKS)
            or evidence.stat().st_size > protocol["maxLedgerBytes"]
            or receipt.get("evidenceRegisterSha256") != hash_file(evidence)):
        raise ValueError("Custody receipt failed required checks or digest binding")
    if receipt["sourceArtifactSha256"] == protocol["phishvn"]["sha256"]:
        raise ValueError("The pinned PhishVN v5 archive failed the registered forward-test eligibility check")
    review = date.fromisoformat(receipt["reviewedDay"])
    if review < date.fromisoformat(protocol["registrationDay"]) or review > date.today() + timedelta(days=1):
        raise ValueError("Independent review date is outside its admissible window")
    return state / (receipt["sourceArtifactSha256"] + ".started.json")


def signed_receipt(path, signature, signers, protocol):
    if path.stat().st_size > 64 * 1024 or signature.stat().st_size > 32 * 1024:
        raise ValueError("Custodian receipt exceeds its size bound")
    document = path.read_bytes()
    result = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(signers), "-I", "phase5g-custodian",
                             "-n", protocol["scoringNamespace"], "-s", str(signature)], input=document,
                            capture_output=True, check=False)
    if result.returncode:
        raise ValueError("Custodian signature verification failed")
    return json.loads(document)


def stream_rows(path, bound=32768):
    with path.open("rb") as stream:
        for line in iter(lambda: stream.readline(bound + 1), b""):
            if len(line) > bound:
                raise ValueError("Private row exceeded its size bound")
            yield json.loads(line)


def prior_index(experiments):
    tokens = {key: set() for key in IDENTITIES}

    def add(entry):
        for key, values in tokens.items():
            value = entry.get(key)
            if value:
                if not is_digest(value):
                    raise ValueError("Unexpected digest in frozen history")
                values.add(value)

    for name, digest in HISTORY.items():
        source = experiments / name
        if hash_file(source) != digest:
            raise ValueError("Frozen overlap source checksum differs")
        if source.suffix == ".jsonl":
            for item in stream_rows(source):
                add(item)
            continue
        spec = read(source)
        if "partitions" in spec:
            for part, entry in spec["partitions"].items():
                path = source.with_name(part + ".jsonl")
                if hash_file(path) != entry["sha256"]:
                    raise ValueError("Prior identity partition checksum differs")
                for row in stream_rows(path):
                    add(row["identity"] | {"campaign": row.get("campaign")})
        else:
            path = source.with_name("exclusions.jsonl")
            if hash_file(path) != spec["exclusionsSha256"]:
                raise ValueError("Publisher holdout exclusion digest differs")
            for item in stream_rows(path):
                add(item)
    return tokens


def eligibility(row, protocol, receipt):
    cohort, label = row.get("cohort"), row.get("label")
    if cohort not in COHORTS or type(label) is not int or label not in (0, 1):
        return "unknown-cohort-or-label"
    if cohort == "benign-auth-payment" and label != 0:
        return "conflicting-control-label"
    observed, verified = row.get("observedDay"), row.get("verifiedDay")
    try:
        if any(date.fromisoformat(day).isoformat() != day for day in (observed, verified)):
            return "missing-or-invalid-dates"
    except (ValueError, TypeError):
        return "missing-or-invalid-dates"
    if not protocol["minObservedDay"] <= observed <= verified <= receipt["reviewedDay"]:
        return "outside-observation-or-verification-window"
    if any(not is_digest(row.get(key)) for key in ("sourceRecordSha256", "verificationEvidenceSha256", "rightsEvidenceSha256")):
        return "missing-evidence"
    if label and (row.get("evidenceClass") != "verified-credential-phishing" or not is_digest(row.get("campaign"))):
        return "unverified-phishing-or-campaign"
    if not label and (row.get("evidenceClass") != "verified-legitimate" or not is_digest(row.get("ownershipEvidenceSha256"))):
        return "unverified-benign-or-owner"
    if label and cohort in COHORTS[1:3]:
        country = row.get("verifiedTargetCountry", "")
        if (not isinstance(country, str) or not re.fullmatch(r"[A-Z]{2}", country)
                or (cohort == "india-financial") != (country == "IN")
                or not is_digest(row.get("financialTargetEvidenceSha256"))
                or not is_digest(row.get("verifiedInstitutionId")) or utc_day(row.get("observedAt")) != observed):
            return "unverified-financial-target-or-country"
    return None


def historical_dom(experiments):
    directory = experiments / "phase-5e-v1"
    names = ("html-pilot-final", "html-20k")
    spec = read(DOCS / "phase5e" / "results.json")["projections"]
    projections = [directory / name for name in names]
    for path, expected in zip(projections, spec, strict=True):
        verify(expected, read(path / "manifest.json"))
    pools, _ = load_matched(experiments / "phase-5c-v1" / "cohort", projections)
    return {signatures(row)[1] for rows in pools.values() for row in rows}


def template_overlap(row, history):
    vector = signatures(row)[1]
    if vector in history:
        return True
    for axis in AXES:
        index = FAMILY_COLUMNS.index(axis)
        for step in (-1, 1):
            neighbor = vector[index] + step
            if min(vector[index], neighbor) > 0 and vector[:index] + (neighbor,) + vector[index + 1:] in history:
                return True
    return False


def content(raw, row, folder, worker, dom_history, review):
    entry = raw.get("capture")
    if not entry or folder is None:
        return "no-authorized-capture"
    if (not isinstance(entry, dict) or not is_digest(entry.get("sha256"))
            or not is_digest(entry.get("rightsEvidenceSha256")) or not is_digest(entry.get("templateEvidenceSha256"))
            or entry.get("urlDigest") != row["identity"]["exact"]):
        return "capture-provenance-or-alignment"
    captured = utc_day(entry.get("capturedAt"))
    if captured != raw["observedDay"] or captured > review:
        return "capture-timestamp"
    path = (folder / (entry["sha256"] + ".html")).resolve()
    if not path.is_relative_to(folder) or not path.is_file() or path.stat().st_size > 1024 * 1024:
        return "missing-or-oversized-capture"
    data = path.read_bytes()
    if sha256(data).hexdigest() != entry["sha256"]:
        return "capture-digest"
    try:
        projection = worker.analyze(row["id"], data.decode("utf-8", errors="strict"), row["normalizedUrl"])
    except UnicodeDecodeError:
        return "capture-encoding"
    if projection["status"] != "usable":
        return "parser-" + projection["status"]
    candidate = row | {"dom": projection["features"]}
    if template_overlap(candidate, dom_history):
        return "prior-numeric-template"
    row["dom"] = candidate["dom"]
    return "usable"


def eligible_rows(ledger, history, receipt, protocol):
    counts = Counter()
    selected = []
    for i, raw in enumerate(stream_rows(ledger), 1):
        if i > protocol["maxRows"] or not isinstance(raw, dict):
            raise ValueError("Private ledger exceeds limits or has invalid rows")
        reason = eligibility(raw, protocol, receipt)
        if reason:
            counts[reason] += 1
        else:
            selected.append(raw)
    urls = project_urls([raw.get("url") for raw in selected])
    rows_by_alias = defaultdict(list)
    for raw, projection in zip(selected, urls, strict=True):
        if projection is None:
            counts["invalid-original-absolute-url"] += 1
            continue
        identity = projection["identity"] | {"campaign": raw.get("campaign")}
        hits = [key for key in IDENTITIES if identity.get(key) and identity[key] in history[key]]
        if hits:
            counts["prior-overlap"] += 1
            counts.update("prior-" + key for key in hits)
            continue
        row = projection | {"identity": identity, "id": raw["sourceRecordSha256"], "partition": "external",
                            "label": raw["label"], "cohort": raw["cohort"]}
        rows_by_alias[identity["alias"]].append((raw, row))
    # Exclude all duplicate aliases, including cross-stratum and conflicting labels.
    unique = []
    for members in rows_by_alias.values():
        if len(members) == 1:
            unique.append(members[0])
        else:
            counts["duplicate-alias"] += len(members)
    if len({row["id"] for _, row in unique}) != len(unique):
        raise ValueError("Custody ledger has duplicate source record digests")
    memberships = defaultdict(set)
    grouping = ("group", "family", "campaign")
    for _, row in unique:
        for key in grouping:
            if token := row["identity"].get(key):
                memberships[(key, token)].add(row["cohort"])
    admitted = []
    for raw, row in unique:
        if any(len(memberships[(key, row["identity"].get(key))]) > 1 for key in grouping):
            counts["cross-cohort-identity"] += 1
        else:
            admitted.append((raw, row))
    counts["admitted"] = len(admitted)
    return admitted, dict(counts)


def run(experiments, registry, receipt, signature, signers, ledger, release, evidence, state, captures):
    protocol = read(PROTOCOL)
    signed = signed_receipt(receipt, signature, signers, protocol)
    attempt = check_receipt(signed, state, protocol, registry, ledger, release, evidence)
    if attempt.exists():
        raise ValueError("This source already has a registered scoring attempt in custodian storage")
    locked = read(registry)
    verify(read(REGISTRY), locked)
    verify(freeze(experiments), locked)
    with threadpool_limits(limits=2):
        history = prior_index(experiments)
        admitted, reasons = eligible_rows(ledger, history, signed, protocol)
        if not admitted:
            write(attempt.with_name(attempt.name.replace(".started.", ".eligibility.")), {
                "custodyReceiptSha256": hash_file(receipt), "eligibility": reasons, "rowsScored": 0})
            return
        models = Frozen(experiments, locked)
        write(attempt, {"registrySha256": stable_hash(registry), "receiptSha256": hash_file(receipt),
                        "sourceArtifactSha256": signed["sourceArtifactSha256"]})
        statuses = Counter()
        if captures is not None:
            dom_history = historical_dom(experiments)
            with HtmlWorker() as worker:
                for raw, row in admitted:
                    statuses[content(raw, row, captures, worker, dom_history, signed["reviewedDay"])] += 1
        else:
            statuses["no-authorized-capture"] = len(admitted)
        points = {name: item["operatingPoints"] for name, item in locked["models"].items()}
        results = {}
        for cohort in COHORTS:
            rows = [row for _, row in admitted if row["cohort"] == cohort]
            if not rows:
                continue
            p = protocol["prevalenceScenarios"]
            url = models.url_scores(rows)
            paired = [row for row in rows if row.get("dom") is not None]
            missing = [row for row in rows if row.get("dom") is None]
            paired_scores = models.url_scores(paired) | models.multimodal_scores(paired) if paired else {}
            fallback = models.fallback(missing) if missing else None
            results[cohort] = {"url": evaluate(rows, url, points, p), "missingDomRows": len(missing),
                               "missingDomRate": len(missing) / len(rows), "abstentionRate": 0,
                               "pairedOnly": evaluate(paired, paired_scores, points, p),
                               "fallbackOnly": evaluate(missing, {name: fallback for name in MULTIMODAL}, points, p)}
    write(attempt.with_name(attempt.name.replace(".started.", ".results.")), {
        "custodyReceiptSha256": hash_file(receipt), "eligibility": reasons,
        "historicalIdentitySupport": {key: len(values) for key, values in history.items()},
        "captureStatus": dict(statuses), "cohorts": results,
        "historicalIncrementalProtection": "unsupported-without-matched-time-valid-snapshots"})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("experiments", "registry", "receipt", "signature", "signers", "ledger", "release", "evidence", "state"):
        parser.add_argument("--" + name, type=private, required=True)
    parser.add_argument("--captures", type=private)
    args = parser.parse_args()
    if os.environ.get("THREAT_PHASE3D_GUARDED") != "1":
        parser.error("Use the Windows Job Object resource guard")
    try:
        run(**vars(args))
    except (KeyError, OSError, TypeError, ValueError):
        parser.error("Custody run failed. Review the signed inputs, pins or attempt receipt inside custody.")
