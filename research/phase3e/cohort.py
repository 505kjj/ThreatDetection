"""Project the approved URL metadata to private vectors and freeze the source identities."""

import argparse
from collections import Counter
import csv
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import re
import subprocess
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[2]
PROTOCOL = Path(__file__).with_name("protocol.json")
PHASE3D = ROOT / "docs/experiments/phase3d/summary.json"


def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def checksum(path):
    return sha256(path.read_bytes()).hexdigest()


def private(path):
    path = path.resolve()
    if path.is_relative_to(ROOT):
        raise ValueError("Keep private inputs and outputs outside the repository")
    return path


def write(path, data):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(data, stream, indent=2, allow_nan=False)
        stream.write("\n")


def phishvn(archive, policy, window, audit):
    if archive.stat().st_size > 8 * 1024 * 1024 or checksum(archive) != policy["archiveSha256"]:
        raise ValueError("Archive does not match the publisher SHA-256")
    with ZipFile(archive) as source:
        table, = (member for member in source.infolist() if member.filename.endswith("/dataset_url.csv"))
        if table.file_size > 40 * 1024 * 1024:
            raise ValueError("Publisher metadata table exceeds the read budget")
        with io.TextIOWrapper(source.open(table), encoding="utf-8-sig", newline="") as data:
            for row in csv.DictReader(data):
                audit["publisherRows"] += 1
                positive = (row["source"] == policy["positiveSource"] and row["label"] == "phishing"
                            and row["tier"] == policy["minimumPositiveTier"])
                negative = (row["source"] in policy["negativeSources"] and row["label"] == "benign"
                            and row["tier"] == policy["negativeTier"])
                if not (positive or negative):
                    audit["outsideApprovedSourcesOrTier"] += 1
                    continue
                day = row["collected_at"][:10]
                if not window["firstDay"] <= day <= window["lastDay"]:
                    audit["outsideObservationWindow"] += 1
                    continue
                # Inferred scenario tokens are an analysis stratum, not adjudicated brand identity.
                scenario = "bank-token" if row["scenario"] == "bank" else "unverified"
                source_id = "phishvn-ncsc" if positive else "phishvn-trusted"
                audit[source_id] += 1
                yield {
                    "url": row["url"], "id": row["id"].lower(), "label": int(positive), "observedDay": day,
                    "source": source_id, "evidence": "PhishVN V5 record and original source status",
                    "providerSource": row["source"], "providerStatus": row["status"], "providerTier": row["tier"],
                    "license": "CC BY 4.0 open metadata release", "brand": scenario, "cohort": "external",
                }


def verified_controls(path):
    with path.open(encoding="utf-8-sig") as stream:
        for line in stream:
            row = json.loads(line)
            if (row["source"] != "official-india" or row["cohort"] != "india-control"
                    or not row.get("license") or not row.get("evidence", "").startswith("https://")
                    or not re.fullmatch(r"(icici|axis|sbi|hdfc|npci|razorpay|kotak|payu|cashfree|phonepe|upi)", row["brand"])):
                raise ValueError("Invalid recorded official control evidence")
            yield row


def prepare(args):
    config = read(PROTOCOL)
    previous = read(PHASE3D)
    for candidate in config["candidateOrder"]:
        item = previous["candidates"][candidate]["fit"]
        available = {entry["targetNegativeDomainFpr"] for entry in item["cutoffs"] if entry["threshold"] is not None}
        if available != {config["primaryDomainTarget"], config["secondaryDomainTarget"]}:
            raise ValueError("Published frozen cutoffs are incomplete")
    output = private(args.output)
    output.mkdir()
    audit = Counter()
    ledger = output / "evidence.jsonl"
    with ledger.open("x", encoding="utf-8", newline="\n") as stream:
        if args.archive:
            for row in phishvn(private(args.archive), config["sourcePolicy"], config["window"], audit):
                stream.write(json.dumps(row, ensure_ascii=False) + "\n")
        for row in verified_controls(private(args.controls)):
            audit["officialControlsEntered"] += 1
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")
    rows = output / "numeric.jsonl"
    # The Node process is a child of the guarded job. It never fetches a supplied URL.
    command = ["node", str(Path(__file__).with_name("prepare.mjs")), *(str(private(folder)) for
               folder in (args.uci, args.phase3c, args.phase3d)), str(ledger), str(rows), str(PROTOCOL)]
    features = json.loads(subprocess.check_output(command, text=True))
    if features["featureVersion"] != config["featureVersion"]:
        raise ValueError("Projection feature version differs")
    freeze = {
        "protocolSha256": checksum(PROTOCOL), "phase3dSummarySha256": checksum(PHASE3D),
        "archiveSha256": config["sourcePolicy"]["archiveSha256"] if args.archive else None,
        "officialControlsSha256": checksum(private(args.controls)), "privateEvidenceSha256": checksum(ledger),
        "acquisition": dict(audit), "projection": features,
        "calibrationRowsUsed": 0,
    }
    write(output / "frozen.json", freeze)
    print(json.dumps({"acquisition": dict(audit), "projection": features["counts"]}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("uci", "phase3c", "phase3d", "controls", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args()
    if os.environ.get("THREAT_PHASE3D_GUARDED") != "1":
        parser.error("Run with the Windows resource guard")
    try:
        prepare(args)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit(f"Private preparation failed ({type(error).__name__}).") from None


if __name__ == "__main__":
    main()
