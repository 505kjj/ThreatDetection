"""Read only pinned, public PhishTank archive workbooks as historical metadata."""

import argparse
from collections import Counter
from datetime import date
from hashlib import file_digest
import json
import os
from pathlib import Path
import re
from urllib.parse import parse_qs, urlsplit
from xml.etree import ElementTree as ET
from zipfile import ZipFile

NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
HEADERS = {"A": "ID", "B": "Phish URL", "C": "Phish", "D": "Submitted Date"}
COLS = {*HEADERS, "G", "H"}
MONTHS = {part: index for index, part in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}
STAMP = re.compile(r"added on ([A-Z][a-z]{2}) (\d{1,2})(?:st|nd|rd|th) (\d{4}) \d{1,2}:\d{2} [AP]M")
PHISHTANK_HOSTS = {"phishtank.org", "www.phishtank.org", "phishtank.com", "www.phishtank.com"}
REPO = Path(__file__).resolve().parents[2]
PLAN = Path(__file__).with_name("protocol.json")


def sha256(path):
    with path.open("rb") as value:
        return file_digest(value, "sha256").hexdigest()


def private(path):
    path = path.resolve()
    if path.is_relative_to(REPO):
        raise ValueError("Data paths must be outside this Git worktree")
    return path


def open_xml(archive, name):
    member = archive.getinfo(name)
    if member.file_size > 220_000_000:
        raise ValueError("XLSX XML member exceeds the research budget")
    return archive.open(member)


def sheet_cells(archive):
    strings = []
    if "xl/sharedStrings.xml" in archive.namelist():
        with open_xml(archive, "xl/sharedStrings.xml") as xml:
            for _, element in ET.iterparse(xml, events=("end",)):
                if element.tag == NS + "si":
                    strings.append("".join(child.text or "" for child in element.iter(NS + "t")))
                    element.clear()
    with open_xml(archive, "xl/worksheets/sheet1.xml") as xml:
        for _, element in ET.iterparse(xml, events=("end",)):
            if element.tag != NS + "row":
                continue
            extracted = {}
            for cell in element:
                column = re.match(r"[A-Z]+", cell.get("r", ""))
                if not column or column[0] not in COLS or cell.find(NS + "f") is not None:
                    continue
                value = cell.findtext(NS + "v", "")
                if cell.get("t") == "s" and value:
                    value = strings[int(value)]
                elif cell.get("t") == "inlineStr":
                    value = "".join(child.text or "" for child in cell.iter(NS + "t"))
                extracted[column[0]] = value
            yield int(element.get("r", "0")), extracted
            element.clear()


def observation_day(value):
    match = STAMP.fullmatch(value.strip())
    if not match or match[1] not in MONTHS:
        return None
    try:
        return date(int(match[3]), MONTHS[match[1]], int(match[2])).isoformat()
    except ValueError:
        return None


def archive_record(row_number, row, source, audit, verdict_column):
    audit["rows"] += 1
    if row.get(verdict_column, "").strip() != "VALID PHISH":
        audit["notVerified"] += 1
        return None
    day = observation_day(row.get("D", ""))
    if not day:
        audit["invalidSubmissionDate"] += 1
        return None
    try:
        reference = urlsplit(row.get("B", ""))
        identifiers = parse_qs(reference.query).get("phish_id", [])
        url = row.get("C", "").strip()
        target = urlsplit(url)
    except ValueError:
        audit["invalidReferenceOrUrl"] += 1
        return None
    if (len(identifiers) != 1 or not re.fullmatch(r"[1-9][0-9]{0,11}", identifiers[0])
            or reference.scheme not in {"http", "https"} or reference.hostname not in PHISHTANK_HOSTS
            or reference.path != "/phish_detail.php" or reference.username or reference.password
            or target.scheme not in {"http", "https"} or not target.hostname or target.username or target.password):
        audit["invalidReferenceOrUrl"] += 1
        return None
    audit["retainedByEvidence"] += 1
    return {
        "id": f"pt-{identifiers[0]}", "url": url, "label": 1, "cohort": "general-transfer",
        "observedDay": day, "source": source, "evidence": row["B"], "sourceRow": row_number,
        "sourceSubmitted": row["D"], "sourceVerdict": "VALID PHISH", "verificationDay": None,
        "brand": None, "campaign": None, "kind": "source-verified-phish", "license": "CC BY 4.0",
    }


def project(files, directory):
    config = json.loads(PLAN.read_text(encoding="utf-8"))
    directory.mkdir()
    inventories = {}
    ledger = directory / "archive-ledger.jsonl"
    with ledger.open("x", encoding="utf-8", newline="\n") as output:
        for path in files:
            path = private(path)
            spec = config["archive"]["files"].get(path.name)
            if not spec or path.stat().st_size != spec["bytes"] or sha256(path) != spec["sha256"]:
                raise ValueError("Archive workbook does not match the pinned content")
            audit = Counter()
            days = []
            with ZipFile(path) as source:
                rows = sheet_cells(source)
                index, header = next(rows, (0, {}))
                verdict, rest = spec["labelColumn"], spec["statusColumn"]
                expected = HEADERS | {verdict: "VALID", rest: "Online/Offline"}
                if (index != 1 or header != expected):
                    raise ValueError("Archive worksheet schema changed")
                for index, row in rows:
                    if not row.get("C"):
                        continue
                    record = archive_record(index, row, spec["id"], audit, verdict)
                    if record:
                        days.append(record["observedDay"])
                        output.write(json.dumps(record, ensure_ascii=False) + "\n")
            if not days:
                raise ValueError("No valid provider evidence in a pinned source")
            inventories[spec["id"]] = dict(audit) | {
                "firstSubmissionDay": min(days), "lastSubmissionDay": max(days),
                "publisherBytes": spec["bytes"], "sha256": spec["sha256"], "publisherMd5": spec["md5"],
            }
    with (directory / "inventory.json").open("x", encoding="utf-8", newline="\n") as report:
        json.dump({"files": inventories, "ledgerSha256": sha256(ledger)}, report, indent=2)
        report.write("\n")
    print(json.dumps(inventories), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("workbooks", type=Path, nargs="+")
    args = parser.parse_args()
    if os.environ.get("THREAT_PHASE3D_GUARDED") != "1":
        parser.error("Run through the Windows research resource guard")
    try:
        project(args.workbooks, private(args.output))
    except (OSError, ValueError, KeyError) as error:
        raise SystemExit(f"Archive projection failed ({type(error).__name__}).") from None


if __name__ == "__main__":
    main()
