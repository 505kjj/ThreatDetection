"""Read and verify the private numeric export without using group IDs as predictors."""

from dataclasses import dataclass
from hashlib import file_digest
import json
from pathlib import Path
import re

import numpy as np


REPO = Path(__file__).resolve().parents[1]
IDENTITY_KEYS = ("dataset", "sourceSha256", "splitSeed", "referenceReportSha256", "featureVersion", "featureColumns")
DIGEST = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class Partition:
    features: np.ndarray
    labels: np.ndarray
    groups: np.ndarray


def private_path(path):
    resolved = Path(path).resolve()
    if resolved.is_relative_to(REPO):
        raise ValueError("Use a private data or model directory outside this Git worktree.")
    return resolved


def sha256(path):
    with Path(path).open("rb") as source:
        return file_digest(source, "sha256").hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path, value):
    with Path(path).open("x", encoding="utf-8", newline="\n") as output:
        json.dump(value, output, indent=2, allow_nan=False)
        output.write("\n")


def identity(manifest):
    return {name: manifest[name] for name in IDENTITY_KEYS}


def read_manifest(directory):
    manifest = read_json(directory / "manifest.json")
    expected = read_json(REPO / "evaluation/manifests/phiusiil-uci-967.json")
    baseline = REPO / "evaluation/reports/phiusiil-uci-967.json"
    if (
        manifest.get("dataset") != expected["dataset"]
        or manifest.get("sourceSha256") != expected["sources"][0]["sha256"]
        or manifest.get("splitSeed") != expected["split"]["seed"]
        or manifest.get("referenceReportSha256") != sha256(baseline)
        or manifest.get("featureVersion") != "url-lexical-v1"
        or manifest.get("featureColumns") != read_json(baseline)["featureSchema"]["columns"]
    ):
        raise ValueError("This export does not identify the pinned Phase 3A dataset.")
    return manifest


def load_partition(directory, manifest, name):
    expected = manifest[name]
    columns = manifest["featureColumns"]
    if expected["file"] != f"{name}.tsv":
        raise ValueError("Unexpected partition filename.")
    path = directory / expected["file"]
    if sha256(path) != expected["sha256"]:
        raise ValueError("Partition checksum does not match its manifest.")
    features, labels, groups = [], [], []
    with path.open("r", encoding="ascii") as source:
        for line in source:
            label, group, *values = line.rstrip("\n").split("\t")
            if label not in ("0", "1") or not DIGEST.fullmatch(group) or len(values) != len(columns):
                raise ValueError("Invalid numeric partition row.")
            vector = [int(value) for value in values]
            if any(value < 0 or value > 8192 for value in vector):
                raise ValueError("Invalid numeric feature range.")
            features.append(vector)
            labels.append(int(label))
            groups.append(group)
    if (sum(labels), len(labels) - sum(labels), len(set(groups))) != (
        expected["phishing"], expected["legitimate"], expected["groups"]
    ):
        raise ValueError("Partition counts do not match its manifest.")
    return Partition(np.asarray(features, dtype=np.float32), np.asarray(labels, dtype=np.int8),
                     np.asarray(groups, dtype="U64"))
