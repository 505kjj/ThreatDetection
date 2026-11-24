"""Verify reconstructed Phase 5B membership against frozen numerical exports."""

import argparse
from hashlib import sha256
import json
from pathlib import Path

import numpy as np

from paths import private
from train import ids_sha256
from benchmark import Rows, balance, external, unique_training
from experiment_data import load_partition, read_manifest


def records(path):
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            yield json.loads(line)


def verified_ids(raw, numeric, source, revision):
    if len(raw) != len(numeric.y):
        raise ValueError("Reconstructed row count differs")
    for i, row in enumerate(raw):
        feature_vector = (row["vector"] + [row["brand"]] if source == "phreshphish" else row["x"])
        if (row["label"] != numeric.y[i] or row["group"] != numeric.groups[i]
                or row.get("family", "") != numeric.families[i] or not np.array_equal(feature_vector, numeric.x[i])):
            raise ValueError("Ordered legacy numerical row differs from reconstruction")
        key = row["sourceId"] if source == "phreshphish" else f'{row["ordinal"]}:{row["sourceId"]}'
        row["id"] = sha256("\0".join((source, revision, key)).encode()).hexdigest()
    if len({row["id"] for row in raw}) != len(raw):
        raise ValueError("Reconstructed record identifiers are ambiguous")


def sample(raw, numerical, size):
    indexed = Rows(np.arange(len(raw)).reshape(-1, 1), numerical.y, numerical.groups, numerical.families)
    indices = balance(unique_training(indexed), size).x[:, 0]
    return [raw[i] for i in indices]


def verify(uci_raw, uci, phresh_raw, phresh, phase5b, protected, output):
    manifest = json.loads(phase5b.read_bytes())
    uci_source = read_manifest(uci)
    phresh_source = json.loads((phresh / "manifest.json").read_bytes())
    replay = json.loads((phresh_raw / "report.json").read_bytes())
    uci_rows = {"train": [], "validation": []}
    for row in records(uci_raw):
        uci_rows[row["partition"]].append(row)
    custody_manifest = json.loads((protected / "manifest.json").read_bytes())
    custody_file = protected / "exclusions.jsonl"
    if sha256(custody_file.read_bytes()).hexdigest() != custody_manifest["exclusionsSha256"]:
        raise ValueError("Exclusion digest mismatch")
    keys = {key: set() for key in ("id", "group", "family")}
    for row in records(custody_file):
        for key, members in keys.items():
            if row.get(key):
                members.add(row[key])
    audit = {"uci": {}, "phresh": {}, "mixed": {"verified": False}}
    mixed = []
    for source in ("uci", "phresh"):
        if source == "phresh" and not replay["verified"]:
            audit[source] = {"verified": False, "replay": replay["partitions"]}
            continue
        for partition in ("train", "validation"):
            key = source + partition.title() + "Sha256"
            if source == "uci":
                if manifest[key] != uci_source[partition]["sha256"]:
                    raise ValueError("UCI Phase 5B checksum mismatch")
                numeric = load_partition(uci, uci_source, partition)
                numerical = Rows(numeric.features, numeric.labels, numeric.groups,
                                 np.full(len(numeric.labels), "", dtype="U1"))
                raw = uci_rows[partition]
                verified_ids(raw, numerical, "phiusiil-uci-967", uci_source["sourceSha256"])
            else:
                spec = phresh_source["partitions"][partition]
                if manifest[key] != spec["sha256"]:
                    raise ValueError("PhreshPhish Phase 5B checksum mismatch")
                numerical = external(phresh, partition, spec)
                raw = list(records(phresh_raw / (partition + ".jsonl")))
                verified_ids(raw, numerical, "phreshphish", replay["revision"])
            selected = sample(raw, numerical, 20000) if partition == "train" else raw
            if partition == "train":
                mixed.extend(sample(raw, numerical, 10000))
            overlap = sum(row["sourceId"] in keys["id"] or row["group"] in keys["group"]
                          or row.get("family") in keys["family"] for row in selected)
            audit[source][partition] = {"rows": len(selected), "orderedIdsSha256": ids_sha256(selected),
                                        "fullPublisherTestOverlap": overlap}
        audit[source]["verified"] = True
    if len(mixed) == 20000:
        audit["mixed"] = {"verified": True, "rows": len(mixed), "orderedIdsSha256": ids_sha256(mixed)}
    with output.open("x", encoding="utf-8") as stream:
        json.dump(audit, stream, indent=2)
    print(json.dumps(audit), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ("uci_raw", "uci", "phresh_raw", "phresh", "phase5b", "protected", "output"):
        parser.add_argument(field, type=private)
    verify(**vars(parser.parse_args()))
