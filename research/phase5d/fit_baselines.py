"""Refit temporal baselines and the controlled 50:50 PhreshPhish/UCI model."""

import argparse
from hashlib import sha256
import json
import os

from threadpoolctl import threadpool_limits

from shared import balanced, ids_sha256, load_partition, private, protocol_bytes
from train import fit_model


def run(kind, source, destination, auxiliary):
    frozen = protocol_bytes()
    protocol = json.loads(frozen)
    pin = sha256(frozen).hexdigest()
    manifest_bytes = (source / "manifest.json").read_bytes()
    manifest = json.loads(manifest_bytes)
    train = load_partition(source, manifest, "train")
    train_size = protocol["temporalBalancedRows"]
    additional = None
    inputs_receipt = {}
    if kind == "mixed":
        if sha256(manifest_bytes).hexdigest() != protocol["phase5cManifestSha256"] or auxiliary is None:
            raise ValueError("Mixed run needs the pinned source and frozen adaptation views")
        target = json.loads((auxiliary / "manifest.json").read_bytes())
        if target["protocolSha256"] != pin:
            raise ValueError("Adaptation protocol changed")
        train_size = protocol["adaptationBalancedRows"] // 2
        additional = balanced(load_partition(auxiliary, target, "uci-adaptation"), train_size)
        inputs_receipt = {"targetTrainingViewSha256": target["partitions"]["uci-adaptation"]["sha256"],
                          "targetTrainingIdsSha256": ids_sha256(additional)}
        tuning = []
    else:
        if manifest["version"] != protocol["version"] or manifest["protocolSha256"] != pin:
            raise ValueError("Temporal protocol changed")
        tuning = load_partition(source, manifest, "tuning")
    selected = balanced(train, train_size)
    if additional is not None:
        selected = sorted(selected + additional, key=lambda row: row["id"])
    destination.mkdir(mode=0o700)
    with threadpool_limits(limits=2):
        _, metadata = fit_model("ngram" if kind == "mixed" else kind, selected, tuning, destination, False)
    report = {"kind": kind, "trainRows": len(selected), "trainIdsSha256": ids_sha256(selected),
              "manifestSha256": sha256(manifest_bytes).hexdigest(), "protocolSha256": pin,
              **inputs_receipt, **metadata}
    (destination / "fit.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: report[key] for key in ("kind", "trainRows", "fitSeconds")}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("ngram", "cnn", "xgboost", "mixed"))
    parser.add_argument("source", type=private)
    parser.add_argument("destination", type=private)
    parser.add_argument("--auxiliary", type=private)
    args = parser.parse_args()
    if os.environ.get("THREAT_PHASE3D_GUARDED") != "1":
        parser.error("Use the Windows Job Object resource guard")
    run(**vars(args))
