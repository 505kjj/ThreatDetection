"""Project pinned PhreshPhish columns into private development or custody files."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from time import sleep
from paths import private

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from research.phase3c.project_phresh import DatasetRedirect, ParquetFile, RangeFile, REVISION, build_opener


TRAIN_COLUMNS = ("sha256", "url", "label", "target", "date", "lang")
CUSTODY_COLUMNS = ("sha256", "url")
PINS = Path(__file__).with_name("source-pins.json")


class ProjectionError(RuntimeError):
    """A safe aggregate acquisition error."""


def project(spec, columns):
    for delay in (0, 2, 5):
        if delay:
            sleep(delay)
        try:
            with RangeFile(spec["name"], spec["size"]) as source:
                rows = ParquetFile(source).read(columns=columns, use_threads=False)
                if tuple(rows.column_names) != columns:
                    raise ValueError("Unexpected projected schema")
                return rows.to_pylist(), source.bytes
        except OSError:
            if delay == 5:
                raise ProjectionError(f"Repeated range failure for {spec['name']}") from None


def acquire(side, output, limit=None):
    url = f"https://huggingface.co/api/datasets/phreshphish/phreshphish/tree/{REVISION}/data"
    with build_opener(DatasetRedirect()).open(url, timeout=30) as response:
        tree = json.load(response)
    count = 56 if side == "train" else 21
    specs = []
    for item in tree:
        if not re.fullmatch(fr"data/{side}-[0-9]{{3}}\.parquet", item["path"]):
            continue
        pin = item["lfs"]["oid"]
        if not re.fullmatch(r"[0-9a-f]{64}", pin) or item["size"] != item["lfs"]["size"]:
            raise ValueError("Invalid publisher LFS checksum or size")
        specs.append({"name": Path(item["path"]).stem, "size": item["size"],
                      "sourceSha256": pin, "gitBlob": item["oid"]})
    specs.sort(key=lambda spec: spec["name"])
    if [spec["name"] for spec in specs] != [f"{side}-{i:03d}" for i in range(count)]:
        raise ValueError("Pinned shard listing changed")
    pins = json.loads(PINS.read_bytes())
    received = [{"file": spec["name"] + ".parquet", "size": spec["size"],
                 "sha256": spec["sourceSha256"], "gitBlob": spec["gitBlob"]} for spec in specs]
    if pins["revision"] != REVISION or pins[side] != received:
        raise ValueError("Publisher shard metadata differs from source pins")
    columns = TRAIN_COLUMNS if side == "train" else CUSTODY_COLUMNS
    if limit is not None:
        if side != "train" or not 1 <= limit <= count:
            raise ValueError("Only a development probe can cap shards")
        specs = specs[:limit]

    output.mkdir(mode=0o700)
    consumer = None
    if side == "test":
        consumer = subprocess.Popen(
            ["node", str(Path(__file__).with_name("custody.mjs")), "phresh",
             str(output / "exclusions.jsonl")], stdin=subprocess.PIPE,
        )
    receipts = []
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            pending = [pool.submit(project, spec, columns) for spec in specs[:2]]
            for index, spec in enumerate(specs):
                rows, transferred = pending.pop(0).result()
                if index + 2 < len(specs):
                    pending.append(pool.submit(project, specs[index + 2], columns))
                block = b"".join((json.dumps(row, default=str, ensure_ascii=True) + "\n").encode()
                                 for row in rows)
                receipt = spec | {"rows": len(rows), "transferBytes": transferred}
                if consumer:
                    consumer.stdin.write(block)
                else:
                    file = output / (spec["name"] + ".jsonl")
                    with file.open("xb") as stream:
                        stream.write(block)
                    receipt |= {"file": file.name, "projectedSha256": sha256(block).hexdigest(),
                                "storedBytes": len(block)}
                receipts.append(receipt)
                print(f"{spec['name']} {len(rows)} rows {transferred} projected bytes", flush=True)
        if consumer:
            consumer.stdin.close()
            if consumer.wait():
                raise ProjectionError("Custody hash export failed")
        manifest = {"side": side, "revision": REVISION, "columns": columns, "shards": receipts}
        if consumer:
            artifact = output / "exclusions.jsonl"
            manifest["exclusionsSha256"] = sha256(artifact.read_bytes()).hexdigest()
        with (output / "manifest.json").open("x", encoding="utf-8") as stream:
            json.dump(manifest, stream, indent=2)
    finally:
        if consumer and consumer.poll() is None:
            consumer.kill()
            consumer.wait()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("side", choices=("train", "test"))
    parser.add_argument("output", type=private)
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()
    if os.environ.get("THREAT_PHASE3D_GUARDED") != "1":
        parser.error("Use the Windows Job Object resource guard")
    try:
        acquire(args.side, args.output, args.limit)
    except Exception as error:
        message = str(error) if isinstance(error, ProjectionError) else type(error).__name__
        raise SystemExit(f"Pinned projection failed: {message}") from None
