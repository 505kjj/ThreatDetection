"""Bounded projection of authorized PhreshPhish training HTML into numeric DOM records."""

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from hashlib import file_digest
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from threading import Lock
from time import perf_counter, sleep
from urllib.request import Request

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "research" / "phase5c")]
from paths import private
from research.phase3c.project_phresh import ParquetFile, RangeFile, REVISION

PARTITIONS = ("train", "tuning", "calibration", "validation")
PHASE5C_PIN = "b05c458d47a7840a484419bb2f20953728e9171cb7557eb3158b6a43ccee86ac"
MAX_DOCUMENT = 1024 * 1024
MAX_READ = 620 * 1024 * 1024
RANGE_BLOCK = 32 * 1024 * 1024


def digest(path):
    with path.open("rb") as stream:
        return file_digest(stream, "sha256").hexdigest()


def load(path):
    return json.loads(path.read_bytes())


def checked_rows(path, expected):
    if digest(path) != expected:
        raise ValueError("Private source checksum differs")
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            yield json.loads(line)


def inputs(previous):
    canonical = previous / "cohort"
    if digest(canonical / "manifest.json") != PHASE5C_PIN:
        raise ValueError("Expected frozen Phase 5C canonical data")
    spec = load(canonical / "manifest.json")
    members = {}
    for part in PARTITIONS:
        count = 0
        for row in checked_rows(canonical / (part + ".jsonl"), spec["partitions"][part]["sha256"]):
            if row["partition"] != part or row["source"] != "phreshphish" or row["revision"] != REVISION:
                raise ValueError("Invalid canonical development record")
            if row["sourceId"] in members:
                raise ValueError("Ambiguous canonical publisher ID")
            members[row["sourceId"]] = (row["id"], row["normalizedUrl"], part, row["label"])
            count += 1
        if count != spec["partitions"][part]["rows"]:
            raise ValueError("Canonical partition count differs")
    projection = previous / "phresh-development"
    provenance = load(projection / "manifest.json")
    pins = load(ROOT / "research" / "phase5c" / "source-pins.json")
    if provenance["side"] != "train" or provenance["revision"] != REVISION or pins["revision"] != REVISION:
        raise ValueError("Only the frozen publisher train release is permitted")
    shards = provenance["shards"]
    if len(shards) != len(pins["train"]):
        raise ValueError("Shard listing length changed")
    for shard, pin in zip(shards, pins["train"], strict=True):
        if (shard["name"] + ".parquet" != pin["file"] or shard["file"] != shard["name"] + ".jsonl"
                or shard["sourceSha256"] != pin["sha256"] or shard["size"] != pin["size"]):
            raise ValueError("Development shard pin changed")
    return members, projection, {shard["name"]: shard for shard in shards}


class Remaining:
    def __init__(self, limit):
        self.limit = limit
        self.received = 0
        self.active = 0
        self.lock = Lock()


class ContentRanges(RangeFile):
    def __init__(self, name, length, budget):
        if not re.fullmatch(r"train-[0-9]{3}", name):
            raise ValueError("Only pinned development shard names are permitted")
        super().__init__(name, length)
        self.budget = budget

    def read_block(self, start, length, target):
        end = start + length - 1
        request = Request(f"{self.url}?part={start}-{end}", headers={
            "Range": f"bytes={start}-{end}", "Accept-Encoding": "identity",
            "User-Agent": "ThreatDetection-offline-dom-research"
        })
        for delay in (0, 1, 3):
            if delay:
                sleep(delay)
            with self.budget.lock:
                if self.budget.received + self.budget.active + length > self.budget.limit:
                    raise OSError("Transfer budget exhausted")
                self.budget.active += length
            cursor = 0
            try:
                with self.opener.open(request, timeout=40) as response:
                    if (response.status != 206
                            or response.headers.get("Content-Range") != f"bytes {start}-{end}/{self.length}"):
                        raise OSError("Storage server did not honor the requested range")
                    while cursor < length:
                        chunk = response.read(min(1024 * 1024, length - cursor))
                        if not chunk:
                            raise OSError("Incomplete range")
                        target[cursor:cursor + len(chunk)] = chunk
                        cursor += len(chunk)
                        with self.budget.lock:
                            self.bytes += len(chunk)
                            self.budget.received += len(chunk)
                            self.budget.active -= len(chunk)
                return
            except OSError:
                if delay == 3:
                    raise OSError("Pinned storage range repeatedly failed") from None
            finally:
                with self.budget.lock:
                    self.budget.active -= length - cursor

    def read(self, size=-1):
        count = min(size if size >= 0 else self.length, self.length - self.position)
        if not count:
            return b""
        if count > MAX_READ or self.budget.received + count > self.budget.limit:
            raise OSError("Projected chunk or transfer exceeds budget")
        result = bytearray(count)
        view = memoryview(result)
        if count <= RANGE_BLOCK:
            self.read_block(self.position, count, view)
        else:
            with ThreadPoolExecutor(max_workers=2) as workers:
                pending = []
                for offset in range(0, count, RANGE_BLOCK):
                    length = min(RANGE_BLOCK, count - offset)
                    pending.append(workers.submit(self.read_block, self.position + offset, length,
                                                  view[offset:offset + length]))
                for block in pending:
                    block.result()
        self.position += count
        return bytes(result)


class HtmlWorker:
    def __enter__(self):
        self.process = subprocess.Popen(["node", str(Path(__file__).with_name("worker.mjs"))],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        text=True, encoding="utf-8", errors="strict")
        return self

    def analyze(self, id_, html, url):
        start = perf_counter()
        self.process.stdin.write(json.dumps({"id": id_, "html": html, "url": url}, ensure_ascii=False) + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        if not line:
            raise RuntimeError("Offline HTML worker closed before returning numeric features")
        result = json.loads(line)
        if result["id"] != id_:
            raise RuntimeError("Offline HTML worker returned a different record ID")
        result["pipelineMs"] = (perf_counter() - start) * 1000
        return result

    def __exit__(self, kind, value, traceback):
        self.process.stdin.close()
        if kind is not None and self.process.poll() is None:
            self.process.kill()
        if self.process.wait(timeout=10) and kind is None:
            raise RuntimeError("Offline HTML worker did not close cleanly")
        self.process.stdout.close()


def document(worker, item, member):
    id_, url, partition, label = member
    if not item.is_valid:
        result = {"id": id_, "status": "missing"}
    else:
        payload = item.as_buffer()
        if len(payload) > MAX_DOCUMENT:
            result = {"id": id_, "status": "oversized"}
        else:
            result = worker.analyze(id_, item.as_py(), url)
    return result | {"partition": partition, "label": label}


def collect_shard(shard, members, projection, output, budget, worker):
    started = perf_counter()
    local = list(checked_rows(projection / shard["file"], shard["projectedSha256"]))
    ids = [row["sha256"] for row in local]
    if len(ids) != shard["rows"] or len(set(ids)) != len(ids):
        raise ValueError("Pinned metadata row count or ID uniqueness changed")
    statuses = Counter()
    coverage = Counter()
    file = output / (shard["name"] + ".jsonl")
    with ContentRanges(shard["name"], shard["size"], budget) as remote, file.open("xb") as sink:
        parquet = ParquetFile(remote, pre_buffer=False)
        if parquet.metadata.num_rows != len(ids) or not {"sha256", "html"}.issubset(parquet.schema.names):
            raise ValueError("Publisher HTML schema or row count changed")
        index = 0
        selected_groups = 0
        for group in range(parquet.metadata.num_row_groups):
            rows = parquet.metadata.row_group(group).num_rows
            group_ids = ids[index:index + rows]
            if not any(id_ in members for id_ in group_ids):
                index += rows
                continue
            selected_groups += 1
            for batch in parquet.iter_batches(batch_size=16, row_groups=[group], columns=["sha256", "html"],
                                               use_threads=False):
                for id_, item in zip(batch.column(0).to_pylist(), batch.column(1), strict=True):
                    if id_ != ids[index]:
                        raise ValueError("HTML projection failed exact publisher alignment")
                    index += 1
                    if id_ not in members:
                        continue
                    result = document(worker, item, members[id_])
                    statuses[result["status"]] += 1
                    if result["status"] == "usable":
                        coverage[f'{result["partition"]}/{result["label"]}'] += 1
                        if result["malformed"]:
                            statuses["usableWithParseErrors"] += 1
                    sink.write((json.dumps(result, separators=(",", ":"), allow_nan=False) + "\n").encode())
                    if sink.tell() > 64 * 1024 * 1024:
                        raise OSError("Derived output exceeds shard storage budget")
        expected = sum(id_ in members for id_ in ids)
        received = sum(count for name, count in statuses.items() if name != "usableWithParseErrors")
        if received != expected or index != len(ids):
            raise ValueError("Projected document count differs from the canonical join")
        report = {"name": shard["name"], "file": file.name, "publisherSha256": shard["sourceSha256"],
                  "sourceRows": len(ids), "matched": received, "statuses": dict(statuses), "coverage": dict(coverage),
                  "projectedBytes": remote.bytes, "processedRowGroups": selected_groups,
                  "availableRowGroups": parquet.metadata.num_row_groups, "seconds": perf_counter() - started}
    report.update({"derivedSha256": digest(file), "derivedBytes": file.stat().st_size})
    return report


def plan_shards(shards, projection, members, already):
    ranked = []
    for name, shard in shards.items():
        if name in already:
            continue
        counts = Counter()
        for row in checked_rows(projection / shard["file"], shard["projectedSha256"]):
            member = members.get(row["sha256"])
            if member and member[2] == "train":
                counts[member[3]] += 1
        ranked.append((name, counts[0] / shard["size"]))
    return [name for name, _ in sorted(ranked, key=lambda row: (-row[1], row[0]))]


def collect(previous, output, shard_names, byte_budget, target_train=None, reuse=()):
    members, projection, shards = inputs(previous)
    have = Counter()
    already = set()
    for path in reuse:
        prior = load(path / "manifest.json")
        if prior["revision"] != REVISION or prior["cohortSha256"] != PHASE5C_PIN:
            raise ValueError("Reuse requires the same pinned cohort")
        for item in prior["completedShards"]:
            if item["name"] in already or digest(path / item["file"]) != item["derivedSha256"]:
                raise ValueError("Previously acquired content shard failed integrity")
            already.add(item["name"])
            have.update(item["coverage"])
    if target_train:
        shard_names = plan_shards(shards, projection, members, already)
    if len(set(shard_names)) != len(shard_names) or any(name not in shards for name in shard_names):
        raise ValueError("Expected unique pinned development shard names")
    output.mkdir(mode=0o700)
    budget = Remaining(byte_budget)
    successful = []

    def save():
        receipt = {"revision": REVISION, "cohortSha256": PHASE5C_PIN, "budgetBytes": byte_budget,
                   "transferBytes": budget.received, "requestedShards": shard_names, "targetTrainRows": target_train,
                   "cumulativeUsableTrainingRowsByClass": [have["train/0"], have["train/1"]],
                   "completedShards": successful}
        temp = output / "manifest.tmp"
        temp.write_text(json.dumps(receipt, indent=2), encoding="utf-8")
        temp.replace(output / "manifest.json")

    try:
        with HtmlWorker() as worker:
            for name in shard_names:
                if target_train and 2 * min(have["train/0"], have["train/1"]) >= target_train:
                    break
                report = collect_shard(shards[name], members, projection, output, budget, worker)
                successful.append(report)
                have.update(report["coverage"])
                (output / (name + "-receipt.json")).write_text(json.dumps(report, indent=2), encoding="utf-8")
                save()
                print(json.dumps(report), flush=True)
        if target_train and 2 * min(have["train/0"], have["train/1"]) < target_train:
            raise ValueError("Available HTML did not reach balanced training capacity")
    finally:
        save()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("previous", type=private)
    parser.add_argument("output", type=private)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--shards", nargs="+")
    mode.add_argument("--target-train", type=int, choices=(20000, 50000))
    parser.add_argument("--reuse", nargs="+", type=private, default=())
    parser.add_argument("--budget-bytes", type=int, required=True)
    args = parser.parse_args()
    if os.environ.get("THREAT_PHASE3D_GUARDED") != "1" or args.budget_bytes <= 0:
        parser.error("Use the Windows Job Object resource guard and a positive transfer budget")
    try:
        collect(args.previous, args.output, args.shards, args.budget_bytes, args.target_train, args.reuse)
    except Exception as error:
        raise SystemExit("Bounded HTML projection stopped (" + type(error).__name__ + ").") from None
