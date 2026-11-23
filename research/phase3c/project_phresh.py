"""Project pinned public Parquet columns without downloading/rendering webpage HTML."""

import argparse
import io
import json
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener
from pathlib import Path
import re
import subprocess

from pyarrow.parquet import ParquetFile


REVISION = "eca603e0ecd4f698f8d4d226c088659e72681239"
REPO = "https://huggingface.co/datasets/phreshphish/phreshphish"
FILES = ("train-000", "train-018", "train-037", "train-055",
         "test-000", "test-007", "test-014", "test-020")
COLUMNS = ("url", "label", "date")


class DatasetRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        url = urlparse(newurl)
        if url.scheme != "https" or not (url.hostname == "huggingface.co" or
                                        (url.hostname or "").endswith(".hf.co")):
            raise OSError("Unexpected dataset storage origin")
        return super().redirect_request(request, fp, code, msg, headers, newurl)


class RangeFile(io.RawIOBase):
    def __init__(self, name, length):
        self.url = f"{REPO}/resolve/{REVISION}/data/{name}.parquet"
        self.length = length
        self.position = 0
        self.bytes = 0
        self.opener = build_opener(DatasetRedirect())

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.position

    def seek(self, offset, whence=0):
        base = (0, self.position, self.length)[whence]
        target = base + offset
        if not 0 <= target <= self.length:
            raise OSError("Invalid offset for pinned shard")
        self.position = target
        return target

    def read(self, size=-1):
        count = min(size if size >= 0 else self.length, self.length - self.position)
        if not count:
            return b""
        if count > 8 * 1024 * 1024 or self.bytes + count > 24 * 1024 * 1024:
            raise OSError("Projected column read exceeded the shard byte budget")
        start, end = self.position, self.position + count - 1
        req = Request(f"{self.url}?part={start}-{end}", headers={"Range": f"bytes={start}-{end}",
                      "Accept-Encoding": "identity", "User-Agent": "ThreatDetection-phreshphish-column-research"})
        with self.opener.open(req, timeout=30) as response:
            if response.status != 206 or response.headers.get("Content-Range") != f"bytes {start}-{end}/{self.length}":
                raise OSError("Dataset endpoint did not honor the exact byte range")
            block = response.read(count + 1)
        if len(block) != count:
            raise OSError("Incomplete pinned shard range")
        self.bytes += len(block)
        self.position += len(block)
        return block


def shard(spec):
    name, size = spec
    with RangeFile(name, size) as source:
        parquet = ParquetFile(source)
        if not set(COLUMNS).issubset(parquet.schema.names):
            raise ValueError("Dataset metadata schema changed")
        rows = parquet.read(columns=COLUMNS, use_threads=False).to_pylist()
        return name, rows, source.bytes


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--uci", type=Path, required=True)
    cli.add_argument("--output", type=Path, required=True)
    args = cli.parse_args()
    tree_url = f"https://huggingface.co/api/datasets/phreshphish/phreshphish/tree/{REVISION}/data"
    with build_opener(DatasetRedirect()).open(tree_url, timeout=25) as response:
        entries = json.load(response)
    pinned = {item["path"]: item for item in entries if re.fullmatch(r"data/(train|test)-\d{3}\.parquet", item["path"])}
    specs = [(name, pinned[f"data/{name}.parquet"]["size"]) for name in FILES]
    runner = Path(__file__).with_name("normalize.mjs")
    with ThreadPoolExecutor(max_workers=4) as pool, subprocess.Popen(
        ["node", str(runner), str(args.uci), str(args.output)], stdin=subprocess.PIPE, text=True, encoding="utf-8"
    ) as consumer:
        with consumer.stdin:
            for name, rows, used in pool.map(shard, specs):
                side = name.split("-")[0]
                for row in rows:
                    day = str(row["date"])[:10]
                    consumer.stdin.write(json.dumps([side, row["label"], day, row["url"]]) + "\n")
                print(f"{name}: {len(rows)} rows from {used:,} projected bytes", flush=True)
        if consumer.wait() != 0:
            raise RuntimeError("Normalization failed")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # A signed storage URL or row must never enter logs.
        raise SystemExit(f"Pinned column projection failed ({type(error).__name__}).") from None
