"""Download only the pinned PhreshPhish URL, date and label columns."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from time import sleep

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from research.phase3c.project_phresh import DatasetRedirect, FILES, REVISION, shard, build_opener


def fetch(spec):
    for delay in (0, 2, 5):
        if delay:
            sleep(delay)
        try:
            return shard(spec)
        except OSError:
            if delay == 5:
                raise RuntimeError(f"Range projection repeatedly failed for {spec[0]}") from None


def collect(uci, original, output):
    tree = f"https://huggingface.co/api/datasets/phreshphish/phreshphish/tree/{REVISION}/data"
    with build_opener(DatasetRedirect()).open(tree, timeout=30) as response:
        entries = json.load(response)
    sizes = {}
    for item in entries:
        match = re.fullmatch(r"data/((?:train|test)-[0-9]{3})\.parquet", item["path"])
        if match:
            sizes[match[1]] = item["size"]
    expected = {f"{kind}-{i:03d}" for kind, count in (("train", 56), ("test", 21)) for i in range(count)}
    if sizes.keys() != expected:
        raise ValueError("Unexpected files in the pinned dataset tree")
    # Published test is fixed before any fit. Previous shards are never acquired again.
    specs = [(name, sizes[name]) for name in sorted(expected.difference(FILES))]
    runner = Path(__file__).with_name("partition.mjs")
    node = subprocess.Popen(
        ["node", "--max-old-space-size=3072", str(runner), str(uci), str(original), str(output)],
        stdin=subprocess.PIPE, encoding="utf-8", text=True,
    )
    try:
        with node.stdin, ThreadPoolExecutor(max_workers=2) as pool:
            # Limit buffering to two projected shards even if the first one is slow.
            pending = [pool.submit(fetch, spec) for spec in specs[:2]]
            for index, spec in enumerate(specs):
                name, rows, used = pending.pop(0).result()
                if index + 2 < len(specs):
                    pending.append(pool.submit(fetch, specs[index + 2]))
                side = name.split("-")[0]
                for row in rows:
                    date = row["date"]
                    day = str(date)[:10] if date else ""
                    node.stdin.write(json.dumps([side, row["label"], day, row["url"]]) + "\n")
                print(f"{name}: {len(rows)} rows, {used} projected bytes", flush=True)
        if node.wait():
            raise RuntimeError("Partitioner rejected the projection")
    finally:
        if node.poll() is None:
            node.terminate()
            node.wait()


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    for name in ("uci", "phase3c", "output"):
        cli.add_argument("--" + name, type=Path, required=True)
    args = cli.parse_args()
    if os.environ.get("THREAT_PHASE3D_GUARDED") != "1":
        cli.error("Run the projector with the Phase 3D resource guard")
    try:
        collect(args.uci, args.phase3c, args.output)
    except RuntimeError as error:
        if str(error).startswith("Range projection repeatedly failed for "):
            raise SystemExit(str(error)) from None
        raise SystemExit("The pinned projection worker failed.") from None
    except Exception as error:
        # Dataset rows and signed redirects must never appear in console logs.
        raise SystemExit(f"Pinned projection failed ({type(error).__name__}).") from None


if __name__ == "__main__":
    main()
