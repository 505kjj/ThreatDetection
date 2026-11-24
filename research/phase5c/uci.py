"""Stream the pinned UCI archive through the isolated development exporter."""

import argparse
from hashlib import file_digest
import os
from pathlib import Path
import shutil
import subprocess
from zipfile import ZipFile

from paths import private


ARCHIVE_SHA256 = "0a639fd03aea6308c5b1c10c92aa23c2ce1505447a9137271865cd0badc9a59a"
CSV = "PhiUSIIL_Phishing_URL_Dataset.csv"


def export(archive, old_development, destination):
    with archive.open("rb") as stream:
        if file_digest(stream, "sha256").hexdigest() != ARCHIVE_SHA256:
            raise ValueError("UCI archive checksum differs")
    with ZipFile(archive) as zipped, zipped.open(CSV) as stream:
        with subprocess.Popen(["node", str(Path(__file__).with_name("custody.mjs")),
                               "uci", str(destination), str(old_development)],
                              stdin=subprocess.PIPE) as worker:
            with worker.stdin:
                shutil.copyfileobj(stream, worker.stdin)
            if worker.wait():
                raise ValueError("UCI development replay failed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=private)
    parser.add_argument("old_development", type=private)
    parser.add_argument("destination", type=private)
    args = parser.parse_args()
    if os.environ.get("THREAT_PHASE3D_GUARDED") != "1":
        parser.error("Use the Windows Job Object resource guard")
    export(args.archive, args.old_development, args.destination)
