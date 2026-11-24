"""Shared Phase 5C representations and frozen research utilities."""

from pathlib import Path
import sys

RESEARCH = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RESEARCH / "phase5c"))

from paths import private
from train import balanced, build_input, ids_sha256, labels, load_partition
from sequence import CharacterCNN, SEED, VOCABULARY, predict as predict_cnn, represent

PHASE5C = RESEARCH.parent / "docs" / "experiments" / "phase5c" / "metrics.json"
PROTOCOL = Path(__file__).with_name("protocol.json")


def protocol_bytes():
    return PROTOCOL.read_bytes().replace(b"\r\n", b"\n")
