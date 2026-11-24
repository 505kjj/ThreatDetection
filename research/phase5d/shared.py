"""Shared Phase 5C representations and frozen research utilities."""

from pathlib import Path
import sys

RESEARCH = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RESEARCH / "phase5c"))

from paths import private
from train import SEED, balanced, build_input, ids_sha256, labels, load_partition

PHASE5C = RESEARCH.parent / "docs" / "experiments" / "phase5c" / "metrics.json"
PROTOCOL = Path(__file__).with_name("protocol.json")


def protocol_bytes():
    return PROTOCOL.read_bytes().replace(b"\r\n", b"\n")


def __getattr__(name):
    """Load the PyTorch sequence helpers only for CNN or Transformer callers."""
    if name not in {"CharacterCNN", "VOCABULARY", "predict_cnn", "represent"}:
        raise AttributeError(name)
    from sequence import CharacterCNN, VOCABULARY, predict as predict_cnn, represent
    globals().update({"CharacterCNN": CharacterCNN, "VOCABULARY": VOCABULARY,
                      "predict_cnn": predict_cnn, "represent": represent})
    return globals()[name]
