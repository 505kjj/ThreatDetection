"""Export frozen sequence checkpoints to ONNX and generate synthetic references."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

import numpy as np
import torch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "research/phase5c"), str(ROOT / "research/phase5d")]
from sequence import CharacterCNN, tokenize
from transformer import URLTransformer
from export_ngram import FIXTURES


def main(experiments, output):
    receipt = json.loads((ROOT / "docs/experiments/phase5e/frozen-url.json").read_text())
    output.mkdir(parents=True, exist_ok=False)
    torch.set_num_threads(2)
    for name, length, model_type in (("cnn", 160, CharacterCNN), ("transformer", 80, URLTransformer)):
        spec = receipt["models"][name]
        source = (experiments / spec["artifact"]).resolve()
        if not source.is_relative_to(experiments.resolve()):
            raise ValueError("Artifact outside experiments directory")
        data = source.read_bytes()
        if len(data) != spec["bytes"] or sha256(data).hexdigest() != spec["sha256"]:
            raise ValueError("Frozen model checksum or size differs")
        model = model_type()
        model.load_state_dict(torch.load(source, map_location="cpu", weights_only=True))
        model.eval()
        vectors = np.stack([tokenize(text)[:length] for text in FIXTURES])
        tokens = torch.as_tensor(vectors)
        with torch.inference_mode():
            torch.backends.mha.set_fastpath_enabled(True)
            scores = model(tokens).sigmoid().numpy().tolist()
            # The fused Transformer inference operator is unsupported by the ONNX exporter.
            torch.backends.mha.set_fastpath_enabled(False)
            torch.onnx.export(model, tokens[:1], output / f"{name}.onnx", input_names=["tokens"],
                              output_names=["logits"], opset_version=17, dynamo=False)
        reference = {"fixtures": FIXTURES, "vectors": vectors.tolist(), "scores": scores,
                     "tolerance": 1e-5, "thresholds": spec["operatingPoints"]}
        (output / f"{name}-reference.json").write_text(json.dumps(reference, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"model": name, "sourceSha256": spec["sha256"],
                          "bytes": (output / f"{name}.onnx").stat().st_size, "fixtures": len(scores)}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("experiments", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.output.resolve().is_relative_to(ROOT.resolve()):
        parser.error("Output must be outside the repository")
    main(args.experiments, args.output)
