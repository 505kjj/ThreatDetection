"""Bounded offline logo features and similarity baselines."""

from dataclasses import dataclass
from hashlib import sha256
from io import BytesIO
from time import perf_counter
import warnings

import cv2
import numpy as np
from PIL import Image, ImageOps, UnidentifiedImageError

MAX_ENCODED = 2 * 1024 * 1024
MAX_PIXELS = 2_000_000
MAX_SIDE = 2048
MODEL_SIZE = 224
METHODS = ("phash", "orb", "mobilenet")
THRESHOLDS = {"phash": (0.80, 0.055), "orb": (0.15, 0.06), "mobilenet": (0.82, 0.055)}
WEIGHT_BYTES = 10241912
WEIGHT_SHA256 = "46d2c063b18125884c48937afa4c49e18128869e52e8db96df48bf0a4d7ff697"
WEIGHT_REVISION = "76b303ec28c466e9df37f4745dfb7aef20ab87ae"
MEAN = np.array([0.485, 0.456, 0.406], dtype=np.float32)
STD = np.array([0.229, 0.224, 0.225], dtype=np.float32)


def decode(data):
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_ENCODED:
        raise ValueError("Image byte budget exceeded")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(BytesIO(data), formats=("PNG", "JPEG")) as source:
                width, height = source.size
                if (not 4 <= min(width, height) or max(width, height) > MAX_SIDE or width * height > MAX_PIXELS
                        or getattr(source, "n_frames", 1) != 1):
                    raise ValueError("Image dimensions or frame count outside policy")
                source.verify()
            with Image.open(BytesIO(data), formats=("PNG", "JPEG")) as source:
                oriented = ImageOps.exif_transpose(source)
                pixels = oriented.convert("RGBA")
                # A fresh image carries pixels only, without source metadata.
                return Image.frombytes("RGBA", pixels.size, pixels.tobytes())
    except (Image.DecompressionBombError, Image.DecompressionBombWarning, UnidentifiedImageError,
            OSError, SyntaxError, OverflowError, EOFError) as error:
        raise ValueError("Invalid or unsupported static raster image") from error


def encode(image, format="PNG", **options):
    output = BytesIO()
    image.save(output, format=format, **options)
    return output.getvalue()


def letterbox(image, size=MODEL_SIZE):
    alpha = image.getchannel("A")
    bounds = alpha.getbbox()
    if bounds is None:
        raise ValueError("Image is fully transparent")
    image = image.crop(bounds)
    width, height = image.size
    scale = (size - 16) / max(width, height)
    resized = image.resize((max(1, round(width * scale)), max(1, round(height * scale))), Image.Resampling.BILINEAR)
    output = Image.new("RGB", (size, size), "#fff")
    output.paste(resized, ((size - resized.width) // 2, (size - resized.height) // 2), resized)
    return np.asarray(output)


def hash_image(rgb):
    gray = cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY)
    low = cv2.resize(gray, (32, 32), interpolation=cv2.INTER_AREA).astype(np.float32)
    freq = cv2.dct(low)[:8, :8].flatten()[1:]
    middle = np.median(freq)
    return sum(int(value > middle) << index for index, value in enumerate(freq))


def hash_similarity(first, second):
    return 1 - (first ^ second).bit_count() / 63


def orb_similarity(first, second):
    if first is None or second is None or min(len(first), len(second)) < 4:
        return None
    matcher = cv2.BFMatcher(cv2.NORM_HAMMING)

    def nearest(query, reference):
        return {(a.queryIdx, a.trainIdx) for pair in matcher.knnMatch(query, reference, k=2)
                if len(pair) == 2 for a, b in [pair] if a.distance < 0.75 * b.distance}

    forwards = nearest(first, second)
    backwards = {(b, a) for a, b in nearest(second, first)}
    return len(forwards & backwards) / max(12, min(len(first), len(second)))


class MobileNet:
    def __init__(self, weights):
        import timm
        import torch
        from safetensors.torch import load

        with weights.open("rb") as stream:
            data = stream.read(WEIGHT_BYTES + 1)
        if len(data) != WEIGHT_BYTES or sha256(data).hexdigest() != WEIGHT_SHA256:
            raise ValueError("Pinned model weights differ")
        self.torch = torch
        torch.set_num_threads(2)
        torch.set_num_interop_threads(1)
        model = timm.create_model("mobilenetv3_small_100.lamb_in1k", pretrained=False)
        model.load_state_dict(load(data), strict=True)
        model.reset_classifier(0)
        self.model = model.cpu().eval()

    @staticmethod
    def tensor(rgb):
        return np.ascontiguousarray(((rgb.astype(np.float32) / 255 - MEAN) / STD).transpose(2, 0, 1)[None])

    def embed(self, rgb):
        with self.torch.inference_mode():
            features = self.model(self.torch.from_numpy(self.tensor(rgb)))[0].numpy()
        norm = float(np.linalg.norm(features))
        if not np.isfinite(norm) or norm == 0:
            raise ValueError("Invalid embedding")
        return features / norm


@dataclass
class Features:
    normalized: str
    phash: int
    orb: np.ndarray | None
    mobilenet: np.ndarray


class Extractor:
    def __init__(self, model):
        cv2.setNumThreads(2)
        cv2.ocl.setUseOpenCL(False)
        self.orb = cv2.ORB_create(nfeatures=256, edgeThreshold=13, patchSize=25, fastThreshold=12)
        self.model = model

    def features(self, image):
        start = perf_counter()
        rgb = letterbox(image)
        if float(rgb.std(axis=(0, 1)).max()) < 2:
            raise ValueError("Image has insufficient visual structure")
        prep = perf_counter()
        phash = hash_image(rgb)
        phash_done = perf_counter()
        gray = cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY)
        _, orb = self.orb.detectAndCompute(gray, None)
        orb_done = perf_counter()
        embedding = self.model.embed(rgb)
        end = perf_counter()
        return Features(sha256(rgb.tobytes()).hexdigest(), phash, orb, embedding), {
            "normalizeMs": (prep - start) * 1000, "phashMs": (phash_done - prep) * 1000,
            "orbMs": (orb_done - phash_done) * 1000, "mobileNetMs": (end - orb_done) * 1000}


def pair_score(query, reference, method):
    if method == "phash":
        return hash_similarity(query.phash, reference.phash)
    if method == "orb":
        return orb_similarity(query.orb, reference.orb)
    if method == "mobilenet":
        return float(np.clip(np.dot(query.mobilenet, reference.mobilenet), -1, 1))
    raise ValueError("Unknown similarity method")


def classify(query, references, method):
    best = {}
    for brand, reference in references:
        score = pair_score(query, reference, method)
        if score is not None:
            best[brand] = max(score, best.get(brand, -1.0))
    ranked = sorted(best.items(), key=lambda item: (-item[1], item[0]))
    floor, margin = THRESHOLDS[method]
    if not ranked or ranked[0][1] < floor:
        return "unrecognized", None
    if len(ranked) > 1 and ranked[0][1] - ranked[1][1] < margin:
        return "ambiguous", None
    return "recognized", ranked[0][0]


def within_scope(host, scopes, shared):
    # Only use a previously normalized canonical DNS host.
    return host in shared or any(host == scope or host.endswith("." + scope) for scope in scopes)


def interpret(host, decisions, brands):
    if not decisions:
        return "missing-visual-evidence"
    recognized = {brand for status, brand in decisions if status == "recognized"}
    if len(recognized) > 1 or any(state == "ambiguous" for state, _ in decisions):
        return "ambiguous-visual-match"
    if not recognized:
        return "unrecognized-brand"
    brand = brands[next(iter(recognized))]
    if within_scope(host, brand["scopes"], brand.get("sharedHosts", [])):
        return "recognized-brand-on-authorized-domain"
    return "recognized-brand-on-unverified-domain"
