"""Per-model image parameters, so one request can fall back across providers.

An automatic image route sends the same OpenAI Images request to candidates whose
models accept different settings. Each candidate receives the closest settings its
model supports: the highest quality it offers up to the one requested, a size within
its limits, and no fields it would reject.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

DEFAULT_IMAGE_QUALITY = "max"
# Set on proxy-generated transport failures: "connect" means the request never reached
# the provider; "timeout" or "interrupted" means it may have been accepted and billed.
TRANSPORT_FAILURE_HEADER = "X-MultiLLM-Transport-Failure"
QUALITY_ORDER = ("low", "medium", "high", "xhigh", "max")
_SIZE = re.compile(r"(\d{2,5})x(\d{2,5})\Z")
_ASPECT_RATIOS = ("1:1", "16:9", "9:16", "4:3", "3:4", "3:2", "2:3")
_STANDARD_SIZES = ((1024, 1024), (1536, 1024), (1024, 1536))
GPT_IMAGE_FIELDS = frozenset({"model", "prompt", "n", "size", "quality", "background", "moderation",
                              "output_format", "output_compression", "response_format", "user"})
GROK_IMAGE_FIELDS = frozenset({"model", "prompt", "n", "response_format", "aspect_ratio", "resolution", "quality", "user"})


@dataclass(frozen=True)
class ImageProfile:
    qualities: tuple[str, ...]
    fields: frozenset[str] | None = GPT_IMAGE_FIELDS
    # Flexible sizes up to this edge; 0 snaps to the three standard sizes.
    max_edge: int = 3840
    aspect_ratio: bool = False


GPT_IMAGE_25 = ImageProfile(QUALITY_ORDER)
GPT_IMAGE_2 = ImageProfile(("low", "medium", "high"))
GPT_IMAGE_1 = ImageProfile(("low", "medium", "high"), max_edge=0)
GROK_IMAGE_2 = ImageProfile(("low", "medium"), GROK_IMAGE_FIELDS, aspect_ratio=True)
GROK_IMAGE = ImageProfile((), GROK_IMAGE_FIELDS, aspect_ratio=True)
# Cloudflare's Workers AI adapter maps quality to diffusion steps and size to dimensions.
WORKERS_AI_IMAGE = ImageProfile(QUALITY_ORDER, frozenset({"model", "prompt", "n", "size", "quality", "response_format"}))


def image_profile(provider: str, provider_model: str) -> ImageProfile | None:
    """The settings a model accepts, or None to pass the request through unchanged."""
    name = provider_model.rsplit("/", 1)[-1].lower()
    if provider == "cloudflare" and provider_model.startswith("@cf/"):
        return WORKERS_AI_IMAGE
    if name.startswith("gpt-image-2.5"):
        # Cloudflare's GPT Image adapter accepts only the standard sizes.
        return ImageProfile(QUALITY_ORDER, max_edge=0) if provider == "cloudflare" else GPT_IMAGE_25
    if name.startswith("gpt-image-2"):
        return ImageProfile(("low", "medium", "high"), max_edge=0) if provider == "cloudflare" else GPT_IMAGE_2
    if name.startswith("gpt-image-1"):
        return GPT_IMAGE_1
    if name.startswith("grok-imagine-image-2"):
        return GROK_IMAGE_2
    if name.startswith("grok-imagine-image"):
        return GROK_IMAGE
    return None


def is_video_model(provider_model: str) -> bool:
    name = provider_model.rsplit("/", 1)[-1].lower()
    return name.startswith(("veo-", "sora-", "grok-imagine-video"))


def _closest_quality(requested: str, supported: tuple[str, ...]) -> str | None:
    if requested == "auto" or requested in supported:
        return requested
    if requested not in QUALITY_ORDER:
        return None
    rank = QUALITY_ORDER.index(requested)
    lower = [quality for quality in supported if QUALITY_ORDER.index(quality) <= rank]
    return lower[-1] if lower else supported[0]


def _fit_size(width: int, height: int, max_edge: int) -> str:
    if max_edge == 0:
        ratio = width / height
        best = min(_STANDARD_SIZES, key=lambda size: abs(math.log((size[0] / size[1]) / ratio)))
        return f"{best[0]}x{best[1]}"
    scale = min(1.0, max_edge / max(width, height))
    # GPT Image sizes use multiples of 16.
    return f"{max(16, int(width * scale) // 16 * 16)}x{max(16, int(height * scale) // 16 * 16)}"


def _aspect_ratio(width: int, height: int) -> str:
    ratio = width / height
    return min(_ASPECT_RATIOS, key=lambda value: abs(math.log(int(value.split(":")[0]) / int(value.split(":")[1]) / ratio)))


def prepare_image_payload(provider: str, provider_model: str, payload: dict) -> dict:
    """The request this candidate should receive; the caller's payload is not changed."""
    profile = image_profile(provider, provider_model)
    if profile is None:
        return dict(payload)
    prepared = dict(payload)
    quality = prepared.get("quality")
    if isinstance(quality, str):
        closest = _closest_quality(quality.lower(), profile.qualities) if profile.qualities else None
        if closest is None:
            prepared.pop("quality", None)
        else:
            prepared["quality"] = closest
    size = _SIZE.fullmatch(str(prepared.get("size") or ""))
    if size:
        width, height = int(size.group(1)), int(size.group(2))
        if profile.aspect_ratio:
            prepared.pop("size")
            prepared.setdefault("aspect_ratio", _aspect_ratio(width, height))
            prepared.setdefault("resolution", "2k" if max(width, height) > 1024 else "1k")
        else:
            prepared["size"] = _fit_size(width, height, profile.max_edge)
    elif profile.aspect_ratio:
        prepared.pop("size", None)
    # Grok's resolution is its quality ceiling: 2k serves high, xhigh and max requests.
    if profile.aspect_ratio and isinstance(quality, str) and quality.lower() in ("high", "xhigh", "max"):
        prepared.setdefault("resolution", "2k")
    if profile.fields is not None:
        prepared = {name: value for name, value in prepared.items() if name in profile.fields}
    return prepared
