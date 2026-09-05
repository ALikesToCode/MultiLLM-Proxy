"""Eligibility and input boundaries for free-only chat routing."""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from urllib.parse import urlsplit

from error_handlers import APIError
from providers.aihubmix import is_aihubmix_image_model
from providers.opencode_go import is_opencode_zen_free_model, opencode_model_endpoint
from services.model_catalog_service import build_model_catalog
from services.model_registry import ModelRegistry
from services.provider_catalog_metadata import model_supports_vision

FREE_MODELS = {"free:text": False, "free:vision": True}
PROVIDER_ORDER = ("groq", "opencode", "aihubmix", "gemini", "openrouter")
# These models require an explicit operator assertion about the account tier.
# A model name alone cannot prevent billing on an upgraded account/project.
FREE_TIER_MODELS = {
    "groq": ("qwen/qwen3.8-27b", "qwen/qwen3.6-27b", "openai/gpt-oss-120b"),
    "gemini": ("gemini-3.1-flash-lite",),
}
VISION_SEEDS = {
    "groq:qwen/qwen3.8-27b",
    "groq:qwen/qwen3.6-27b",
    "gemini:gemini-3.1-flash-lite",
    "openrouter:openrouter/free",
}
REQUEST_FIELDS = frozenset(
    {
        "model",
        "messages",
        "stream",
        "stream_options",
        "max_tokens",
        "max_completion_tokens",
        "temperature",
        "top_p",
        "stop",
        "seed",
        "frequency_penalty",
        "presence_penalty",
        "response_format",
        "reasoning_effort",
    }
)


@dataclass(frozen=True)
class FreeCandidate:
    id: str
    provider: str
    model: str
    vision: bool | None
    billing_basis: str


def _has_price(pricing) -> bool:
    """Fail closed when a free-labelled model advertises a charge."""
    if not isinstance(pricing, Mapping):
        return pricing is not None
    for value in pricing.values():
        try:
            amount = Decimal(str(value))
        except (InvalidOperation, ValueError):
            return True
        if not amount.is_finite() or amount != 0:
            return True
    return False


def _free_label(provider: str, model: str) -> bool:
    if provider == "openrouter":
        return model.endswith(":free") or model == "openrouter/free"
    if provider == "aihubmix":
        return model.endswith("-free")
    if provider == "opencode":
        return (
            is_opencode_zen_free_model(model)
            and opencode_model_endpoint(model) == "v1/chat/completions"
        )
    return False


def free_candidates(config, *, vision: bool) -> list[FreeCandidate]:
    """Use cached discovery only; never spend a generation to discover capability."""
    attested = {
        p.strip() for p in config.get("FREE_ROUTE_FREE_TIER_PROVIDERS", "").split(",")
    }
    catalog = {row["id"]: row for row in build_model_catalog(config["API_BASE_URLS"])}
    seeds = ["openrouter:openrouter/free"]
    seeds.extend(
        f"{provider}:{model}"
        for provider, models in FREE_TIER_MODELS.items()
        if provider in attested
        for model in models
    )
    for model_id in seeds:
        provider, model = model_id.split(":", 1)
        catalog.setdefault(
            model_id,
            {
                "id": model_id,
                "provider": provider,
                "model": model,
                "status": ModelRegistry.get_model_status(model_id),
            },
        )
    candidates = []
    for row in catalog.values():
        provider, model = row["provider"], row["model"]
        metadata = row.get("provider_metadata") or {}
        if provider not in config["API_BASE_URLS"] or row["status"] == "disabled":
            continue
        tier = provider in attested and model in FREE_TIER_MODELS.get(provider, ())
        if not tier and (
            not _free_label(provider, model) or _has_price(metadata.get("pricing"))
        ):
            continue
        if metadata.get("supports_image_output") is True:
            continue
        if provider == "aihubmix" and is_aihubmix_image_model(model):
            continue
        outputs = metadata.get("output_modalities")
        if outputs and "text" not in outputs:
            continue
        image_support = model_supports_vision(metadata)
        if image_support is None and row["id"] in VISION_SEEDS:
            image_support = True
        if vision and image_support is not True:
            continue
        candidates.append(
            FreeCandidate(
                row["id"],
                provider,
                model,
                image_support,
                "free-tier-attested" if tier else "free-labelled",
            )
        )
    preferred = list(
        dict.fromkeys(
            p.strip()
            for p in config.get("FREE_ROUTE_PROVIDER_ORDER", "").split(",")
            if p.strip() in PROVIDER_ORDER
        )
    )
    order = preferred + [p for p in PROVIDER_ORDER if p not in preferred]
    return sorted(
        candidates,
        key=lambda c: (
            order.index(c.provider),
            FREE_TIER_MODELS.get(c.provider, ()).index(c.model)
            if c.model in FREE_TIER_MODELS.get(c.provider, ())
            else 99,
            c.model != "openrouter/free",
            c.id,
        ),
    )


def _validate_part(part, *, vision: bool) -> None:
    if not isinstance(part, dict):
        raise APIError("Each content part must be an object", status_code=400)
    if part.get("type") == "text" and set(part) <= {"type", "text"}:
        if isinstance(part.get("text"), str) and part["text"].strip():
            return
    if (
        vision
        and part.get("type") == "image_url"
        and set(part) <= {"type", "image_url"}
    ):
        image = part.get("image_url")
        if isinstance(image, dict) and set(image) <= {"url", "detail"}:
            url = image.get("url")
            if isinstance(url, str):
                try:
                    parsed = urlsplit(url)
                except ValueError as error:
                    raise APIError("Invalid image URL", status_code=400) from error
                if (
                    parsed.scheme == "https" and parsed.hostname and not parsed.username
                ) or re.fullmatch(
                    r"data:image/(?:png|jpeg|webp|gif);base64,[A-Za-z0-9+/]+={0,2}", url
                ):
                    return
    raise APIError(
        "Use text parts, or image_url parts with free:vision", status_code=400
    )


def validate_free_payload(payload: dict, fixed_model: str | None = None) -> dict:
    unknown = set(payload) - REQUEST_FIELDS
    if unknown:
        raise APIError(
            "Unsupported free-route parameters; routing overrides, plugins, "
            "tools and paid add-ons are not allowed",
            status_code=400,
        )
    model = payload.get("model", fixed_model or "free:text")
    if (
        not isinstance(model, str)
        or model not in FREE_MODELS
        or (fixed_model and model != fixed_model)
    ):
        raise APIError(
            "Use the matching free:text or free:vision model", status_code=400
        )
    messages = payload.get("messages")
    if not isinstance(messages, list) or not messages:
        raise APIError("messages must be a non-empty list", status_code=400)
    for message in messages:
        if not isinstance(message, dict) or set(message) - {"role", "content", "name"}:
            raise APIError("Unsupported free-route message fields", status_code=400)
        role = message.get("role")
        if not isinstance(role, str) or role not in {
            "system",
            "developer",
            "user",
            "assistant",
        }:
            raise APIError("Unsupported message role", status_code=400)
        content = message.get("content")
        if isinstance(content, str) and content.strip():
            continue
        if not isinstance(content, list) or not content:
            raise APIError("Message content must not be empty", status_code=400)
        for part in content:
            _validate_part(part, vision=FREE_MODELS[model])
    if "stream" in payload and not isinstance(payload["stream"], bool):
        raise APIError("stream must be a boolean", status_code=400)
    for field in ("max_tokens", "max_completion_tokens"):
        if field in payload and (
            type(payload[field]) is not int or payload[field] <= 0
        ):
            raise APIError(f"{field} must be a positive integer", status_code=400)
    result = {**payload, "model": model}
    if not {"max_tokens", "max_completion_tokens"} & result.keys():
        result["max_tokens"] = 1024
    return result
