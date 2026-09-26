"""Eligibility and input boundaries for free-only chat routing."""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from urllib.parse import urlsplit

from error_handlers import APIError
from providers.aihubmix import is_aihubmix_image_model
from providers.opencode_go import is_opencode_zen_free_model, opencode_model_endpoint
from services.free_provider_catalog import (
    FREE_PROVIDERS,
    FREE_TIER_MODELS,
    PROVIDER_ORDER,
    SEED_TOOLS,
    SEED_VISION,
    provider_enabled,
    provider_tier_confirmed,
)
from services.model_catalog_service import build_model_catalog
from services.free_json_contract import validate_response_format
from services.free_tool_contract import (
    TOOL_FIELDS,
    is_tool_message,
    validate_tool_message,
    validate_tools,
)
from services.model_registry import ModelRegistry
from services.provider_catalog_metadata import (
    model_supports_tools,
    model_supports_vision,
)

FREE_MODELS = {"free:text": False, "free:vision": True}
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
        *TOOL_FIELDS,
    }
)
_LIST_PRICE_FIELDS = ("input_cost_per_million", "output_cost_per_million")


@dataclass(frozen=True)
class FreeCandidate:
    id: str
    provider: str
    model: str
    vision: bool | None
    billing_basis: str
    tools: bool | None = None


def free_model_aliases() -> list[dict]:
    """Advertise pool capabilities without implying live provider availability."""
    return [
        {
            "id": model,
            "object": "model",
            "created": 0,
            "owned_by": "multillm",
            "status": "available",
            "capabilities": {
                "supports_chat": True,
                "supports_streaming": True,
                # Tool requests use only candidates with confirmed tool support.
                "supports_tools": True,
                "supports_vision": vision,
                "supports_images": False,
                "supports_video": False,
            },
            "supports_vision": vision,
        }
        for model, vision in FREE_MODELS.items()
    ]


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


def free_candidates(config, *, vision: bool, tools: bool = False) -> list[FreeCandidate]:
    """Use cached discovery only; never spend a generation to discover capability.

    A tool request admits only candidates whose catalog or reviewed seed confirms
    tool calling; unknown support is excluded.
    """
    catalog = {row["id"]: row for row in build_model_catalog(config["API_BASE_URLS"])}
    seeds = [
        f"{provider}:{model}"
        for provider, spec in FREE_PROVIDERS.items()
        if provider_enabled(config, provider)
        and provider_tier_confirmed(config, provider)
        for model, _ in spec.models
    ]
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
        if not provider_enabled(config, provider) or row["status"] == "disabled":
            continue
        if not provider_tier_confirmed(config, provider):
            continue
        spec = FREE_PROVIDERS[provider]
        seeded = (model, SEED_VISION.get(row["id"])) in spec.models
        # New providers have reviewed seeds only, not a generic free-name rule.
        if spec.extra and not seeded:
            continue
        tier = spec.requires_free_tier and seeded
        list_prices = {
            field: metadata[field]
            for field in _LIST_PRICE_FIELDS
            if metadata.get(field) is not None
        }
        if not tier and (
            not (seeded or _free_label(provider, model))
            or _has_price(metadata.get("pricing"))
            or _has_price(list_prices)
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
        if image_support is None:
            image_support = SEED_VISION.get(row["id"])
        # Seeds without reviewed vision coverage stay out of image routing.
        if seeded and SEED_VISION.get(row["id"]) is not True:
            image_support = SEED_VISION.get(row["id"])
        if vision and image_support is not True:
            continue
        # An explicit catalog flag wins; a reviewed seed covers models without one.
        tool_support = model_supports_tools(metadata)
        if tool_support is None:
            tool_support = SEED_TOOLS.get(row["id"])
        if tools and tool_support is not True:
            continue
        candidates.append(
            FreeCandidate(
                row["id"],
                provider,
                model,
                image_support,
                "free-tier-attested"
                if tier
                else (
                    "free-fallback-disabled"
                    if provider == "bazaarlink"
                    else "free-labelled"
                ),
                tool_support,
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


def declared_tools(payload: dict) -> frozenset[str]:
    """Function names a validated free request declares."""
    return frozenset(tool["function"]["name"] for tool in payload.get("tools") or ())


def tool_request(payload: dict) -> bool:
    """Tool definitions or tool-call history need a model that supports tools."""
    return "tools" in payload or any(
        isinstance(message, dict) and is_tool_message(message)
        for message in payload.get("messages") or ()
    )


def validate_free_payload(payload: dict, fixed_model: str | None = None) -> dict:
    unknown = set(payload) - REQUEST_FIELDS
    if unknown:
        raise APIError(
            "Unsupported free-route parameters; routing overrides, plugins, "
            "server-side tools and paid add-ons are not allowed",
            status_code=400,
        )
    try:
        validate_response_format(payload.get("response_format"))
    except (ValueError, RecursionError) as error:
        raise APIError("Invalid or unsupported response_format schema", status_code=400) from error
    try:
        validate_tools(payload)
    except (ValueError, RecursionError) as error:
        raise APIError(f"Invalid tools: {error}", status_code=400) from error
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
        if isinstance(message, dict) and is_tool_message(message):
            try:
                validate_tool_message(message)
            except ValueError as error:
                raise APIError(str(error), status_code=400) from error
            continue
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
