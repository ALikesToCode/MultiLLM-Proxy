from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Literal, TypeVar
from urllib.parse import urlsplit


AIHUBMIX_PRIMARY_BASE_URL = "https://aihubmix.com"
AIHUBMIX_SECONDARY_BASE_URL = "https://api.inferera.com"
AIHUBMIX_ALLOWED_HOSTS = frozenset({"aihubmix.com", "api.inferera.com"})

# Snapshot from the authenticated /v1/models catalog on 2026-08-28. The live
# catalog refresh supplements this seed without making startup depend on the
# provider network.
AIHUBMIX_FREE_MODEL_IDS = frozenset(
    {
        "coding-glm-4.6-free",
        "coding-glm-4.7-free",
        "coding-glm-5-free",
        "coding-glm-5-turbo-free",
        "coding-glm-5.1-free",
        "coding-glm-5.2-free",
        "coding-glm-5.3-free",
        "coding-kimi-k3-free",
        "coding-minimax-m2-free",
        "coding-minimax-m2.1-free",
        "coding-minimax-m2.5-free",
        "coding-minimax-m2.7-free",
        "coding-minimax-m3-free",
        "dots-3-note-preview-free",
        "gemini-3-flash-preview-free",
        "gemini-3.1-flash-image-preview-free",
        "gemini-3.5-flash-lite-free",
        "gemini-3.6-flash-free",
        "gemini-3.7-flash-free",
        "gemma-4-26b-a4b-it-free",
        "gemma-4-31b-it-free",
        "glm-4.7-flash-free",
        "gpt-4.1-free",
        "gpt-4.1-mini-free",
        "gpt-4.1-nano-free",
        "gpt-4o-free",
        "gpt-5.5-free",
        "gpt-image-2-free",
        "gpt-oss-20b-free",
        "hy3-free",
        "k2.6-code-preview-free",
        "kimi-for-coding-free",
        "laguna-s-2.1-free",
        "laguna-xs-2.1-free",
        "lfm-2.5-2.6b-free",
        "ling-3.0-flash-free",
        "ling-3.0-tiny-free",
        "mimo-v2-flash-free",
        "minimax-m2.7-free",
        "minimax-m3-free",
        "nemotron-3-nano-30b-a3b-free",
        "nemotron-3-nano-omni-30b-a3b-reasoning-free",
        "nemotron-3-super-120b-a12b-free",
        "nemotron-3-ultra-550b-a55b-free",
        "nemotron-3.5-content-safety-free",
        "nemotron-3.5-lightning-free",
        "nemotron-nano-12b-v2-vl-free",
        "nemotron-nano-9b-v2-free",
        "north-mini-code-free",
        "qwen3.6-plus-preview-free",
        "xiaomi-mimo-v2-omni-free",
        "xiaomi-mimo-v2-pro-free",
        "xiaomi-mimo-v2.5-free",
        "xiaomi-mimo-v2.5-pro-free",
    }
)

AIHUBMIX_IMAGE_MODEL_IDS = frozenset(
    {
        "doubao-seedream-4-0",
        "gemini-3.1-flash-image-preview-free",
        "gpt-image-2-free",
    }
)
AIHUBMIX_BUILTIN_MODEL_IDS = tuple(
    sorted(AIHUBMIX_FREE_MODEL_IDS | AIHUBMIX_IMAGE_MODEL_IDS)
)

_AIHUBMIX_METHODS_BY_PATH = {
    "v1/models": frozenset({"GET"}),
    "v1/chat/completions": frozenset({"POST"}),
    "v1/images/generations": frozenset({"POST"}),
    "v1/images/edits": frozenset({"POST"}),
    "v1/models/doubao/doubao-seedream-4-0/predictions": frozenset({"POST"}),
}
_SAFE_FAILOVER_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_ResponseT = TypeVar("_ResponseT")


@dataclass(frozen=True)
class AIHubMixImageRequest:
    path: str
    payload: dict[str, Any]
    response_kind: Literal["openai", "gemini", "prediction"]


def trusted_aihubmix_origin(value: str | None, default: str) -> str:
    """Return a trusted AIHubMix origin, accepting an optional trailing /v1."""
    candidate_value = str(value or "").strip()
    try:
        candidate = urlsplit(candidate_value)
        path = candidate.path.rstrip("/")
        valid = (
            candidate.scheme == "https"
            and candidate.hostname in AIHUBMIX_ALLOWED_HOSTS
            and candidate.username is None
            and candidate.password is None
            and candidate.port is None
            and not candidate.query
            and not candidate.fragment
            and path in {"", "/v1"}
        )
        if valid:
            return f"https://{candidate.hostname}"
    except (TypeError, ValueError):
        pass
    return default


def ai_hubmix_origins(
    primary: str | None,
    secondary: str | None,
) -> tuple[str, ...]:
    primary_origin = trusted_aihubmix_origin(primary, AIHUBMIX_PRIMARY_BASE_URL)
    secondary_origin = trusted_aihubmix_origin(
        secondary,
        AIHUBMIX_SECONDARY_BASE_URL,
    )
    if secondary_origin == primary_origin:
        return (primary_origin,)
    return primary_origin, secondary_origin


def build_aihubmix_url(origin: str, path: str) -> str:
    return f"{origin.rstrip('/')}/{path.lstrip('/')}"


def is_valid_aihubmix_request(path: str, method: str) -> bool:
    if not path or any(delimiter in path for delimiter in "%?#\\"):
        return False
    if any(ord(character) < 32 or ord(character) == 127 for character in path):
        return False
    normalized = path.strip("/")
    if any(segment in {"", ".", ".."} for segment in normalized.split("/")):
        return False
    return method.upper() in _AIHUBMIX_METHODS_BY_PATH.get(
        normalized,
        frozenset(),
    )


def is_aihubmix_image_model(model_id: str) -> bool:
    return model_id in AIHUBMIX_IMAGE_MODEL_IDS


def _validated_prompt(payload: Mapping[str, Any]) -> str:
    prompt = payload.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip():
        raise ValueError("AIHubMix image generation requires a non-empty prompt")
    return prompt


def _require_single_image(payload: Mapping[str, Any]) -> None:
    requested = payload.get("n", 1)
    if requested != 1:
        raise ValueError("This AIHubMix model currently supports exactly one image")


def _build_gemini_image_request(
    model_id: str,
    payload: Mapping[str, Any],
) -> AIHubMixImageRequest:
    _require_single_image(payload)
    upstream_payload: dict[str, Any] = {
        "model": model_id,
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": _validated_prompt(payload)}
                ],
            }
        ],
        "modalities": ["text", "image"],
    }
    if payload.get("temperature") is not None:
        upstream_payload["temperature"] = payload["temperature"]
    return AIHubMixImageRequest(
        path="v1/chat/completions",
        payload=upstream_payload,
        response_kind="gemini",
    )


def _build_doubao_image_request(
    payload: Mapping[str, Any],
) -> AIHubMixImageRequest:
    _require_single_image(payload)
    upstream_input: dict[str, Any] = {
        "model": "doubao-seedream-4-0",
        "prompt": _validated_prompt(payload),
        "size": payload.get("size") or "2K",
        "sequential_image_generation": "disabled",
        "stream": False,
        "response_format": "url",
        "watermark": bool(payload.get("watermark", False)),
    }
    if isinstance(payload.get("image"), str) and payload["image"].strip():
        upstream_input["image"] = payload["image"]
    return AIHubMixImageRequest(
        path="v1/models/doubao/doubao-seedream-4-0/predictions",
        payload={"input": upstream_input},
        response_kind="prediction",
    )


def build_aihubmix_image_request(
    model_id: str,
    payload: Mapping[str, Any],
) -> AIHubMixImageRequest:
    if model_id == "gpt-image-2-free":
        _validated_prompt(payload)
        upstream_payload = dict(payload)
        upstream_payload["model"] = model_id
        return AIHubMixImageRequest(
            path="v1/images/generations",
            payload=upstream_payload,
            response_kind="openai",
        )
    if model_id == "gemini-3.1-flash-image-preview-free":
        return _build_gemini_image_request(model_id, payload)
    if model_id == "doubao-seedream-4-0":
        return _build_doubao_image_request(payload)
    raise ValueError(f"Unsupported AIHubMix image model: {model_id}")


def _gemini_image_parts(payload: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    parts: list[Mapping[str, Any]] = []
    choices = payload.get("choices")
    if not isinstance(choices, list):
        return parts
    for choice in choices:
        if not isinstance(choice, Mapping):
            continue
        message = choice.get("message")
        if not isinstance(message, Mapping):
            continue
        for field in ("multi_mod_content", "multiModContent", "content"):
            candidate = message.get(field)
            if isinstance(candidate, list):
                parts.extend(part for part in candidate if isinstance(part, Mapping))
    return parts


def _normalized_gemini_images(
    payload: Mapping[str, Any],
) -> tuple[list[dict[str, str]], set[str]]:
    images: list[dict[str, str]] = []
    formats: set[str] = set()
    for part in _gemini_image_parts(payload):
        inline = part.get("inline_data") or part.get("inlineData")
        if isinstance(inline, Mapping) and isinstance(inline.get("data"), str):
            images.append({"b64_json": inline["data"]})
            mime_type = inline.get("mime_type") or inline.get("mimeType")
            if isinstance(mime_type, str) and mime_type.strip():
                formats.add(mime_type.rsplit("/", 1)[-1].lower())
            continue

        image_url = part.get("image_url") or part.get("imageUrl")
        if isinstance(image_url, Mapping):
            image_url = image_url.get("url")
        if not isinstance(image_url, str):
            image_url = part.get("url")
        if isinstance(image_url, str) and image_url:
            images.append({"url": image_url})
    return images, formats


def _normalize_gemini_response(payload: Mapping[str, Any]) -> dict[str, Any]:
    images, formats = _normalized_gemini_images(payload)
    if not images:
        raise ValueError("AIHubMix Gemini response did not contain image data")
    normalized: dict[str, Any] = {
        "created": payload.get("created", 0),
        "data": images,
    }
    if len(formats) == 1:
        normalized["output_format"] = next(iter(formats))
    if isinstance(payload.get("usage"), Mapping):
        normalized["usage"] = dict(payload["usage"])
    return normalized


def _normalize_prediction_response(payload: Mapping[str, Any]) -> dict[str, Any]:
    output = payload.get("output")
    if not isinstance(output, Mapping):
        raise ValueError("AIHubMix prediction response did not contain output")
    image_items = output.get("images")
    if not isinstance(image_items, list):
        raise ValueError("AIHubMix prediction response did not contain images")
    images: list[dict[str, str]] = []
    for item in image_items:
        if isinstance(item, str) and item:
            images.append({"url": item})
        elif isinstance(item, Mapping):
            if isinstance(item.get("url"), str) and item["url"]:
                images.append({"url": item["url"]})
            elif isinstance(item.get("b64_json"), str) and item["b64_json"]:
                images.append({"b64_json": item["b64_json"]})
    if not images:
        raise ValueError("AIHubMix prediction response did not contain usable images")
    return {
        "created": output.get("created", payload.get("created", 0)),
        "data": images,
    }


def normalize_aihubmix_image_response(
    response_kind: str,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    if response_kind == "openai":
        return dict(payload)
    if response_kind == "gemini":
        return _normalize_gemini_response(payload)
    if response_kind == "prediction":
        return _normalize_prediction_response(payload)
    raise ValueError(f"Unsupported AIHubMix response kind: {response_kind}")


def _has_header(headers: Mapping[str, Any], name: str) -> bool:
    expected = name.lower()
    return any(
        str(header).lower() == expected and bool(str(value).strip())
        for header, value in headers.items()
    )


def _is_transport_failure_response(response: Any) -> bool:
    if getattr(response, "status_code", None) != 502:
        return False
    if getattr(response, "raw", None) is not None:
        return False
    try:
        payload = response.json()
    except (AttributeError, ValueError):
        return False
    error = payload.get("error") if isinstance(payload, Mapping) else None
    return isinstance(error, Mapping) and error.get("type") == "upstream_transport_error"


def request_with_origin_fallback(
    send_request: Callable[[str], _ResponseT],
    *,
    primary_origin: str,
    secondary_origin: str,
    method: str,
    request_headers: Mapping[str, Any],
) -> _ResponseT:
    """Try a secondary origin only after a definite replay-safe transport failure."""
    response = send_request(primary_origin)
    replay_safe = (
        method.upper() in _SAFE_FAILOVER_METHODS
        or _has_header(request_headers, "Idempotency-Key")
    )
    if (
        not replay_safe
        or secondary_origin == primary_origin
        or not _is_transport_failure_response(response)
    ):
        return response

    close = getattr(response, "close", None)
    if callable(close):
        close()
    return send_request(secondary_origin)


def request_with_aihubmix_origin_fallback(
    send_request: Callable[[str], _ResponseT],
    *,
    primary_origin: str,
    secondary_origin: str,
    method: str,
    request_headers: Mapping[str, Any],
) -> _ResponseT:
    """Backward-compatible AIHubMix wrapper around bounded origin failover."""
    return request_with_origin_fallback(
        send_request,
        primary_origin=primary_origin,
        secondary_origin=secondary_origin,
        method=method,
        request_headers=request_headers,
    )
