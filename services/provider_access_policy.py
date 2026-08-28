from __future__ import annotations

import re

from services.transport_policy import RAW_PASSTHROUGH_PROVIDERS

ADMIN_ONLY_PROVIDERS = RAW_PASSTHROUGH_PROVIDERS | {"opencode"}

MODEL_READ_PATHS = frozenset(
    {
        "models",
        "v1/models",
        "openai/v1/models",
    }
)

GENERATION_WRITE_PATHS = frozenset(
    {
        "chat/completions",
        "v1/chat/completions",
        "openai/v1/chat/completions",
        "completions",
        "v1/completions",
        "responses",
        "v1/responses",
        "embeddings",
        "v1/embeddings",
        "images/generations",
        "v1/images/generations",
        "predict",
    }
)

PALM_GENERATION_PATHS = frozenset(
    {
        "models/chat-bison-001/generatetext",
        "models/text-bison-001/generatetext",
    }
)

GEMINI_GENERATION_PATH = re.compile(
    r"^(?:v1beta/)?models/[a-z0-9][a-z0-9._-]{0,127}"
    r":(?:generatecontent|streamgeneratecontent)$"
)


def provider_route_scope(provider: str, path: str, method: str) -> str:
    """Return the least privilege required for a direct provider route."""
    normalized_provider = str(provider or "").strip().lower()
    normalized_path = str(path or "").strip("/").lower()
    normalized_method = str(method or "").strip().upper()

    if normalized_provider in ADMIN_ONLY_PROVIDERS:
        return "admin"
    if normalized_method == "GET" and normalized_path in MODEL_READ_PATHS:
        return "models"
    if normalized_method != "POST":
        return "admin"
    if normalized_path in GENERATION_WRITE_PATHS:
        return "chat"
    if normalized_provider == "palm" and normalized_path in PALM_GENERATION_PATHS:
        return "chat"
    if normalized_provider in {"gemini", "gemma"} and GEMINI_GENERATION_PATH.fullmatch(
        normalized_path
    ):
        return "chat"
    return "admin"
