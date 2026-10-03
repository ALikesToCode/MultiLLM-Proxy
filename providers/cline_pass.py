"""ClinePass, Cline's flat-rate coding subscription, through Cline's OpenAI-compatible API.

Chat goes to https://api.cline.bot/api/v1/chat/completions with CLINE_API_KEY and a full
`cline-pass/...` model ID. Cline's /models list names upstream models, not the
subscription's, so discovery reads the public recommended-models document: its
`clinePass` list is what the subscription serves, and its `free` list is served on the
same key at no charge (https://docs.cline.bot/getting-started/clinepass).

Non-streaming completions arrive wrapped as {"data": <completion>, "success": true};
event streams are plain OpenAI chunks.
"""

from __future__ import annotations

from typing import Any

CLINE_API_BASE_URL = "https://api.cline.bot/api/v1"
CLINE_RECOMMENDED_MODELS_PATH = "ai/cline/recommended-models"
# Recommended-models sections the subscription key serves; each entry is tagged with its
# section as `required_plan`, and the free pools admit only `free` entries.
CLINE_PASS_CATALOG_SECTIONS = ("clinePass", "free")
CLINE_FREE_PLAN = "free"
# Free models under this prefix answer API calls with 403 "only available via Cline product
# surfaces" (checked 2026-10-03), so only the rest of the free list can serve the free pools.
CLINE_PRODUCT_ONLY_PREFIX = "cline-free/"
# Built-in until the first catalog refresh; the live list replaces it.
CLINE_PASS_MODEL_IDS = (
    "cline-pass/glm-5.3",
    "cline-pass/glm-5.3-flash",
    "cline-pass/kimi-k3",
    "cline-pass/deepseek-v4-pro",
    "cline-pass/deepseek-v4.1-flash",
    "cline-pass/qwen3.8-max",
    "cline-pass/qwen3.7-max",
    "cline-pass/qwen3.7-plus",
    "cline-pass/minimax-m3",
    "cline-pass/mimo-v2.6-pro",
    "cline-pass/mimo-v2.6-flash",
    "cline-pass/mimo-v2.5-pro",
    "cline-pass/mimo-v2.5",
    "cline-pass/muse-spark-1.3-contributor",
)


def cline_completion_payload(payload: Any) -> Any:
    """Unwrap Cline's non-streaming envelope, {"data": {...}, "success": true}."""
    if (
        isinstance(payload, dict)
        and "choices" not in payload
        and "success" in payload
        and isinstance(payload.get("data"), dict)
    ):
        return payload["data"]
    return payload


def cline_pass_catalog_entries(payload: Any) -> list[dict[str, Any]]:
    """The ClinePass and free model entries of a recommended-models document, each
    tagged with the section it came from."""
    if not isinstance(payload, dict):
        return []
    return [
        {**item, "required_plan": section}
        for section in CLINE_PASS_CATALOG_SECTIONS
        if isinstance(payload.get(section), list)
        for item in payload[section]
        if isinstance(item, dict)
    ]
