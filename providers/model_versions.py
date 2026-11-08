"""Version numbers in model names, so code follows new releases without a list to update.

GPT Image IDs are `gpt-image-<major>[.<minor>]` with an optional suffix: `gpt-image-2`,
`gpt-image-2.5-sunburst`, `gpt-image-2-2026-04-21` or a relay's `gpt-image-2-free`.
The major version is one digit, so a typo such as `gpt-image-25` is not read as 25.
"""

from __future__ import annotations

import re
from typing import Any

_GPT_IMAGE = re.compile(r"gpt-image-(\d)(?:\.(\d{1,2}))?(?:-.*)?")


def model_basename(model_id: Any) -> str:
    """The lowercase model name without its `provider:` prefix or `namespace/` path."""
    normalized = str(model_id or "").strip().lower()
    if ":" in normalized:
        normalized = normalized.split(":", 1)[1]
    return normalized.rsplit("/", 1)[-1]


def gpt_image_version(model_id: Any) -> tuple[int, int] | None:
    """`(2, 6)` for `gguu:gpt-image-2.6`, `(2, 0)` for `gpt-image-2`; None for other models."""
    match = _GPT_IMAGE.fullmatch(model_basename(model_id))
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2) or 0)
