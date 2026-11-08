"""Route candidates that follow a provider's newest release instead of naming one model.

An automatic route may hold a placeholder such as `gguu:gpt-image@latest`. Each read of
the route replaces it with the models of that family the provider lists now, newest
version first, so `gpt-image-2.6` leads the route as soon as GGUU's catalog shows it and
nobody has to edit the route again. The catalog is the provider's last good live model
list (refreshed by model-list views and the half-hourly health check), or the relay's
built-in list before its first refresh.

`<family>@latest` orders each version's variants by detail: Sunburst (OpenAI's detail
model), then the unsuffixed ID, other suffixes, and Flare (the speed model) last.
`<family>@latest-fast` puts speed variants first, newest version first within each
group, and leaves out Sunburst. Dated snapshots such as `gpt-image-2-2026-04-21` repeat
an alias and are skipped. A placeholder adds at most MAX_MODELS_PER_PLACEHOLDER models,
and nothing when the provider lists none of the family.
"""

from __future__ import annotations

import dataclasses
import logging
import re
from collections.abc import Iterable

logger = logging.getLogger(__name__)

MAX_MODELS_PER_PLACEHOLDER = 4
LATEST = "latest"
LATEST_FAST = "latest-fast"
_PLACEHOLDER = re.compile(r"(?P<family>[a-z0-9][a-z0-9._/-]{0,127}?)@(?P<mode>latest(?:-fast)?)")
_DETAIL_VARIANTS = frozenset({"sunburst"})
_SPEED_VARIANTS = frozenset({"flare", "lite", "mini", "fast", "turbo"})
_DATED_SNAPSHOT = re.compile(r"(?:^|-)\d{4}-\d{2}-\d{2}$")


def parse_placeholder(provider_model: str) -> tuple[str, str] | None:
    """`("gpt-image", "latest")` for `gpt-image@latest`; None for an ordinary model ID."""
    match = _PLACEHOLDER.fullmatch(str(provider_model or ""))
    return (match.group("family"), match.group("mode")) if match else None


def is_placeholder(model_id: str) -> bool:
    _, separator, provider_model = str(model_id or "").partition(":")
    return bool(separator) and parse_placeholder(provider_model) is not None


def looks_like_placeholder(provider_model: str) -> bool:
    """A model ID that tries to be a placeholder, so a typo is refused instead of sent."""
    return "@latest" in str(provider_model or "").lower()


def _release(family: str, model_id: str) -> tuple[tuple[int, ...], str] | None:
    match = re.fullmatch(
        re.escape(family) + r"-(\d+(?:\.\d+)*)(?:-([a-z0-9]+(?:-[a-z0-9]+)*))?",
        model_id.lower(),
    )
    if match is None:
        return None
    variant = match.group(2) or ""
    if _DATED_SNAPSHOT.search(variant):
        return None
    return tuple(int(part) for part in match.group(1).split(".")), variant


def _detail_rank(variant: str) -> int:
    if variant in _DETAIL_VARIANTS:
        return 0
    if not variant:
        return 1
    return 3 if variant in _SPEED_VARIANTS else 2


def _speed_rank(variant: str) -> int:
    if variant in _SPEED_VARIANTS:
        return 0
    return 1 if not variant else 2


def order_releases(family: str, mode: str, model_ids: Iterable[str]) -> tuple[str, ...]:
    """The family's models in the order the placeholder tries them, capped."""
    releases = []
    for model_id in dict.fromkeys(model_ids):
        release = _release(family, model_id)
        if release is None:
            continue
        version, variant = release
        if mode == LATEST_FAST and variant in _DETAIL_VARIANTS:
            continue
        releases.append((model_id, version, variant))
    # Stable sorts: the last key applied is the primary one.
    releases.sort(key=lambda release: release[0])
    if mode == LATEST_FAST:
        releases.sort(key=lambda release: release[1], reverse=True)
        releases.sort(key=lambda release: _speed_rank(release[2]))
    else:
        releases.sort(key=lambda release: _detail_rank(release[2]))
        releases.sort(key=lambda release: release[1], reverse=True)
    return tuple(model_id for model_id, _, _ in releases[:MAX_MODELS_PER_PLACEHOLDER])


def provider_model_ids(provider: str) -> tuple[str, ...]:
    """The provider's last good live catalog, or the relay's built-in list without one."""
    from providers.image_relays import image_relay_model_ids
    from services.provider_catalog_service import ProviderCatalogService

    try:
        live = tuple(model.model_id for model in ProviderCatalogService.list_models()
                     if model.provider == provider)
    except Exception as error:  # noqa: BLE001 - a catalog outage must not stop dispatch.
        logger.warning("Latest-model catalog read failed provider=%s error_type=%s",
                       provider, type(error).__name__)
        live = ()
    return live or image_relay_model_ids(provider)


def resolve(model_id: str) -> tuple[str, ...]:
    """The concrete candidates a route entry stands for: itself unless it is a placeholder."""
    provider, separator, provider_model = str(model_id or "").partition(":")
    placeholder = parse_placeholder(provider_model) if separator else None
    if placeholder is None:
        return (model_id,)
    family, mode = placeholder
    return tuple(f"{provider}:{model}" for model in order_releases(family, mode, provider_model_ids(provider)))


def expand_candidates(candidates: Iterable[str], limit: int) -> tuple[str, ...]:
    """Replace placeholders with current models, keeping the first copy of a repeated ID."""
    expanded: dict[str, None] = {}
    for candidate in candidates:
        for model_id in resolve(candidate):
            expanded.setdefault(model_id, None)
    return tuple(expanded)[:limit]


def expand_canary(canary, candidates: tuple[str, ...]):
    """An approved canary placeholder approves the models it currently stands for."""
    approved = canary.approved_candidates
    if not any(is_placeholder(model_id) for model_id in approved):
        return canary
    current = expand_candidates(approved, len(approved) * MAX_MODELS_PER_PLACEHOLDER)
    return dataclasses.replace(canary, approved_candidates=tuple(
        model_id for model_id in current if model_id in candidates))
