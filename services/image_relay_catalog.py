"""Bounded, read-triggered discovery for configured image relays."""

import logging
import threading
import time
from collections.abc import Callable, Mapping

from providers.image_relays import image_relay_specs
from services.provider_catalog_service import ProviderCatalogService

logger = logging.getLogger(__name__)


class ImageRelayCatalogRefresh:
    """Share one refresh window across a process's authenticated catalog views."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        ttl_seconds: float = 300,
        retry_seconds: float = 60,
    ):
        self._clock = clock
        self._ttl_seconds = ttl_seconds
        self._retry_seconds = retry_seconds
        self._next_refresh: dict[tuple[str, str], float] = {}
        self._lock = threading.Lock()

    def refresh(
        self, base_urls: Mapping[str, str], auth_service_cls, proxy_service_cls
    ) -> None:
        # Wait for a cold refresh already in flight instead of returning an
        # empty catalog to a second menu request or starting duplicate fetches.
        with self._lock:
            now = self._clock()
            targets = {
                spec.provider: str(base_urls[spec.provider])
                for spec in image_relay_specs()
                if base_urls.get(spec.provider)
                and now
                >= self._next_refresh.get(
                    (spec.provider, str(base_urls[spec.provider])), 0
                )
            }
            if not targets:
                return
            for provider, base_url in targets.items():
                self._next_refresh[provider, base_url] = now + self._retry_seconds
            try:
                results = ProviderCatalogService.refresh_configured(
                    targets, auth_service_cls, proxy_service_cls
                )
            except Exception as error:
                # Discovery is optional; a storage or adapter failure must not
                # hide built-in models or the last successful catalog.
                logger.warning(
                    "Image relay catalog refresh failed error_type=%s",
                    type(error).__name__,
                )
                return
            finished_at = self._clock()
            for result in results:
                provider = result["provider"]
                delay = (
                    self._ttl_seconds
                    if result["status"] == "updated"
                    else self._retry_seconds
                )
                self._next_refresh[provider, targets[provider]] = finished_at + delay


def refresh_image_relay_catalog(app, auth_service_cls, proxy_service_cls) -> None:
    if app.config.get("IMAGE_RELAY_CATALOG_AUTO_REFRESH", True):
        app.extensions["image_relay_catalog_refresh"].refresh(
            app.config["API_BASE_URLS"], auth_service_cls, proxy_service_cls
        )
