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
        self._thread_lock = threading.Lock()
        self._thread: threading.Thread | None = None

    def start(self, app, auth_service_cls, proxy_service_cls) -> threading.Thread | None:
        """Refresh in a background thread unless one is running; never waits on a relay."""
        from services.provider_dispatch import capture_dispatch

        with self._thread_lock:
            if self._thread is not None and self._thread.is_alive():
                return None
            # The refresh dispatches as the account whose health check asked for it.
            self._thread = threading.Thread(
                target=capture_dispatch(self._refresh_in_background),
                args=(app.config["API_BASE_URLS"], auth_service_cls, proxy_service_cls),
                name="image-relay-catalog-refresh",
                daemon=True,
            )
            self._thread.start()
            return self._thread

    def _refresh_in_background(self, base_urls, auth_service_cls, proxy_service_cls) -> None:
        try:
            self.refresh(base_urls, auth_service_cls, proxy_service_cls)
        except Exception as error:  # noqa: BLE001 - discovery is optional.
            logger.warning(
                "Background image relay catalog refresh failed error_type=%s",
                type(error).__name__,
            )

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


def start_image_relay_catalog_refresh(app, auth_service_cls, proxy_service_cls):
    """Refresh relay catalogs off the request thread; the health-check cron asks every 30
    minutes, so a route that follows a relay's newest model (services.latest_models) sees
    a release even when nobody opens a model list."""
    refresher = app.extensions.get("image_relay_catalog_refresh")
    if refresher is None or not app.config.get("IMAGE_RELAY_CATALOG_AUTO_REFRESH", True):
        return None
    return refresher.start(app, auth_service_cls, proxy_service_cls)
