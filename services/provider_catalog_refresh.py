"""Keep every provider's live model catalog current without a manual refresh.

The global model list (/v1/models, /admin/models, /docs and the Operations menu) showed
only built-in IDs for a provider until an administrator pressed "Refresh catalog". Each of
those views now asks this refresher to update the catalogs last refreshed more than
PROVIDER_CATALOG_REFRESH_SECONDS ago, and the Worker's health-check cron asks too. The
refresh runs in one background thread, so a view does not wait on provider APIs: it shows
the last good catalog, which D1 keeps across Containers. Only the first refresh of a new
process is awaited, for at most PROVIDER_CATALOG_COLD_WAIT_SECONDS, so the first view after
a deploy already lists every provider's current models. A provider whose refresh fails
keeps its last good catalog and is retried after RETRY_SECONDS.

Image relays keep their own inline refresh (services.image_relay_catalog).
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable

from providers.image_relays import image_relay_specs
from services.image_relay_catalog import refresh_image_relay_catalog
from services.provider_catalog_service import (
    PROVIDER_CATALOG_SPECS,
    ProviderCatalogService,
)

logger = logging.getLogger(__name__)
RETRY_SECONDS = 300


class ProviderCatalogAutoRefresh:
    """Share one background refresh of the non-relay provider catalogs per process."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        ttl_seconds: float = 1800,
        retry_seconds: float = RETRY_SECONDS,
        cold_wait_seconds: float = 10,
    ):
        self._clock = clock
        self._ttl_seconds = ttl_seconds
        self._retry_seconds = min(retry_seconds, ttl_seconds)
        self._cold_wait_seconds = cold_wait_seconds
        self._next_refresh: dict[tuple[str, str], float] = {}
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._first_refresh = threading.Event()

    def start(self, app, auth_service_cls, proxy_service_cls) -> threading.Thread | None:
        """Start a refresh of the stale catalogs unless one is running; never waits."""
        base_urls = app.config["API_BASE_URLS"]
        relays = {spec.provider for spec in image_relay_specs()}
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return None
            now = self._clock()
            targets = {
                provider: str(base_urls[provider])
                for provider in PROVIDER_CATALOG_SPECS
                if provider not in relays
                and base_urls.get(provider)
                and now >= self._next_refresh.get((provider, str(base_urls[provider])), 0)
            }
            if not targets:
                return None
            # A refresh that dies without reporting is retried, not repeated on every read.
            for target in targets.items():
                self._next_refresh[target] = now + self._retry_seconds
            self._thread = threading.Thread(
                target=self._run,
                args=(app, targets, auth_service_cls, proxy_service_cls),
                name="provider-catalog-refresh",
                daemon=True,
            )
            self._thread.start()
            return self._thread

    def wait_for_first_refresh(self) -> None:
        """Let the first views of a new process see the first refresh, within a bound."""
        with self._lock:
            started = self._thread is not None
        if started and not self._first_refresh.is_set():
            self._first_refresh.wait(self._cold_wait_seconds)

    def _run(self, app, targets, auth_service_cls, proxy_service_cls) -> None:
        results = []
        try:
            with app.app_context():
                results = ProviderCatalogService.refresh_configured(
                    targets,
                    auth_service_cls,
                    proxy_service_cls,
                    supplemental_base_urls={
                        "opencode": app.config.get("OPENCODE_ZEN_BASE_URL"),
                    },
                )
        except Exception as error:  # noqa: BLE001 - discovery is optional.
            # A storage or adapter failure must not hide built-in models or the last good catalog.
            logger.warning(
                "Provider catalog auto-refresh failed error_type=%s",
                type(error).__name__,
            )
        finally:
            finished_at = self._clock()
            with self._lock:
                for result in results:
                    provider = result.get("provider")
                    if provider not in targets:
                        continue
                    delay = (
                        self._ttl_seconds
                        if result.get("status") in {"updated", "skipped"}
                        else self._retry_seconds
                    )
                    self._next_refresh[provider, targets[provider]] = finished_at + delay
            self._first_refresh.set()
            failed = sorted(
                result["provider"] for result in results if result.get("status") == "failed"
            )
            if failed:
                logger.info("Provider catalogs not refreshed: %s", ", ".join(failed))


def start_provider_catalog_refresh(app, auth_service_cls, proxy_service_cls):
    """Start the background provider catalog refresh when it is enabled."""
    from services.config_revision_sync import request_poll

    request_poll(app)
    refresher = app.extensions.get("provider_catalog_refresh")
    if refresher is None or not app.config.get("PROVIDER_CATALOG_AUTO_REFRESH", True):
        return None
    return refresher.start(app, auth_service_cls, proxy_service_cls)


def refresh_model_catalogs(app, auth_service_cls, proxy_service_cls) -> None:
    """Bring a catalog view up to date: providers in the background, image relays inline."""
    start_provider_catalog_refresh(app, auth_service_cls, proxy_service_cls)
    refresh_image_relay_catalog(app, auth_service_cls, proxy_service_cls)
    refresher = app.extensions.get("provider_catalog_refresh")
    if refresher is not None:
        refresher.wait_for_first_refresh()


def refresh_provider_catalog_revision(revision):
    """Load the durable catalog strictly; an outage leaves the last installed copy intact."""
    from services import control_state_d1, provider_catalog_d1

    fetched = {}
    listing = provider_catalog_d1._listing(control_state_d1.call(provider_catalog_d1.ENDPOINT, "list"))
    for provider in listing:
        snapshot = provider_catalog_d1._snapshot(
            control_state_d1.call(provider_catalog_d1.ENDPOINT, "get", provider=provider), provider)
        if snapshot is None:
            raise ValueError("Catalog snapshot disappeared during refresh")
        fetched[provider] = snapshot
    with provider_catalog_d1._refresh_lock, provider_catalog_d1._lock:
        provider_catalog_d1._state.update(snapshots=fetched, loaded=True, expires=float("inf"),
                                          version=provider_catalog_d1._state["version"] + 1)
