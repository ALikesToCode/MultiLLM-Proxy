import logging
import re
import sqlite3
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from services.sqlite_store import connect, storage_path

logger = logging.getLogger(__name__)
MAX_MODELS_PER_PROVIDER = 5000
_MODEL_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,255}$")


@dataclass(frozen=True)
class ProviderCatalogSpec:
    upstream_path: str
    proxy_path: str


@dataclass(frozen=True)
class ProviderCatalogModel:
    provider: str
    model_id: str
    discovered_at: str


PROVIDER_CATALOG_SPECS = {
    "openai": ProviderCatalogSpec("v1/models", "/openai/v1/models"),
    "openrouter": ProviderCatalogSpec("models", "/openrouter/models"),
    "linkapi": ProviderCatalogSpec("v1/models", "/linkapi/v1/models"),
    "codex-easy": ProviderCatalogSpec("v1/models", "/codex-easy/v1/models"),
    "kimi-code": ProviderCatalogSpec("models", "/kimi-code/v1/models"),
    "groq": ProviderCatalogSpec("openai/v1/models", "/groq/openai/v1/models"),
    "opencode": ProviderCatalogSpec("models", "/opencode/v1/models"),
    "nanogpt": ProviderCatalogSpec("v1/models", "/nanogpt/v1/models"),
    "navyai": ProviderCatalogSpec("v1/models", "/navyai/v1/models"),
    "together": ProviderCatalogSpec("v1/models", "/together/v1/models"),
    "xai": ProviderCatalogSpec("v1/models", "/xai/v1/models"),
    "cerebras": ProviderCatalogSpec("v1/models", "/cerebras/v1/models"),
}


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ProviderCatalogService:
    """Discover and cache provider model IDs without persisting credentials."""

    @staticmethod
    def _connect() -> sqlite3.Connection:
        return connect(storage_path("MODEL_REGISTRY_DB_PATH", "model_registry.sqlite3"))

    @classmethod
    def _ensure_storage(cls, connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS provider_model_catalog (
                provider TEXT NOT NULL,
                model_id TEXT NOT NULL,
                discovered_at TEXT NOT NULL,
                PRIMARY KEY (provider, model_id)
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_provider_model_catalog_provider
            ON provider_model_catalog(provider, model_id)
            """
        )

    @classmethod
    def list_models(cls) -> list[ProviderCatalogModel]:
        with closing(cls._connect()) as connection:
            cls._ensure_storage(connection)
            connection.commit()
            rows = connection.execute(
                """
                SELECT provider, model_id, discovered_at
                FROM provider_model_catalog
                ORDER BY provider, model_id
                """
            ).fetchall()
        return [
            ProviderCatalogModel(
                provider=str(row["provider"]),
                model_id=str(row["model_id"]),
                discovered_at=str(row["discovered_at"]),
            )
            for row in rows
        ]

    @classmethod
    def has_model(cls, provider: str, model_id: str) -> bool:
        """Return whether a model appears in the last successful live catalog."""
        with closing(cls._connect()) as connection:
            cls._ensure_storage(connection)
            connection.commit()
            row = connection.execute(
                """
                SELECT 1
                FROM provider_model_catalog
                WHERE provider = ? AND model_id = ?
                LIMIT 1
                """,
                (provider, model_id),
            ).fetchone()
        return row is not None

    @classmethod
    def replace_provider_models(
        cls,
        provider: str,
        model_ids: tuple[str, ...],
        *,
        discovered_at: str | None = None,
    ) -> None:
        timestamp = discovered_at or _utcnow_iso()
        with closing(cls._connect()) as connection:
            cls._ensure_storage(connection)
            connection.commit()
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "DELETE FROM provider_model_catalog WHERE provider = ?",
                (provider,),
            )
            connection.executemany(
                """
                INSERT INTO provider_model_catalog (provider, model_id, discovered_at)
                VALUES (?, ?, ?)
                """,
                [(provider, model_id, timestamp) for model_id in model_ids],
            )
            connection.commit()

    @staticmethod
    def _model_collection(payload: Any) -> list[Any]:
        if isinstance(payload, list):
            return payload
        if not isinstance(payload, dict):
            return []
        for key in ("data", "models", "items"):
            collection = payload.get(key)
            if isinstance(collection, list):
                return collection
            if isinstance(collection, dict):
                return list(collection.values())
        return []

    @classmethod
    def extract_model_ids(cls, provider: str, payload: Any) -> tuple[str, ...]:
        normalized: set[str] = set()
        for item in cls._model_collection(payload):
            candidate: str | None
            if isinstance(item, str):
                candidate = item
            elif isinstance(item, dict):
                candidate = next(
                    (
                        item[key]
                        for key in ("id", "model", "model_id", "name")
                        if isinstance(item.get(key), str)
                    ),
                    None,
                )
            else:
                candidate = None
            if not candidate:
                continue
            candidate = candidate.strip()
            provider_prefix = f"{provider}:"
            if candidate.lower().startswith(provider_prefix.lower()):
                candidate = candidate[len(provider_prefix) :]
            if _MODEL_ID_PATTERN.fullmatch(candidate):
                normalized.add(candidate)
        return tuple(sorted(normalized))

    @staticmethod
    def _credential_candidates(auth_service_cls, provider: str) -> tuple[str, ...]:
        if provider == "nanogpt":
            return tuple(auth_service_cls.get_api_keys(provider))
        api_key = auth_service_cls.get_api_key(provider)
        return (api_key,) if api_key else ()

    @classmethod
    def _fetch_provider(
        cls,
        provider: str,
        spec: ProviderCatalogSpec,
        base_url: str,
        credentials: tuple[str, ...],
        proxy_service_cls,
    ) -> dict[str, Any]:
        last_status: int | None = None
        for credential in credentials:
            response = None
            try:
                headers = proxy_service_cls.prepare_headers(
                    {"Accept": "application/json"},
                    provider,
                    credential,
                    upstream_path=spec.upstream_path,
                )
                response = proxy_service_cls.make_request(
                    method="GET",
                    url=f"{base_url.rstrip('/')}/{spec.upstream_path}",
                    headers=headers,
                    params=[],
                    data=None,
                    api_provider=provider,
                    use_cache=False,
                    timeout_override=(3, 10),
                    force_raw_passthrough=True,
                )
                last_status = int(response.status_code)
                if 200 <= last_status < 300:
                    model_ids = cls.extract_model_ids(provider, response.json())
                    if model_ids:
                        truncated = len(model_ids) > MAX_MODELS_PER_PROVIDER
                        return {
                            "provider": provider,
                            "status": "updated",
                            "models": model_ids[:MAX_MODELS_PER_PROVIDER],
                            "truncated": truncated,
                        }
                    return {
                        "provider": provider,
                        "status": "failed",
                        "message": "Catalog returned no usable model IDs",
                    }
            except Exception as error:  # noqa: BLE001 - provider transports vary.
                logger.warning(
                    "Provider model catalog refresh failed provider=%s error_type=%s",
                    provider,
                    type(error).__name__,
                )
            finally:
                if response is not None and hasattr(response, "close"):
                    response.close()

        return {
            "provider": provider,
            "status": "failed",
            "message": f"Catalog request returned HTTP {last_status}"
            if last_status is not None
            else "Catalog request failed",
        }

    @classmethod
    def refresh_configured(
        cls,
        base_urls: Mapping[str, str],
        auth_service_cls,
        proxy_service_cls,
    ) -> list[dict[str, Any]]:
        refresh_targets = []
        results: list[dict[str, Any]] = []
        for provider, spec in PROVIDER_CATALOG_SPECS.items():
            base_url = base_urls.get(provider)
            if not base_url:
                continue
            credentials = cls._credential_candidates(auth_service_cls, provider)
            if not credentials:
                results.append(
                    {
                        "provider": provider,
                        "status": "skipped",
                        "message": "Provider credential is not configured",
                    }
                )
                continue
            refresh_targets.append((provider, spec, str(base_url), credentials))

        if refresh_targets:
            max_workers = min(4, len(refresh_targets))
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(
                        cls._fetch_provider,
                        provider,
                        spec,
                        base_url,
                        credentials,
                        proxy_service_cls,
                    ): provider
                    for provider, spec, base_url, credentials in refresh_targets
                }
                for future in as_completed(futures):
                    provider = futures[future]
                    try:
                        result = future.result()
                    except Exception as error:  # noqa: BLE001 - isolate adapters.
                        logger.warning(
                            "Provider model catalog worker failed provider=%s error_type=%s",
                            provider,
                            type(error).__name__,
                        )
                        result = {
                            "provider": provider,
                            "status": "failed",
                            "message": "Catalog request failed",
                        }
                    if result["status"] == "updated":
                        model_ids = tuple(result.pop("models"))
                        cls.replace_provider_models(result["provider"], model_ids)
                        result["model_count"] = len(model_ids)
                    results.append(result)

        return sorted(results, key=lambda result: result["provider"])
