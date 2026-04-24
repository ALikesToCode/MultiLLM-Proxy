import os
import sqlite3
from contextlib import closing
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from config import Config
from providers.base import ModelInfo
from providers.registry import get_registry


STATIC_PROVIDER_MODELS = {
    "groq": "GROQ_MODELS",
    "together": "TOGETHER_MODELS",
    "chutes": "CHUTES_MODELS",
    "gemini": "GEMINI_MODELS",
    "gemma": "GEMMA_MODELS",
}

DEFAULT_MODEL_IDS = {
    "openai": ["gpt-4.1", "gpt-4.1-mini"],
    "openrouter": ["openai/gpt-4.1", "anthropic/claude-sonnet-4.5"],
    "opencode": ["kimi-k2.5"],
    "xai": ["grok-4"],
    "cerebras": ["llama3.1-8b"],
    "azure": ["gpt-4o-mini"],
    "scaleway": ["llama-3.1-8b-instruct"],
    "hyperbolic": ["meta-llama/Meta-Llama-3.1-8B-Instruct"],
    "sambanova": ["Meta-Llama-3.1-8B-Instruct"],
}


class ModelRegistry:
    _storage_path: Optional[Path] = None

    @classmethod
    def _default_storage_path(cls) -> Path:
        return Path(__file__).resolve().parent.parent / "instance" / "model_registry.sqlite3"

    @classmethod
    def _get_storage_path(cls) -> Path:
        configured_path = os.environ.get("MODEL_REGISTRY_DB_PATH")
        if configured_path:
            return Path(configured_path)
        if cls._storage_path is None:
            cls._storage_path = cls._default_storage_path()
        return cls._storage_path

    @classmethod
    def _connect(cls) -> sqlite3.Connection:
        storage_path = cls._get_storage_path()
        storage_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(storage_path)
        connection.row_factory = sqlite3.Row
        return connection

    @classmethod
    def _ensure_storage(cls, connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS model_overrides (
                model_id TEXT PRIMARY KEY,
                status TEXT NOT NULL
            )
            """
        )

    @staticmethod
    def parse_model_id(model_id: Optional[str]) -> tuple[str, str]:
        if not model_id or ":" not in model_id:
            raise ValueError("Model must use provider:model format")
        provider, model = model_id.split(":", 1)
        provider = provider.strip().lower()
        model = model.strip()
        if not provider or not model:
            raise ValueError("Model must use provider:model format")
        return provider, model

    @classmethod
    def _provider_models(cls, provider: str) -> Iterable[str]:
        config_attr = STATIC_PROVIDER_MODELS.get(provider)
        if config_attr:
            yield from getattr(Config, config_attr, [])
        yield from DEFAULT_MODEL_IDS.get(provider, [])

    @classmethod
    def _status_overrides(cls) -> Dict[str, str]:
        with closing(cls._connect()) as connection:
            cls._ensure_storage(connection)
            rows = connection.execute("SELECT model_id, status FROM model_overrides").fetchall()
            return {row["model_id"]: row["status"] for row in rows}

    @classmethod
    def list_models(cls, base_urls: Dict[str, str]) -> list[ModelInfo]:
        overrides = cls._status_overrides()
        adapters = get_registry(base_urls)
        models: list[ModelInfo] = []

        for provider, adapter in adapters.items():
            capabilities = adapter.capabilities()
            seen: set[str] = set()
            for provider_model_id in cls._provider_models(provider):
                if provider_model_id in seen:
                    continue
                seen.add(provider_model_id)
                model_id = f"{provider}:{provider_model_id}"
                models.append(
                    ModelInfo(
                        id=model_id,
                        provider=provider,
                        display_name=provider_model_id,
                        supports_streaming=capabilities.supports_streaming,
                        supports_tools=capabilities.supports_tools,
                        supports_vision=capabilities.supports_vision,
                        supports_audio=capabilities.supports_audio,
                        supports_json_schema=capabilities.supports_json_schema,
                        status=overrides.get(model_id, "available"),
                    )
                )

        return sorted(models, key=lambda model: model.id)

    @classmethod
    def get_model(cls, model_id: str, base_urls: Dict[str, str]) -> Optional[ModelInfo]:
        try:
            provider, provider_model_id = cls.parse_model_id(model_id)
        except ValueError:
            return None

        adapter = get_registry(base_urls).get(provider)
        if not adapter:
            return None

        if provider_model_id not in set(cls._provider_models(provider)):
            return None

        capabilities = adapter.capabilities()
        return ModelInfo(
            id=model_id,
            provider=provider,
            display_name=provider_model_id,
            supports_streaming=capabilities.supports_streaming,
            supports_tools=capabilities.supports_tools,
            supports_vision=capabilities.supports_vision,
            supports_audio=capabilities.supports_audio,
            supports_json_schema=capabilities.supports_json_schema,
            status=cls.get_model_status(model_id),
        )

    @classmethod
    def get_model_status(cls, model_id: str) -> str:
        return cls._status_overrides().get(model_id, "available")

    @classmethod
    def disable_model(cls, model_id: str) -> None:
        with closing(cls._connect()) as connection:
            cls._ensure_storage(connection)
            connection.execute(
                """
                INSERT INTO model_overrides (model_id, status)
                VALUES (?, 'disabled')
                ON CONFLICT(model_id) DO UPDATE SET status = excluded.status
                """,
                (model_id,),
            )
            connection.commit()

    @staticmethod
    def to_admin_dict(model: ModelInfo) -> Dict[str, Any]:
        payload = asdict(model)
        for key in ("input_cost_per_million", "output_cost_per_million"):
            if payload[key] is not None:
                payload[key] = str(payload[key])
        return payload

    @staticmethod
    def to_openai_model_dict(model: ModelInfo) -> Dict[str, Any]:
        return {
            "id": model.id,
            "object": "model",
            "created": 0,
            "owned_by": model.provider,
            "status": model.status,
        }
