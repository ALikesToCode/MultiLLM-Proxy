import re
import sqlite3
from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Mapping

from providers.registry import get_registry
from error_handlers import APIError
from services import auto_route_d1, canary_traffic, config_revision_sync
from services.model_registry import ModelRegistry
from services.sqlite_store import connect, storage_path


AUTO_ROUTE_PREFIX = "auto:"
MAX_AUTO_ROUTE_CANDIDATES = 16
_CANARY_UNSET = object()
# Media routes follow the Artificial Analysis image arena (Sep 2026): GPT Image 2.5
# Sunburst and Flare lead, then GPT Image 2 and Grok Imagine Image 2.0. GGUU serves
# them first at a flat ¥0.04 per image (1K to 4K); OpenAI charges about $0.21 at max.
# GGUU keys belong to one group, so Grok Imagine uses the separate gguu-grok relay.
# Codex Everywhere's image pool (ce-image, $0.015 per image) follows GGUU; the user keeps
# GGUU first because it is the cheapest.
# Cloudflare AI (AI Gateway billing, zero data retention), xAI, Together and AIHubMix
# follow, and a Workers AI model is the last resort. Operations edits persist in D1
# when the Worker provides it; on Container-local SQLite until the Container restarts.
DEFAULT_AUTO_ROUTES = {
    "auto:glm-5.2": (
        "nanogpt:zai-org/glm-5.2:thinking",
        "opencode:glm-5.2",
        "navyai:glm-5.2",
    ),
    # GLM 5.3 on the two subscriptions: ClinePass gave the first words in about 4 s through
    # the roleplay endpoint (2026-10-05), NanoGPT is the second provider.
    "auto:glm-5.3": (
        "cline-pass:cline-pass/glm-5.3",
        "nanogpt:z-ai/glm-5.3",
    ),
    # GPT-6.1 Sol cheapest first: Codex Everywhere Plus (0.03x OpenAI), then Pro (0.05x). Each
    # pool also rotates to its spare key. Seeded routes never use OpenRouter.
    "auto:gpt-6.1": (
        "ce-gpt-plus:gpt-6.1-sol",
        "ce-gpt-pro:gpt-6.1-sol",
    ),
    "auto:image": (
        "gguu:gpt-image-2.5-sunburst",
        "gguu:gpt-image-2.5-flare",
        "gguu:gpt-image-2",
        "gguu-grok:grok-imagine-image-2.0",
        "ce-image:gpt-image-2.5-sunburst",
        "ce-image:gpt-image-2.5-flare",
        "ce-image:gpt-image-2",
        "cloudflare:openai/gpt-image-2.5-sunburst",
        "openai:gpt-image-2.5-sunburst",
        "xai:grok-imagine-image-2.0",
        "together:openai/gpt-image-2",
        "aihubmix:gpt-image-2-free",
        "cloudflare:@cf/leonardo/lucid-origin",
    ),
    "auto:image-fast": (
        "gguu:gpt-image-2.5-flare",
        "gguu:gpt-image-2",
        "gguu-grok:grok-imagine-image-2.0",
        "ce-image:gpt-image-2.5-flare",
        "ce-image:gpt-image-2",
        "cloudflare:openai/gpt-image-2.5-flare",
        "openai:gpt-image-2.5-flare",
        "xai:grok-imagine-image-2.0",
        "cloudflare:@cf/black-forest-labs/flux-1-schnell",
    ),
    "auto:gpt-image-2.5": (
        "gguu:gpt-image-2.5-sunburst",
        "gguu:gpt-image-2.5",
        "gguu:gpt-image-2.5-flare",
        "ce-image:gpt-image-2.5-sunburst",
        "ce-image:gpt-image-2.5-flare",
        "cloudflare:openai/gpt-image-2.5-sunburst",
        "openai:gpt-image-2.5-sunburst",
        "openai:gpt-image-2.5-flare",
    ),
    # Edits and reference images: only candidates that accept source images. Cloudflare
    # and xAI take no mask and are skipped when one is sent; see routes/media_edits.py.
    "auto:image-edit": (
        "gguu:gpt-image-2.5-sunburst",
        "gguu:gpt-image-2",
        "ce-image:gpt-image-2.5-sunburst",
        "ce-image:gpt-image-2",
        "cloudflare:openai/gpt-image-2.5-sunburst",
        "openai:gpt-image-2.5-sunburst",
        "xai:grok-imagine-image-2.0",
        "aihubmix:gpt-image-2-free",
    ),
    # Embeddings, speech and transcription (routes/media_audio.py). Vectors from different
    # embedding models are not comparable, so auto:embed serves one model from two providers.
    "auto:embed": (
        "openai:text-embedding-3-small",
        "nanogpt:text-embedding-3-small",
    ),
    # Speech and transcription run on Gemini first (Google AI credits): 3.8 Flash-Lite TTS
    # is the fast default, 3.8 Flash TTS the high-fidelity narrator, and 3.5 Transcribe
    # detects 85+ languages. Aura speaks English only and is skipped for other scripts.
    "auto:tts": (
        "gemini:gemini-3.8-flash-lite-tts",
        "gemini:gemini-3.8-flash-tts",
        "openai:gpt-4o-mini-tts",
        "cloudflare:@cf/deepgram/aura-2-en",
    ),
    "auto:tts-narration": (
        "gemini:gemini-3.8-flash-tts",
        "gemini:gemini-3.8-flash-lite-tts",
        "openai:gpt-4o-mini-tts",
    ),
    "auto:stt": (
        "gemini:gemini-3.5-transcribe",
        "openai:gpt-4o-mini-transcribe",
        "nanogpt:gpt-4o-mini-transcribe",
        "together:openai/whisper-large-v3",
        "cloudflare:@cf/openai/whisper-large-v3-turbo",
    ),
    # Asynchronous video jobs; see services/video_generation.py.
    "auto:video": (
        "gemini:veo-3.1-generate-preview",
        "xai:grok-imagine-video-1.5",
        "cloudflare:google/veo-3.1",
        "openai:sora-2-pro",
        "openai:sora-2",
    ),
}
# Earlier seeded defaults. A stored route that still holds one follows the current default.
LEGACY_DEFAULT_AUTO_ROUTES = {
    "auto:glm-5.2": (
        (
            "nanogpt:glm-5.2",
            "opencode:glm-5.2",
            "navyai:glm-5.2",
        ),
    ),
    "auto:gpt-image-2.5": (
        (
            "gguu:gpt-image-2.5",
        ),
        (
            "gguu:gpt-image-2.5-sunburst",
            "gguu:gpt-image-2.5",
            "gguu:gpt-image-2.5-flare",
            "cloudflare:openai/gpt-image-2.5-sunburst",
            "openai:gpt-image-2.5-sunburst",
            "openai:gpt-image-2.5-flare",
        ),
    ),
    "auto:image": (
        (
            "gguu:gpt-image-2.5-sunburst",
            "gguu:gpt-image-2.5-flare",
            "gguu:gpt-image-2",
            "gguu:grok-imagine-image-2.0",
            "cloudflare:openai/gpt-image-2.5-sunburst",
            "openai:gpt-image-2.5-sunburst",
            "xai:grok-imagine-image-2.0",
            "together:openai/gpt-image-2",
            "aihubmix:gpt-image-2-free",
            "cloudflare:@cf/leonardo/lucid-origin",
        ),
        (
            "gguu:gpt-image-2.5-sunburst",
            "gguu:gpt-image-2.5-flare",
            "gguu:gpt-image-2",
            "gguu-grok:grok-imagine-image-2.0",
            "cloudflare:openai/gpt-image-2.5-sunburst",
            "openai:gpt-image-2.5-sunburst",
            "xai:grok-imagine-image-2.0",
            "together:openai/gpt-image-2",
            "aihubmix:gpt-image-2-free",
            "cloudflare:@cf/leonardo/lucid-origin",
        ),
    ),
    "auto:image-fast": (
        (
            "gguu:gpt-image-2.5-flare",
            "gguu:gpt-image-2",
            "cloudflare:openai/gpt-image-2.5-flare",
            "openai:gpt-image-2.5-flare",
            "xai:grok-imagine-image-2.0",
            "cloudflare:@cf/black-forest-labs/flux-1-schnell",
        ),
        (
            "gguu:gpt-image-2.5-flare",
            "gguu:gpt-image-2",
            "gguu-grok:grok-imagine-image-2.0",
            "cloudflare:openai/gpt-image-2.5-flare",
            "openai:gpt-image-2.5-flare",
            "xai:grok-imagine-image-2.0",
            "cloudflare:@cf/black-forest-labs/flux-1-schnell",
        ),
    ),
    "auto:tts": (
        (
            "openai:gpt-4o-mini-tts",
            "cloudflare:@cf/deepgram/aura-2-en",
        ),
    ),
    "auto:stt": (
        (
            "openai:gpt-4o-mini-transcribe",
            "nanogpt:gpt-4o-mini-transcribe",
            "together:openai/whisper-large-v3",
            "cloudflare:@cf/openai/whisper-large-v3-turbo",
        ),
    ),
    "auto:image-edit": (
        (
            "gguu:gpt-image-2.5-sunburst",
            "gguu:gpt-image-2",
            "cloudflare:openai/gpt-image-2.5-sunburst",
            "openai:gpt-image-2.5-sunburst",
            "xai:grok-imagine-image-2.0",
            "aihubmix:gpt-image-2-free",
        ),
    ),
}

# Providers served by the Worker rather than a credentialed OpenAI-compatible adapter.
MEDIA_ONLY_PROVIDERS = frozenset({"cloudflare"})
_ROUTE_ID_PATTERN = re.compile(r"^auto:[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MODEL_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,255}$")


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class AutoRoute:
    id: str
    candidates: tuple[str, ...]
    updated_at: str
    canary: canary_traffic.CanaryConfig = field(default_factory=canary_traffic.CanaryConfig)


class AutoRouteService:
    """Persist ordered, explicit provider candidates for virtual chat and image models."""

    @staticmethod
    def _connect() -> sqlite3.Connection:
        return connect(storage_path("MODEL_REGISTRY_DB_PATH", "model_registry.sqlite3"))

    @classmethod
    def _ensure_storage(cls, connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS auto_routes (
                route_id TEXT PRIMARY KEY,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS auto_route_candidates (
                route_id TEXT NOT NULL,
                priority INTEGER NOT NULL,
                model_id TEXT NOT NULL,
                PRIMARY KEY (route_id, priority),
                UNIQUE (route_id, model_id),
                FOREIGN KEY (route_id) REFERENCES auto_routes(route_id)
                    ON DELETE CASCADE
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_auto_route_candidates_route_priority
            ON auto_route_candidates(route_id, priority)
            """
        )

        for route_id, candidates in DEFAULT_AUTO_ROUTES.items():
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO auto_routes (route_id, updated_at)
                VALUES (?, ?)
                """,
                (route_id, _utcnow_iso()),
            )
            if cursor.rowcount:
                connection.executemany(
                    """
                    INSERT INTO auto_route_candidates (route_id, priority, model_id)
                    VALUES (?, ?, ?)
                    """,
                    [
                        (route_id, priority, model_id)
                        for priority, model_id in enumerate(candidates)
                    ],
                )
                continue

            current_candidates = tuple(
                str(row["model_id"])
                for row in connection.execute(
                    """
                    SELECT model_id
                    FROM auto_route_candidates
                    WHERE route_id = ?
                    ORDER BY priority
                    """,
                    (route_id,),
                ).fetchall()
            )
            if current_candidates not in LEGACY_DEFAULT_AUTO_ROUTES.get(route_id, ()):
                continue
            connection.execute(
                "DELETE FROM auto_route_candidates WHERE route_id = ?",
                (route_id,),
            )
            connection.executemany(
                """
                INSERT INTO auto_route_candidates (route_id, priority, model_id)
                VALUES (?, ?, ?)
                """,
                [
                    (route_id, priority, model_id)
                    for priority, model_id in enumerate(candidates)
                ],
            )
            connection.execute(
                "UPDATE auto_routes SET updated_at = ? WHERE route_id = ?",
                (_utcnow_iso(), route_id),
            )

    @staticmethod
    def is_auto_route(model_id: object) -> bool:
        return isinstance(model_id, str) and model_id.lower().startswith(
            AUTO_ROUTE_PREFIX
        )

    @staticmethod
    def normalize_route_id(route_id: object) -> str:
        if not isinstance(route_id, str):
            raise ValueError("Auto route ID must be a string")
        normalized = route_id.strip()
        if not _ROUTE_ID_PATTERN.fullmatch(normalized):
            raise ValueError(
                "Auto route ID must use auto:<name> with letters, numbers, dots, "
                "underscores, or hyphens"
            )
        return normalized

    @classmethod
    def normalize_candidates(
        cls,
        candidates: object,
        base_urls: Mapping[str, str],
    ) -> tuple[str, ...]:
        if not isinstance(candidates, list):
            raise ValueError("Auto route candidates must be a JSON array")
        if not candidates:
            raise ValueError("Auto route requires at least one candidate")
        if len(candidates) > MAX_AUTO_ROUTE_CANDIDATES:
            raise ValueError(
                f"Auto route supports at most {MAX_AUTO_ROUTE_CANDIDATES} candidates"
            )

        supported_providers = set(get_registry(base_urls)) | MEDIA_ONLY_PROVIDERS
        normalized: list[str] = []
        seen: set[str] = set()
        for candidate in candidates:
            if not isinstance(candidate, str) or len(candidate) > 256:
                raise ValueError("Each auto route candidate must be a model ID string")
            candidate_id = candidate.strip()
            if not _MODEL_ID_PATTERN.fullmatch(candidate_id):
                raise ValueError(
                    "Auto route model IDs may contain letters, numbers, dots, "
                    "underscores, slashes, colons, plus signs, at signs, or hyphens"
                )
            provider, provider_model = ModelRegistry.parse_model_id(candidate_id)
            if provider == "auto":
                raise ValueError("Auto routes cannot contain another auto route")
            if provider not in supported_providers:
                raise ValueError(f"Unsupported provider in auto route: {provider}")
            model_id = f"{provider}:{provider_model}"
            if model_id in seen:
                raise ValueError(f"Duplicate auto route candidate: {model_id}")
            seen.add(model_id)
            normalized.append(model_id)
        return tuple(normalized)

    @classmethod
    def _rows_to_routes(cls, rows: Iterable[sqlite3.Row], configurations=None) -> list[AutoRoute]:
        candidates_by_route: dict[str, list[str]] = {}
        updated_at_by_route: dict[str, str] = {}
        for row in rows:
            route_id = str(row["route_id"])
            updated_at_by_route[route_id] = str(row["updated_at"])
            candidates = candidates_by_route.setdefault(route_id, [])
            if row["model_id"] is not None:
                candidates.append(str(row["model_id"]))
        return [
            AutoRoute(
                id=route_id,
                candidates=tuple(candidates),
                updated_at=updated_at_by_route[route_id],
                canary=canary_traffic.stored_config(configurations or {}, route_id,
                    updated_at_by_route[route_id], candidates),
            )
            for route_id, candidates in candidates_by_route.items()
        ]

    @classmethod
    def _durable_routes(cls) -> list[AutoRoute]:
        """Seeded defaults overlaid by the routes operators saved in D1."""
        stored = config_revision_sync.route_copy()
        if stored is None:
            stored = auto_route_d1.stored_routes()
        routes = {route_id: AutoRoute(route_id, candidates, "") for route_id, candidates in DEFAULT_AUTO_ROUTES.items()}
        configurations = canary_traffic.durable_configurations()
        for route_id, (candidates, updated_at) in stored.items():
            # A route still holding a retired default follows the current default.
            if candidates in LEGACY_DEFAULT_AUTO_ROUTES.get(route_id, ()):
                candidates = DEFAULT_AUTO_ROUTES[route_id]
            routes[route_id] = AutoRoute(route_id, candidates, updated_at,
                canary_traffic.stored_config(configurations, route_id, updated_at, candidates))
        return [routes[route_id] for route_id in sorted(routes)]

    @classmethod
    def list_routes(cls) -> list[AutoRoute]:
        if auto_route_d1.using_d1():
            return cls._durable_routes()
        with closing(cls._connect()) as connection:
            cls._ensure_storage(connection)
            connection.commit()
            rows = connection.execute(
                """
                SELECT routes.route_id, routes.updated_at, candidates.model_id
                FROM auto_routes AS routes
                LEFT JOIN auto_route_candidates AS candidates
                    ON candidates.route_id = routes.route_id
                ORDER BY routes.route_id, candidates.priority
                """
            ).fetchall()
            configurations = canary_traffic.local_configurations(connection)
        return cls._rows_to_routes(rows, configurations)

    @classmethod
    def get_route(cls, route_id: object) -> AutoRoute | None:
        normalized = cls.normalize_route_id(route_id)
        if auto_route_d1.using_d1():
            return next((route for route in cls._durable_routes() if route.id == normalized), None)
        with closing(cls._connect()) as connection:
            cls._ensure_storage(connection)
            connection.commit()
            rows = connection.execute(
                """
                SELECT routes.route_id, routes.updated_at, candidates.model_id
                FROM auto_routes AS routes
                LEFT JOIN auto_route_candidates AS candidates
                    ON candidates.route_id = routes.route_id
                WHERE routes.route_id = ?
                ORDER BY candidates.priority
                """,
                (normalized,),
            ).fetchall()
            configurations = canary_traffic.local_configurations(connection)
        routes = cls._rows_to_routes(rows, configurations)
        return routes[0] if routes else None

    @classmethod
    def save_route(
        cls,
        route_id: object,
        candidates: object,
        base_urls: Mapping[str, str],
        *,
        canary: object = _CANARY_UNSET,
        expected_updated_at: str | None = None,
        current_revision: int | None = None,
    ) -> AutoRoute:
        normalized_route_id = cls.normalize_route_id(route_id)
        normalized_candidates = cls.normalize_candidates(candidates, base_urls)
        policy = canary_traffic.normalize_config({} if canary is _CANARY_UNSET else canary, normalized_candidates)
        if expected_updated_at is not None and not isinstance(expected_updated_at, str):
            raise ValueError("Expected route timestamp must be a string")
        if current_revision is not None and (type(current_revision) is not int or not 0 <= current_revision < 9007199254740991):
            raise ValueError("Current route revision must be a non-negative safe integer")
        updated_at = _utcnow_iso()
        if auto_route_d1.using_d1():
            if expected_updated_at is not None:
                raise ValueError("Durable route saves require current_revision instead of a local timestamp")
            if canary is not _CANARY_UNSET or current_revision is not None:
                result = canary_traffic.durable_request("canary_put", route_id=normalized_route_id,
                    candidates=list(normalized_candidates), updated_at=updated_at, canary=policy.as_dict(),
                    current_revision=current_revision)
                if result.get("stored") is not True:
                    raise APIError("Canary route storage did not confirm the save", 503)
                auto_route_d1.reset_cache()
                return AutoRoute(normalized_route_id, normalized_candidates, updated_at, policy)
            auto_route_d1.save_route(normalized_route_id, normalized_candidates, updated_at)
            return AutoRoute(id=normalized_route_id, candidates=normalized_candidates, updated_at=updated_at)

        if current_revision is not None:
            raise ValueError("Local route saves require expected_updated_at instead of a durable revision")
        with closing(cls._connect()) as connection:
            cls._ensure_storage(connection)
            connection.commit()
            connection.execute("BEGIN IMMEDIATE")
            if expected_updated_at is not None:
                previous = connection.execute("SELECT updated_at FROM auto_routes WHERE route_id = ?",
                                              (normalized_route_id,)).fetchone()
                if previous is None or previous["updated_at"] != expected_updated_at:
                    raise APIError("Auto route revision changed; reload before saving", 409)
            connection.execute(
                """
                INSERT INTO auto_routes (route_id, updated_at)
                VALUES (?, ?)
                ON CONFLICT(route_id) DO UPDATE SET updated_at = excluded.updated_at
                """,
                (normalized_route_id, updated_at),
            )
            connection.execute(
                "DELETE FROM auto_route_candidates WHERE route_id = ?",
                (normalized_route_id,),
            )
            connection.executemany(
                """
                INSERT INTO auto_route_candidates (route_id, priority, model_id)
                VALUES (?, ?, ?)
                """,
                [
                    (normalized_route_id, priority, model_id)
                    for priority, model_id in enumerate(normalized_candidates)
                ],
            )
            if canary is not _CANARY_UNSET:
                canary_traffic.save_local_configuration(connection, normalized_route_id, updated_at, policy)
            connection.commit()

        return AutoRoute(
            id=normalized_route_id,
            candidates=normalized_candidates,
            updated_at=updated_at,
            canary=policy,
        )
