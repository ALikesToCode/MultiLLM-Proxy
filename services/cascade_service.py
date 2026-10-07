"""Operator cascade configuration, durable in D1 and SQLite in local mode."""

import copy
import json
from contextlib import closing
from datetime import datetime, timezone

from services import cascade_d1, intelligence_d1_store
from services.auto_route_service import AutoRouteService
from services.cascade_config import DEFAULT_CASCADES, MAX_CASCADES, normalize_config


class CascadeService:
    @staticmethod
    def _storage(connection):
        connection.execute("CREATE TABLE IF NOT EXISTS cascades (name TEXT PRIMARY KEY, config TEXT NOT NULL, updated_at TEXT NOT NULL)")
        for config in DEFAULT_CASCADES.values():
            connection.execute("INSERT OR IGNORE INTO cascades VALUES (?, ?, ?)",
                               (config["name"], json.dumps(config), config.get("updated_at", "")))
        connection.commit()

    @classmethod
    def list_routes(cls):
        if intelligence_d1_store.using_d1():
            return list({**copy.deepcopy(DEFAULT_CASCADES), **cascade_d1.stored_routes()}.values())
        with closing(AutoRouteService._connect()) as connection:
            cls._storage(connection)
            rows = connection.execute("SELECT config FROM cascades ORDER BY name LIMIT ?", (MAX_CASCADES,)).fetchall()
        return [normalize_config(json.loads(row["config"])) for row in rows]

    @classmethod
    def get_route(cls, name):
        return next((item for item in cls.list_routes() if item["name"] == name), None)

    @classmethod
    def save_route(cls, value, base_urls):
        config = normalize_config(value)
        models = [tier["model"] for tier in config["tiers"]]
        models += [config[field]["model"] for field in ("judge", "agreement") if config.get(field, {}).get("model")]
        for model in models:
            if model.startswith("auto:"):
                if AutoRouteService.get_route(model) is None and model != "auto:intelligence":
                    raise ValueError(f"Automatic route not found: {model}")
            elif model.startswith("free:"):
                if model not in {"free:text", "free:vision"}:
                    raise ValueError("Unsupported free judge pool")
            else:
                AutoRouteService.normalize_candidates([model], base_urls)
        config["updated_at"] = datetime.now(timezone.utc).isoformat()
        if intelligence_d1_store.using_d1():
            cascade_d1.save_route(config)
            return config
        with closing(AutoRouteService._connect()) as connection:
            cls._storage(connection)
            connection.execute("BEGIN IMMEDIATE")
            exists = connection.execute("SELECT 1 FROM cascades WHERE name=?", (config["name"],)).fetchone()
            if not exists and connection.execute("SELECT COUNT(*) FROM cascades").fetchone()[0] >= MAX_CASCADES:
                raise ValueError("Cascade storage limit reached")
            connection.execute("INSERT INTO cascades VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET config=excluded.config, updated_at=excluded.updated_at",
                               (config["name"], json.dumps(config), config["updated_at"]))
            connection.commit()
        return config
