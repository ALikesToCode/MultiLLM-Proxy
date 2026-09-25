"""Automatic routes persist in D1 and routing never disappears when D1 does."""

import pytest

from error_handlers import APIError
from services import auto_route_d1, intelligence_d1_store
from services.auto_route_service import DEFAULT_AUTO_ROUTES, AutoRouteService
from services.intelligence_d1_store import PrivateIntelligenceError

BASE_URLS = {"gguu": "https://gguu.example", "openai": "https://api.openai.com", "nanogpt": "https://nano-gpt.com/api"}


class FakeRoutes:
    """The Worker's fixed auto route operations, held in memory."""

    def __init__(self):
        self.rows, self.calls, self.down = {}, [], False

    def __call__(self, payload, *, endpoint):
        assert endpoint == "auto_routes"
        self.calls.append(payload["operation"])
        if self.down:
            raise PrivateIntelligenceError(503, "storage_unavailable")
        if payload["operation"] == "list":
            return {"version": 1, "routes": [{"route_id": route_id, **row} for route_id, row in sorted(self.rows.items())]}
        self.rows[payload["route_id"]] = {"candidates": payload["candidates"], "updated_at": payload["updated_at"]}
        return {"version": 1, "stored": True}


@pytest.fixture
def routes(monkeypatch, tmp_path):
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "d1")
    monkeypatch.setenv("MODEL_REGISTRY_DB_PATH", str(tmp_path / "registry.sqlite3"))
    fake = FakeRoutes()
    monkeypatch.setattr(intelligence_d1_store, "request_private_intelligence", fake)
    auto_route_d1.reset_cache()
    yield fake
    auto_route_d1.reset_cache()
    assert not (tmp_path / "registry.sqlite3").exists(), "D1 routes never create Container-local route storage"


def test_saved_routes_survive_a_container_restart_over_the_seeded_defaults(routes):
    assert {route.id for route in AutoRouteService.list_routes()} == set(DEFAULT_AUTO_ROUTES)
    AutoRouteService.save_route("auto:gpt-image-2.5", ["openai:gpt-image-2.5", "gguu:gpt-image-2.5"], BASE_URLS)
    auto_route_d1.reset_cache()
    route = AutoRouteService.get_route("auto:gpt-image-2.5")
    assert route.candidates == ("openai:gpt-image-2.5", "gguu:gpt-image-2.5")
    assert AutoRouteService.get_route("auto:glm-5.2").candidates == DEFAULT_AUTO_ROUTES["auto:glm-5.2"]


def test_reads_are_cached_and_an_outage_keeps_the_last_stored_routes(routes):
    AutoRouteService.save_route("auto:image-test", ["gguu:gpt-image-2.5"], BASE_URLS)
    auto_route_d1.reset_cache()
    for _ in range(3):
        assert AutoRouteService.get_route("auto:image-test").candidates == ("gguu:gpt-image-2.5",)
    assert routes.calls.count("list") == 1
    routes.down = True
    auto_route_d1._cache["expires"] = 0
    for _ in range(3):
        assert AutoRouteService.get_route("auto:image-test").candidates == ("gguu:gpt-image-2.5",)
    assert routes.calls.count("list") == 2, "a failed read is retried after a pause, not on every request"
    with pytest.raises(APIError) as caught:
        AutoRouteService.save_route("auto:image-test", ["openai:gpt-image-2.5"], BASE_URLS)
    assert caught.value.status_code == 503
    auto_route_d1.reset_cache()
    assert AutoRouteService.get_route("auto:gpt-image-2.5").candidates == DEFAULT_AUTO_ROUTES["auto:gpt-image-2.5"], \
        "without any stored copy the seeded defaults still route"
    assert AutoRouteService.get_route("auto:image-test") is None
