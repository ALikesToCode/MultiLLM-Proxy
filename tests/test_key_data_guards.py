"""Data controls protect an app whose requests carry personal data."""

import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from flask import Flask, Response, g

from error_handlers import APIError
from services import key_controls, key_data_guards
from tests.unified_api_test_case import UnifiedApiTestCase


def test_controls_validate_storage_and_public_values():
    controls = key_controls.validate({"official_only": True,
                                      "forced_provider_preferences": {"data_collection": "deny", "zdr": True}})
    assert controls["official_only"] == 1
    restored = key_controls.from_storage(controls)
    assert key_controls.public(restored)["official_only"] is True
    assert key_controls.public(restored)["forced_provider_preferences"] == {"data_collection": "deny", "zdr": True}
    for payload in ({"official_only": "true"}, {"official_only": 1},
                    {"forced_provider_preferences": []}, {"forced_provider_preferences": "oops"},
                    {"forced_provider_preferences": {"data_collection": "invalid"}},
                    {"forced_provider_preferences": {"data_collection": []}},
                    {"forced_provider_preferences": {"only": ["x" * 5000]}}):
        with pytest.raises(APIError) as error:
            key_controls.validate(payload)
        assert error.value.status_code == 400
    with pytest.raises(APIError) as error:
        key_controls.from_storage({"official_only": 2})
    assert error.value.status_code == 503


def test_registry_classes_and_tiers_fail_closed():
    from config import Config
    from providers.registry import get_registry
    registry = get_registry(Config.API_BASE_URLS)
    for name, adapter in registry.items():
        assert adapter.data_class in {"official", "subscription", "reseller", "free"}, name
    assert key_data_guards.provider_data_class("openai") == "official"
    assert key_data_guards.provider_data_class("ce-unlisted") == "subscription"
    assert key_data_guards.provider_data_class("custom-relay") == "reseller"
    assert key_data_guards.provider_data_class("gemini", {}) == "free"
    assert key_data_guards.provider_data_class("gemini", {"GEMINI_DATA_TIER": "paid"}) == "official"
    assert key_data_guards.provider_data_class("gemini", {"GEMINI_DATA_TIER": "paid",
                                                              "FREE_ROUTE_FREE_TIER_PROVIDERS": "gemini"}) == "free"
    assert not key_controls.model_allowed({"official_only": True}, "free:text")
    assert key_controls.model_allowed({"official_only": True}, "auto:chat")


@pytest.mark.parametrize("caller,forced,expected", [
    ({"data_collection": "allow", "sort": "price"}, {"data_collection": "deny"},
     {"data_collection": "deny", "sort": "price"}),
    ({"data_collection": "deny"}, {"data_collection": "allow"}, {"data_collection": "deny"}),
    ({"max_price": {"prompt": 4, "completion": 2}}, {"max_price": {"prompt": 1}},
     {"max_price": {"prompt": 1, "completion": 2}}),
])
def test_preferences_cannot_be_weakened_at_transport(caller, forced, expected):
    app = Flask(__name__)
    with app.test_request_context():
        g.authenticated_user = {"forced_provider_preferences": forced}
        original = {"model": "example/model", "provider": caller}
        data = json.dumps(original).encode()
        guarded = key_data_guards.guard_request("openrouter", data)
        assert json.loads(guarded)["provider"] == expected
        assert json.loads(data) == original
        assert key_data_guards.guard_request("openai", data) == data


def test_auto_filters_candidates_before_dispatch_and_refuses_empty():
    from routes.auto_routes import dispatch_auto_route
    app = Flask(__name__)
    route = SimpleNamespace(id="auto:guarded", candidates=("opencode:example", "openai:example"), canary=None)
    calls = []
    with app.test_request_context(), patch("routes.auto_routes.AutoRouteService.get_route", return_value=route), \
            patch("routes.auto_routes.canary_traffic.prepare_request", return_value=None):
        g.authenticated_user = {"official_only": True}
        response = dispatch_auto_route({"model": route.id}, validate_candidate=lambda _: None,
            dispatch_candidate=lambda payload, model, decision: (calls.append(model) or Response("{}", mimetype="application/json")))
        assert response.status_code == 200
        assert calls == ["openai:example"]
        route.candidates = ("opencode:example",)
        with pytest.raises(APIError) as error:
            dispatch_auto_route({"model": route.id}, validate_candidate=lambda _: None,
                                dispatch_candidate=lambda *_: pytest.fail("No eligible provider"))
        assert error.value.status_code == 403
        assert error.value.payload["error"] == "provider_class_not_allowed"


def test_cascade_filters_tiers_and_nested_auto_without_dispatch():
    from routes.cascades import dispatch_cascade, validate_cascade_target
    app = Flask(__name__)
    config = {"name": "cascade:guarded", "tiers": [{"model": "opencode:example"}], "checks": ["complete"]}
    with app.test_request_context(), patch("routes.cascades.CascadeService.get_route", return_value=config):
        g.authenticated_user = {"official_only": True}
        with pytest.raises(APIError) as error:
            dispatch_cascade({"model": config["name"]}, lambda *_: pytest.fail("No eligible tier"))
        assert error.value.payload["error"] == "provider_class_not_allowed"
        config["tiers"] = [{"model": "auto:guarded"}]
        route = SimpleNamespace(id="auto:guarded", candidates=("opencode:example",))
        with patch("routes.unified.AutoRouteService.get_route", return_value=route):
            with pytest.raises(APIError) as error:
                validate_cascade_target(app, None, config["name"], None)
        assert error.value.status_code == 403


def test_cascade_uses_remaining_official_tier(monkeypatch):
    from tests.test_cascades import CONFIG, answer, run
    from services import request_accounting, usage_ledger
    app = Flask(__name__)
    monkeypatch.setattr(request_accounting, "begin", lambda **_: None)
    monkeypatch.setattr(usage_ledger.LEDGER, "record", lambda _: None)
    with app.test_request_context():
        g.authenticated_user = {"official_only": True}
        config = {**CONFIG, "tiers": [{"model": "opencode:example"}, {"model": "openai:example"}]}
        response, calls = run(config, [answer()])
        assert response.status_code == 200
        assert [body["model"] for body in calls] == ["openai:example"]


class KeyDataRouteTest(UnifiedApiTestCase):
    def key(self, **controls):
        auth = self.app_module.AuthService
        with patch.object(auth, "get_current_user", return_value={"username": "admin", "is_admin": True}):
            created = auth.create_user("guarded", is_admin=True)
            auth.set_key_controls("guarded", controls)
        return created["api_key"]

    def test_direct_classes_and_free_routes_refuse_before_transport(self):
        key = self.key(official_only=True)
        with patch("app.ProxyService.make_request") as transport:
            for endpoint, model in (("/v1/chat/completions", "opencode:glm-5.2"),
                                    ("/v1/chat/completions", "free:text"),
                                    ("/linkapi/v1/chat/completions", "example/model")):
                response = self.client.post(endpoint, json={"model": model, "messages": []},
                                            headers={"Authorization": f"Bearer {key}"})
                assert response.status_code == 403, response.get_json()
                assert response.get_json()["error"] == "provider_class_not_allowed"
            transport.assert_not_called()

    def test_transport_merges_forced_preferences_on_unified_and_raw_calls(self):
        key = self.key(forced_provider_preferences={"data_collection": "deny"})
        with patch.object(self.app_module.ProxyService, "_make_base_request", return_value=self._chat_response()) as upstream, \
                patch.object(self.app_module.AuthService, "get_api_key", return_value="synthetic-provider-key"):
            for endpoint, model in (("/v1/chat/completions", "openrouter:example/model"),
                                    ("/openrouter/chat/completions", "example/model")):
                response = self.client.post(endpoint, headers={"Authorization": f"Bearer {key}"},
                    json={"model": model, "messages": [{"role": "user", "content": "example"}],
                          "provider": {"data_collection": "allow", "sort": "price"}})
                assert response.status_code == 200, response.get_json()
                assert json.loads(upstream.call_args.kwargs["data"])["provider"] == {"data_collection": "deny", "sort": "price"}
