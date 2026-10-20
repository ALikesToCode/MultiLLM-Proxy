"""Paid-tier admission stays bound to the operator credential on every path."""

import json
import os
from unittest.mock import patch

import requests

from services.auto_route_service import AutoRoute
from tests.unified_api_test_case import UnifiedApiTestCase


class GeminiDataRouteTest(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        self.app.config["GEMINI_DATA_TIER"] = "paid"
        os.environ["GEMINI_API_KEY"] = "AIza-attested-synthetic"
        os.environ["OPENAI_API_KEY"] = "synthetic-operator"
        auth = self.app_module.AuthService
        with patch.object(auth, "get_current_user", return_value={"username": "admin", "is_admin": True}):
            created = auth.create_user("guarded", is_admin=True)
            auth.set_key_controls("guarded", {"official_only": True})
        self.key = created["api_key"]

    def endpoints(self):
        return [("/gemini/v1beta/models/gemini-test-model:generateContent", {"contents": [{"parts": [{"text": "Synthetic"}]}]}),
                ("/gemini/chat/completions", {"model": "gemini-test-model", "messages": [{"role": "user", "content": "Synthetic"}]}),
                ("/v1/chat/completions", {"model": "gemini:gemini-test-model", "messages": [{"role": "user", "content": "Synthetic"}]})]

    @staticmethod
    def native_response():
        response = requests.Response()
        response.status_code = 200
        response._content = json.dumps({"candidates": [{"content": {"parts": [{"text": "Synthetic"}]}, "finishReason": "STOP"}]}).encode()
        response.headers["Content-Type"] = "application/json"
        return response

    def test_raw_native_and_unified_refuse_caller_credentials_before_upstream(self):
        overrides = [("?key=AIza-caller-synthetic", {}), ("?%6bey=", {}),
                     ("", {"x-goog-api-key": "AIza-caller-synthetic"}),
                     ("", {"X-MultiLLM-Api-Key": self.key, "Authorization": "Bearer AIza-caller-synthetic"})]
        with patch.object(self.app_module.ProxyService, "_make_base_request") as send:
            for endpoint, payload in self.endpoints():
                for query, extra in overrides:
                    with self.subTest(endpoint=endpoint, override=query or next(iter(extra))):
                        response = self.client.post(endpoint + query, json=payload,
                            headers={"Authorization": f"Bearer {self.key}", **extra})
                        assert response.status_code == 403, response.json
                        assert response.json["error"] == "provider_credential_not_allowed"
            send.assert_not_called()

    def test_every_route_uses_only_the_attested_operator_key(self):
        with patch.object(self.app_module.ProxyService, "_make_base_request", side_effect=lambda **_: self.native_response()) as send:
            for endpoint, payload in self.endpoints():
                with self.subTest(endpoint=endpoint):
                    response = self.client.post(endpoint, json=payload, headers={"Authorization": f"Bearer {self.key}"})
                    assert response.status_code == 200, response.json
                    headers = send.call_args.kwargs["headers"]
                    assert headers["x-goog-api-key"] == "AIza-attested-synthetic"
                    assert not any(name.lower() == "authorization" for name in headers)

    def test_missing_attested_binding_never_uses_cached_or_alias_credentials(self):
        os.environ.pop("GEMINI_API_KEY")
        with patch.object(self.app_module.AuthService, "get_api_key", return_value="AIza-unattested-synthetic"), \
                patch.object(self.app_module.ProxyService, "_make_base_request") as send:
            for endpoint, payload in self.endpoints():
                with self.subTest(endpoint=endpoint):
                    response = self.client.post(endpoint, json=payload, headers={"Authorization": f"Bearer {self.key}"})
                    assert response.status_code == 503, response.json
                    assert response.json["error"] == "attested_credential_unavailable"
            send.assert_not_called()

    def test_automatic_fallback_refuses_overrides_and_missing_attestation(self):
        from services.auto_route_service import AutoRouteService
        route = AutoRoute("auto:attested", ("openai:first", "gemini:gemini-test-model"), "synthetic")
        calls = []
        def send(**kwargs):
            calls.append(kwargs)
            assert kwargs["api_provider"] == "openai"
            response = requests.Response()
            response.status_code = 429
            response._content = b'{"error":{"message":"Synthetic limit"}}'
            response.headers["Content-Type"] = "application/json"
            return response
        with patch.object(AutoRouteService, "get_route", side_effect=lambda name: route if name == route.id else None), \
                patch.object(self.app_module.ProxyService, "_make_base_request", side_effect=send):
            for query, missing in [("?key=AIza-caller-synthetic", False), ("", True)]:
                with self.subTest(missing=missing):
                    if missing:
                        os.environ.pop("GEMINI_API_KEY")
                    calls.clear()
                    response = self.client.post("/v1/chat/completions" + query,
                        json={"model": route.id, "messages": [{"role": "user", "content": "Synthetic"}]},
                        headers={"Authorization": f"Bearer {self.key}"})
                    assert response.status_code >= 400, response.json
                    assert len(calls) == 1, (response.status_code, response.json)


def test_transport_boundary_blocks_overrides_even_on_forced_raw_dispatch(monkeypatch):
    import pytest
    from flask import Flask, g
    from error_handlers import APIError
    from services.proxy_service import ProxyService

    monkeypatch.setenv("GEMINI_API_KEY", "AIza-attested-synthetic")
    app = Flask(__name__)
    app.config["GEMINI_DATA_TIER"] = "paid"
    url = "https://provider.example/v1beta/models/example:generateContent"
    overrides = [(url, {"key": "AIza-caller-synthetic"}, {}),
                 (url + "?key=AIza-caller-synthetic", {}, {}),
                 (url, {}, {"x-goog-api-key": "AIza-caller-synthetic"}),
                 (url, {}, {"authorization": "Bearer AIza-caller-synthetic"})]
    with app.test_request_context(headers={"Authorization": "Bearer synthetic-gateway"}):
        g.authenticated_user = {"official_only": True}
        with patch.object(ProxyService, "_make_base_request") as send:
            for force_raw in (False, True):
                for target, params, headers in overrides:
                    with pytest.raises(APIError) as error:
                        ProxyService.make_request("POST", target, headers, params, b"{}", "gemini",
                                                  use_cache=False, force_raw_passthrough=force_raw)
                    assert error.value.status_code == 403
            send.assert_not_called()
