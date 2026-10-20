"""All provider adapters share current durable policy and credential admission."""
import json
import os
from unittest.mock import Mock, patch

import pytest
from flask import Flask, g

from error_handlers import APIError
from services.dispatch_policy import envelope, verify
from services.provider_dispatch import capture_dispatch, provider_http
from services.user_store import _row
from tests.unified_api_test_case import UnifiedApiTestCase


def account(**controls):
    return {"username": "synthetic-user", "api_key_prefix": "synthetic", "data_policy": envelope({
        "official_only": None, "forced_provider_preferences": None, **controls})}


@pytest.mark.parametrize("policy", [None, {}, {"version": 0, "official_only": None, "forced_provider_preferences": None},
    {"version": 1, "official_only": None}, {"version": 1, "forced_provider_preferences": None},
    {"version": 1, "official_only": "false", "forced_provider_preferences": None}])
def test_missing_old_or_malformed_policy_never_authorizes(policy, monkeypatch):
    monkeypatch.setattr("services.auth_service.AuthService._load_user_by_username", lambda _: {**account(), "data_policy": policy})
    send = Mock()
    with Flask(__name__).test_request_context():
        g.authenticated_user = {"username": "synthetic-user", "is_admin": True}
        with pytest.raises(APIError) as error:
            provider_http("openai", "POST", "https://provider.example/v1/chat/completions", transport=send)
    assert error.value.status_code == 503
    send.assert_not_called()


@pytest.mark.parametrize("provider", ["opencode", "free", "linkapi", "knowledge", "unknown"])
def test_every_adapter_uses_current_controls_instead_of_cached_principal(provider, monkeypatch):
    monkeypatch.setattr("services.auth_service.AuthService._load_user_by_username", lambda _: account(official_only=1))
    send = Mock()
    with Flask(__name__).test_request_context():
        g.authenticated_user = account()
        with pytest.raises(APIError) as error:
            provider_http(provider, "POST", "https://provider.example/generate", transport=send)
    assert error.value.status_code == 403
    send.assert_not_called()


def test_deferred_dispatch_captures_identity_but_rereads_controls(monkeypatch):
    current = account()
    monkeypatch.setattr("services.auth_service.AuthService._load_user_by_username", lambda _: current)
    send = Mock()
    with Flask(__name__).test_request_context():
        g.authenticated_user = current
        deferred = capture_dispatch(lambda: provider_http("linkapi", "POST", "https://provider.example/generate", transport=send))
    current = account(official_only=1)
    with pytest.raises(APIError) as error:
        deferred()
    assert error.value.status_code == 403
    send.assert_not_called()


def test_forced_preferences_merge_at_actual_http_boundary(monkeypatch):
    monkeypatch.setattr("services.auth_service.AuthService._load_user_by_username", lambda _: account(forced_provider_preferences={"data_collection": "deny"}))
    monkeypatch.setenv("OPENROUTER_API_KEY", "synthetic-operator")
    send = Mock()
    with Flask(__name__).test_request_context():
        g.authenticated_user = account()
        provider_http("openrouter", "POST", "https://provider.example/generate", transport=send,
            json={"provider": {"data_collection": "allow", "sort": "price"}}, headers={"Authorization": "Bearer synthetic-cached"})
    assert send.call_args.kwargs["json"]["provider"] == {"data_collection": "deny", "sort": "price"}
    assert send.call_args.kwargs["headers"]["Authorization"] == "Bearer synthetic-operator"
    assert send.call_args.kwargs["allow_redirects"] is False


@pytest.mark.parametrize("policy", [None, {}, {"version": 2, "official_only": None, "forced_provider_preferences": None}])
def test_mixed_version_rpc_rows_fail_closed(policy):
    from services.user_store import USER_FIELDS
    row = dict.fromkeys(USER_FIELDS)
    row.update(username="synthetic-user", api_key_hash="synthetic-hash", api_key_prefix="synthetic", scopes="chat", is_admin=0,
        created_at="2026-10-20T00:00:00Z")
    if policy is not None:
        row["data_policy"] = policy
    with pytest.raises(APIError):
        _row(row)
    row["data_policy"] = envelope(row)
    assert _row(row)["official_only"] is None
    assert verify(row["data_policy"])["version"] == 1


class ProviderDispatchRouteTest(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        self.app.config["GEMINI_DATA_TIER"] = "paid"
        os.environ["GEMINI_API_KEY"] = "AIza-attested-synthetic"
        auth = self.app_module.AuthService
        with patch.object(auth, "get_current_user", return_value={"username": "admin", "is_admin": True}):
            created = auth.create_user("synthetic-video", is_admin=True)
            auth.set_key_controls("synthetic-video", {"official_only": True})
        self.headers = {"Authorization": "Bearer " + created["api_key"]}

    def test_gemini_video_creation_reselects_attested_credential(self):
        from tests.test_media_generation import upstream
        with patch.object(self.app_module.AuthService, "get_api_key", return_value="AIza-stale-synthetic"), \
                patch("services.provider_dispatch.requests.request", return_value=upstream(200, {"name": "operations/synthetic"})) as send:
            response = self.client.post("/v1/videos", headers=self.headers,
                json={"model": "gemini:veo-3.1-generate-preview", "prompt": "Synthetic landscape"})
        assert response.status_code == 200, response.json
        assert send.call_args.kwargs["headers"]["x-goog-api-key"] == "AIza-attested-synthetic"

    def test_video_overrides_and_missing_attestation_do_not_dispatch(self):
        for query, extra, missing in [("?key=caller-synthetic", {}, False), ("", {"x-goog-api-key": "caller-synthetic"}, False), ("", {}, True)]:
            if missing:
                os.environ.pop("GEMINI_API_KEY")
            with patch.object(self.app_module.AuthService, "get_api_key", return_value="AIza-stale-synthetic"), \
                    patch("services.provider_dispatch.requests.request") as send:
                response = self.client.post("/v1/videos" + query, headers={**self.headers, **extra},
                    json={"model": "gemini:veo-3.1-generate-preview", "prompt": "Synthetic landscape"})
            assert response.status_code == (503 if missing else 403), response.json
            send.assert_not_called()

    def test_bootstrap_recovery_does_not_grant_provider_authority(self):
        from services.auth_service import AuthService
        AuthService._forget_verified_keys()
        with patch.object(AuthService, "_load_user_by_username", side_effect=APIError("Synthetic store unavailable", 503)), \
                patch("requests.sessions.Session.request") as send:
            response = self.client.post("/v1/chat/completions", headers={"Authorization": "Bearer admin-test-key"},
                json={"model": "openai:synthetic", "messages": [{"role": "user", "content": "Synthetic"}]})
        assert response.status_code == 503, response.json
        send.assert_not_called()


@pytest.mark.parametrize("response", [{"version": 1, "principal": None}, {"version": 0, "principal": account()},
    {"version": 1, "principal": {"username": "integration:synthetic"}},
    {"version": 1, "principal": {"username": "integration:synthetic", "data_policy": {"version": 1, "official_only": None}}}])
def test_integration_dispatch_rejects_old_or_incomplete_worker_authority(response, monkeypatch):
    monkeypatch.setattr("services.intelligence_d1_store.request_private_intelligence", lambda *args, **kwargs: response)
    send = Mock()
    with pytest.raises(APIError) as error:
        provider_http("openai", "POST", "https://provider.example/generate", reference={"username": "integration:synthetic"}, transport=send)
    assert error.value.status_code == 503
    send.assert_not_called()


@pytest.mark.parametrize("operation", ["poll", "content", "watch"])
def test_video_deferred_operations_recheck_current_policy_and_attestation(operation, monkeypatch):
    from services import video_generation
    from services.provider_dispatch import dispatch_as
    app = Flask(__name__)
    app.config["GEMINI_DATA_TIER"] = "paid"
    current = account(official_only=1)
    monkeypatch.setattr("services.auth_service.AuthService._load_user_by_username", lambda _: current)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    send = Mock()
    job = {"p": "gemini", "u": "operations/synthetic", "m": "veo-synthetic", "t": 1}
    def execute():
        if operation == "content":
            return video_generation.stream_content("https://provider.example/synthetic.mp4", {"x-goog-api-key": "synthetic-cached"}, provider="gemini")
        return video_generation.job_status(job, "synthetic-job", "synthetic-cached", "https://provider.example")
    with app.test_request_context():
        g.authenticated_user = current
        deferred = capture_dispatch(execute)
    with patch("services.provider_dispatch.requests.request", send), dispatch_as({"username": "synthetic-user"}):
        with pytest.raises(APIError) as error:
            deferred()
        assert error.value.status_code == 503
        monkeypatch.setenv("GEMINI_API_KEY", "synthetic-current")
        app.config["GEMINI_DATA_TIER"] = "free"
        with pytest.raises(APIError) as error:
            deferred()
        assert error.value.status_code == 403
    send.assert_not_called()
