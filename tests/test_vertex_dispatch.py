"""Restricted Vertex calls refresh only the current operator credential binding."""
import json
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from flask import Flask, g

from error_handlers import APIError
from services.dispatch_network import network_admitted
from services.dispatch_policy import envelope
from services.provider_dispatch import provider_http
from tests.unified_api_test_case import UnifiedApiTestCase

URL = "https://us-central1-aiplatform.googleapis.com/v1/projects/synthetic/locations/us-central1/endpoints/openapi/chat/completions"


def binding(name="synthetic-a"):
    return json.dumps({"type": "service_account", "client_email": name + "@synthetic.iam.gserviceaccount.com",
                      "token_uri": "https://oauth2.googleapis.com/token"})


@pytest.fixture
def vertex(monkeypatch):
    app = Flask(__name__)
    app.config["API_BASE_URLS"] = {"googleai": URL}
    monkeypatch.setattr("services.auth_service.AuthService._load_user_by_username", lambda _: {"username": "synthetic", "data_policy": envelope({
        "official_only": 1, "forced_provider_preferences": None})})
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS_JSON", raising=False)
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.setenv("GOOGLEAI_API_KEY", "synthetic-unattested-key")
    with app.test_request_context():
        g.authenticated_user = {"username": "synthetic"}
        yield


def credentials(token="synthetic-current"):
    result = SimpleNamespace(token=token)
    def refresh(request):
        assert network_admitted()
    result.refresh = Mock(side_effect=refresh)
    return result


@pytest.mark.parametrize("source", ["json", "file"])
def test_current_service_account_binding_overrides_cached_token(vertex, monkeypatch, tmp_path, source):
    path = tmp_path / "operator.json"
    def set_binding(value):
        if source == "json":
            monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS_JSON", value)
        else:
            path.write_text(value)
            monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(path))
    send = Mock()
    current = credentials("synthetic-first")
    set_binding(binding())
    with patch("google.oauth2.service_account.Credentials.from_service_account_info", return_value=current) as build:
        provider_http("googleai", "POST", URL, transport=send, headers={"Authorization": "Bearer synthetic-cached"})
        assert send.call_args.kwargs["headers"]["Authorization"] == "Bearer synthetic-first"
        current.token = "synthetic-second"
        set_binding(binding("synthetic-b"))
        provider_http("googleai", "POST", URL, transport=send, headers={"Authorization": "Bearer synthetic-first"})
        assert send.call_args.kwargs["headers"]["Authorization"] == "Bearer synthetic-second"
        assert build.call_args.args[0]["client_email"].startswith("synthetic-b@")
        assert current.refresh.call_count == 2


@pytest.mark.parametrize("mode", ["missing", "malformed", "missing-file", "changed-during-refresh", "untrusted-token-origin"])
def test_unverified_or_changed_service_account_cannot_dispatch(vertex, monkeypatch, mode):
    send = Mock()
    monkeypatch.setattr("services.provider_credentials.shutil.which", lambda _: None)
    if mode == "malformed":
        monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS_JSON", "{}")
    elif mode == "missing-file":
        monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/nonexistent/synthetic.json")
    elif mode == "untrusted-token-origin":
        monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS_JSON", binding().replace("oauth2.googleapis.com", "unrelated.example"))
    elif mode == "changed-during-refresh":
        monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS_JSON", binding())
    current = credentials()
    if mode == "changed-during-refresh":
        current.refresh.side_effect = lambda _: monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS_JSON", binding("synthetic-b"))
    with patch("google.oauth2.service_account.Credentials.from_service_account_info", return_value=current):
        with pytest.raises(APIError) as error:
            provider_http("googleai", "POST", URL, transport=send, headers={"Authorization": "Bearer synthetic-cached"})
    assert error.value.status_code == 503
    send.assert_not_called()


@pytest.mark.parametrize("changed", [False, True])
def test_gcloud_binds_a_fresh_token_to_the_current_operator_account(vertex, monkeypatch, changed):
    monkeypatch.setattr("services.provider_credentials.shutil.which", lambda _: "/trusted/gcloud")
    answers = ["synthetic-a", "synthetic-current", "synthetic-b" if changed else "synthetic-a"]
    run = Mock(side_effect=lambda *args, **kwargs: SimpleNamespace(stdout=answers.pop(0)))
    monkeypatch.setattr("services.provider_credentials.subprocess.run", run)
    send = Mock()
    if changed:
        with pytest.raises(APIError):
            provider_http("googleai", "POST", URL, transport=send)
        send.assert_not_called()
    else:
        provider_http("googleai", "POST", URL, transport=send)
        assert send.call_args.kwargs["headers"]["Authorization"] == "Bearer synthetic-current"
    assert run.call_args_list[1].args[0] == ["/trusted/gcloud", "auth", "print-access-token", "synthetic-a", "--quiet"]


class RegisteredVertexDispatchTest(UnifiedApiTestCase):
    def test_restricted_native_vertex_route_uses_current_service_account(self):
        from tests.test_media_generation import upstream
        auth = self.app_module.AuthService
        with patch.object(auth, "get_current_user", return_value={"username": "admin", "is_admin": True}):
            created = auth.create_user("synthetic-vertex", is_admin=True)
            auth.set_key_controls("synthetic-vertex", {"official_only": True})
        self.app.config["API_BASE_URLS"]["googleai"] = URL.rsplit("/", 1)[0]
        with patch.dict("os.environ", {"GOOGLE_APPLICATION_CREDENTIALS_JSON": binding(), "PROJECT_ID": "synthetic",
                "LOCATION": "us-central1", "GOOGLE_ENDPOINT": "us-central1-aiplatform.googleapis.com"}), \
                patch("google.oauth2.service_account.Credentials.from_service_account_info", return_value=credentials()), \
                patch.object(auth, "get_google_token", return_value="synthetic-cached"), \
                patch("requests.sessions.Session.request", return_value=upstream(200,
                    {"choices": [{"message": {"role": "assistant", "content": "Synthetic"}}]})) as send:
            result = self.client.post("/googleai/v1/chat/completions", headers={"Authorization": "Bearer " + created["api_key"]},
                json={"model": "synthetic", "messages": [{"role": "user", "content": "Synthetic"}]})
        assert result.status_code == 200, result.json
        assert send.call_args.kwargs["headers"]["Authorization"] == "Bearer synthetic-current"
