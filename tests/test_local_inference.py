"""Explicit local endpoints reuse the managed OpenAI-compatible transport."""
import importlib
import json
import os
from unittest.mock import patch

import pytest

from tests.unified_api_test_case import UnifiedApiTestCase

URL_KEYS = {
    "ollama": "OLLAMA_BASE_URL", "vllm": "VLLM_BASE_URL",
    "lmstudio": "LM_STUDIO_BASE_URL", "llamacpp": "LLAMA_CPP_BASE_URL",
    "sglang": "SGLANG_BASE_URL",
}
KEY_KEYS = {"ollama": "OLLAMA_API_KEY", "vllm": "VLLM_API_KEY",
            "lmstudio": "LM_STUDIO_API_KEY", "llamacpp": "LLAMA_CPP_API_KEY",
            "sglang": "SGLANG_API_KEY"}


@pytest.fixture
def isolated(monkeypatch, tmp_path):
    import config
    import env_loader
    monkeypatch.setattr(config, "load_runtime_env", lambda: None)
    monkeypatch.setattr(env_loader, "load_runtime_env", lambda: None)
    for name in (*URL_KEYS.values(), *KEY_KEYS.values(),
                 "LMSTUDIO_API_KEY", "LLAMACPP_API_KEY"):
        monkeypatch.setenv(name, "")
    monkeypatch.setenv("MODEL_REGISTRY_DB_PATH", str(tmp_path / "models.sqlite3"))
    monkeypatch.setenv("CONTROL_PLANE_DATABASE_URL", "")
    monkeypatch.setenv("CONTROL_STATE_BACKEND", "local")
    monkeypatch.setenv("MODEL_PRECISION_PREFERENCE", "")
    from services.auth_service import AuthService
    from services.credential_pool import CredentialPool
    monkeypatch.setattr(AuthService, "_api_keys", {})
    monkeypatch.setattr(CredentialPool, "pooled", lambda provider: False)
    return importlib.import_module("providers.local_inference")


@pytest.mark.parametrize("provider", URL_KEYS)
def test_only_explicit_urls_register(provider, isolated, monkeypatch):
    from providers.registry import build_default_registry
    assert isolated.local_inference_base_urls() == {}
    monkeypatch.setenv(URL_KEYS[provider], "http://127.0.0.1:8000/v1/")
    urls = isolated.local_inference_base_urls()
    assert urls == {provider: "http://127.0.0.1:8000/v1"}
    adapter = build_default_registry(urls)[provider]
    assert adapter.chat_completions_url() == "http://127.0.0.1:8000/v1/chat/completions"
    assert adapter.capabilities().supports_chat
    assert not adapter.capabilities().supports_tools
    assert not adapter.capabilities().supports_images


@pytest.mark.parametrize("value,expected", [
    ("http://localhost:11434", "http://localhost:11434/v1"),
    ("http://10.1.2.3:8000/v1/", "http://10.1.2.3:8000/v1"),
    ("http://172.16.0.1/v1", "http://172.16.0.1/v1"),
    ("http://192.168.1.3/v1", "http://192.168.1.3/v1"),
    ("http://[::1]:8080/v1", "http://[::1]:8080/v1"),
    ("http://[fd00::1]/v1", "http://[fd00::1]/v1"),
    ("https://inference.example/serve/v1/", "https://inference.example/serve/v1"),
])
def test_v1_normalization_and_private_http(value, expected, isolated):
    assert isolated.normalize_local_base_url(value) == expected


@pytest.mark.parametrize("value", [
    "http://public.example/v1", "http://8.8.8.8/v1", "http://169.254.169.254/v1",
    "http://0.0.0.0/v1", "http://[::]/v1", "http://224.0.0.1/v1",
    "http://127.0.0.1:0/v1", "http://localhost:99999/v1",
    "https://user:secret@inference.example/v1", "file:///v1", "/v1",
    "http://localhost/api/chat", "http://localhost/v1?key=secret",
    "http://localhost/v1#fragment", "http://localhost/a/../v1",
    "http://localhost/%2e%2e/v1", "http://localhost\\evil/v1",
    "http://localhost/v1\n", "https://bad host/v1",
])
def test_malformed_origins_disable_without_logging_values(value, isolated, monkeypatch, caplog):
    isolated._invalid_settings_logged.clear()
    monkeypatch.setenv("OLLAMA_BASE_URL", value)
    assert isolated.local_inference_base_urls() == {}
    assert isolated.local_inference_base_urls() == {}
    assert len(caplog.records) == 1
    assert "OLLAMA_BASE_URL" in caplog.text
    assert value not in caplog.text


def test_disabled_configuration_and_adapter_output_are_unchanged(isolated, monkeypatch):
    from providers.base import CanonicalRequest
    from providers.registry import build_default_registry
    from config import Config
    with patch("env_loader.load_runtime_env"), patch("config.load_runtime_env"):
        module = importlib.reload(importlib.import_module("config"))
    assert not set(URL_KEYS).intersection(module.Config.API_BASE_URLS)
    original = {"openai": "https://api.openai.com"}
    registry = build_default_registry(original)
    assert set(registry) == {"openai"}
    payload = {"model": "gpt-4.1", "messages": [], "temperature": 0.4}
    request = registry["openai"].prepare_request(CanonicalRequest("openai", raw=payload))
    assert request.data == json.dumps(payload).encode()
    assert request.url == "https://api.openai.com/v1/chat/completions"
    monkeypatch.setattr(Config, "API_BASE_URLS", original)


@pytest.mark.parametrize("provider", URL_KEYS)
def test_private_key_mapping_and_optional_auth(provider, isolated, monkeypatch):
    from services.auth_service import AuthService
    monkeypatch.setenv(URL_KEYS[provider], "http://localhost:8000/v1")
    urls = isolated.local_inference_base_urls()
    assert AuthService.get_api_key(provider) is None
    assert not AuthService.provider_requires_api_key(provider, urls)
    assert AuthService.provider_requires_api_key(provider, {})
    assert AuthService.provider_requires_api_key("openai", urls)
    assert AuthService.provider_credential_env_names(provider)[0] == KEY_KEYS[provider]
    monkeypatch.setenv(KEY_KEYS[provider], "synthetic-local-key")
    assert AuthService.get_api_key(provider) == "synthetic-local-key"
    monkeypatch.setenv(KEY_KEYS[provider], "your-local-api-key")
    assert AuthService.get_api_key(provider) is None
    monkeypatch.setenv(URL_KEYS[provider], "")
    assert AuthService.get_api_key(provider) is None


def test_catalog_refresh_is_explicit_and_keyless(isolated, monkeypatch):
    from services.auth_service import AuthService
    from services.provider_catalog_service import ProviderCatalogService
    from services.proxy_service import ProxyService
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
    response = UnifiedApiTestCase._chat_response()
    response._content = json.dumps({"data": [{"id": "model:latest"}]}).encode()
    with patch.object(ProxyService, "make_request", return_value=response) as transport:
        results = ProviderCatalogService.refresh_configured(
            isolated.local_inference_base_urls(), AuthService, ProxyService)
    assert results == [{"provider": "ollama", "status": "updated", "truncated": False,
                        "model_count": 1}]
    assert transport.call_count == 1
    kwargs = transport.call_args.kwargs
    assert kwargs["url"] == "http://localhost:11434/v1/models"
    assert "Authorization" not in kwargs["headers"]
    assert kwargs["force_raw_passthrough"]
    assert [model.model_id for model in ProviderCatalogService.list_models()] == ["model:latest"]
    monkeypatch.setenv("OLLAMA_BASE_URL", "")
    assert ProviderCatalogService.list_models() == []
    with patch.object(ProxyService, "make_request") as transport:
        assert ProviderCatalogService.refresh_configured({}, AuthService, ProxyService) == []
    transport.assert_not_called()


def test_catalog_proxy_paths_match_normalized_v1_base(isolated):
    from services.provider_catalog_service import PROVIDER_CATALOG_SPECS
    for provider in URL_KEYS:
        spec = PROVIDER_CATALOG_SPECS[provider]
        assert spec.upstream_path == "models"
        assert spec.proxy_path == f"/{provider}/models"


def test_catalog_keeps_only_declarations_with_provenance(isolated, monkeypatch):
    from services.provider_catalog_service import ProviderCatalogService
    monkeypatch.setenv("MODEL_PRECISION_PREFERENCE", '["fp16"]')
    records = ProviderCatalogService.extract_models("vllm", {"data": [
        {"id": "some-int4", "supports_tools": True, "precision": "fp16"},
        {"id": "vision-int4", "api_key": "synthetic-secret"},
    ]})
    known, unknown = [record.metadata for record in records]
    assert known["supports_tools"] is True
    assert known["precision"] == "fp16"
    assert known["metadata_provenance"]["supports_tools"] == "provider_catalog:vllm"
    assert known["precision_source"] == "provider_catalog:vllm"
    assert unknown["precision"] == "unknown"
    assert "supports_vision" not in unknown
    assert "api_key" not in unknown


def test_explicit_models_resolve_without_discovery(isolated, monkeypatch):
    from services.model_registry import ModelRegistry
    monkeypatch.setenv("VLLM_BASE_URL", "http://localhost:8000/v1")
    assert ModelRegistry.get_model("vllm:org/unlisted:latest", isolated.local_inference_base_urls())
    assert ModelRegistry.get_model("vllm:org/unlisted:latest", {}) is None


def test_config_registers_all_five_urls_only_when_set(isolated, monkeypatch):
    config = importlib.import_module("config")
    original = config.Config
    for name in URL_KEYS.values():
        monkeypatch.setenv(name, "http://127.0.0.1:8000/v1/")
    with patch("env_loader.load_runtime_env", lambda: None):
        importlib.reload(config)
    try:
        assert set(URL_KEYS).issubset(config.Config.API_BASE_URLS)
        assert all(config.Config.API_BASE_URLS[name] == "http://127.0.0.1:8000/v1"
                   for name in URL_KEYS)
    finally:
        config.Config = original


def test_invalid_direct_base_url_never_dispatches_catalog(isolated):
    from providers.registry import build_default_registry
    from services.provider_catalog_service import ProviderCatalogService
    from services.auth_service import AuthService
    from services.proxy_service import ProxyService
    urls = {"ollama": "http://public.example/v1"}
    assert build_default_registry(urls) == {}
    with patch.object(ProxyService, "make_request") as transport:
        assert ProviderCatalogService.refresh_configured(urls, AuthService, ProxyService) == []
    transport.assert_not_called()


def test_failed_catalog_retains_real_last_good_result(isolated, monkeypatch):
    from services.provider_catalog_service import ProviderCatalogService
    from services.auth_service import AuthService
    from services.proxy_service import ProxyService
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
    ProviderCatalogService.replace_provider_models("ollama", ("already-loaded",))
    response = UnifiedApiTestCase._chat_response()
    response.status_code = 503
    response._content_consumed = True
    with patch.object(ProxyService, "make_request", return_value=response) as transport:
        results = ProviderCatalogService.refresh_configured(
            isolated.local_inference_base_urls(), AuthService, ProxyService)
    assert results[0]["status"] == "failed"
    assert results[0]["message"] == "Catalog request returned HTTP 503"
    assert transport.call_count == 1
    assert [model.model_id for model in ProviderCatalogService.list_models()] == ["already-loaded"]


class LocalInferenceRouteTest(UnifiedApiTestCase):
    def setUp(self):
        self.env_patch = patch.dict(os.environ, {**dict.fromkeys(URL_KEYS.values(), ""),
            **dict.fromkeys(KEY_KEYS.values(), ""), "OLLAMA_BASE_URL": "http://localhost:11434/v1",
            "OLLAMA_API_KEY": "synthetic-local-key", "PROVIDER_CATALOG_AUTO_REFRESH": "false"})
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)
        self.loader_patch = patch("env_loader.load_runtime_env", lambda: None)
        self.loader_patch.start()
        self.addCleanup(self.loader_patch.stop)
        config_patch = patch("config.load_runtime_env", lambda: None)
        config_patch.start()
        self.addCleanup(config_patch.stop)
        super().setUp()
        self.app.config["API_BASE_URLS"] = {**self.app.config["API_BASE_URLS"],
            "ollama": "http://localhost:11434/v1"}

    def test_chat_uses_configured_v1_and_original_model(self):
        with patch.object(self.app_module.ProxyService, "make_request",
                          return_value=self._chat_response()) as transport:
            response = self.client.post("/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json={"model": "ollama:model:latest", "messages": [{"role": "user", "content": "hello"}]})
        self.assertEqual(response.status_code, 200, response.json)
        self.assertEqual(transport.call_count, 1)
        kwargs = transport.call_args.kwargs
        self.assertEqual(kwargs["url"], "http://localhost:11434/v1/chat/completions")
        self.assertEqual(json.loads(kwargs["data"])["model"], "model:latest")
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer synthetic-local-key")

    def test_responses_translates_to_chat_and_rejects_native_controls(self):
        with patch.object(self.app_module.ProxyService, "make_request",
                          return_value=self._chat_response()) as transport:
            response = self.client.post("/v1/responses",
                headers={"Authorization": "Bearer admin-test-key"},
                json={"model": "ollama:model:latest", "input": "hello"})
        self.assertEqual(response.status_code, 200, response.json)
        self.assertEqual(transport.call_count, 1)
        self.assertEqual(transport.call_args.kwargs["url"], "http://localhost:11434/v1/chat/completions")
        with patch.object(self.app_module.ProxyService, "make_request") as transport:
            response = self.client.post("/v1/responses",
                headers={"Authorization": "Bearer admin-test-key"},
                json={"model": "ollama:model:latest", "input": "hello", "previous_response_id": "resp-native"})
        self.assertEqual(response.status_code, 400, response.json)
        transport.assert_not_called()

    def test_models_expose_only_configured_catalog(self):
        service = importlib.import_module("services.provider_catalog_service").ProviderCatalogService
        service.replace_provider_models("ollama", service.extract_models("ollama", {"data": [{"id": "model:latest"}]}))
        response = self.client.get("/v1/models", headers={"Authorization": "Bearer admin-test-key"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("ollama:model:latest", {row["id"] for row in response.json["data"]})

    def test_disabled_provider_is_rejected_before_dispatch(self):
        self.app.config["API_BASE_URLS"].pop("ollama")
        with patch.object(self.app_module.ProxyService, "make_request") as transport:
            response = self.client.post("/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json={"model": "ollama:model:latest", "messages": []})
        self.assertEqual(response.status_code, 400)
        transport.assert_not_called()

    def test_provider_failure_is_not_retried_or_replaced(self):
        upstream = self._chat_response()
        upstream.status_code = 503
        upstream._content = b'{"error":{"message":"local server unavailable"}}'
        with patch.object(self.app_module.ProxyService, "make_request",
                          return_value=upstream) as transport:
            response = self.client.post("/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json={"model": "ollama:model:latest", "messages": []})
        self.assertEqual(response.status_code, 503)
        self.assertEqual(transport.call_count, 1)

    def test_all_five_providers_use_managed_chat(self):
        for provider in URL_KEYS:
            with self.subTest(provider=provider):
                self.app.config["API_BASE_URLS"][provider] = "http://localhost:8000/v1"
                with patch.dict(os.environ, {URL_KEYS[provider]: "http://localhost:8000/v1",
                                            KEY_KEYS[provider]: "synthetic-local-key"}), patch.object(
                        self.app_module.ProxyService, "make_request",
                        return_value=self._chat_response()) as transport:
                    response = self.client.post("/v1/chat/completions",
                        headers={"Authorization": "Bearer admin-test-key"},
                        json={"model": f"{provider}:org/model:latest", "messages": []})
                self.assertEqual(response.status_code, 200, response.json)
                self.assertEqual(transport.call_count, 1)
                self.assertEqual(transport.call_args.kwargs["url"],
                                 "http://localhost:8000/v1/chat/completions")
                self.assertEqual(json.loads(transport.call_args.kwargs["data"])["model"],
                                 "org/model:latest")

    def test_keyless_local_provider_dispatches_without_authorization(self):
        auth = self.app_module.AuthService
        self.assertFalse(auth.provider_requires_api_key("ollama", self.app.config["API_BASE_URLS"]))
        for path, payload in (
            ("/v1/chat/completions", {"model": "ollama:model:latest", "messages": []}),
            ("/v1/responses", {"model": "ollama:model:latest", "input": "hello"}),
        ):
            with self.subTest(path=path), patch.dict(os.environ, {"OLLAMA_API_KEY": ""}), patch.object(
                    self.app_module.ProxyService, "make_request",
                    return_value=self._chat_response()) as transport:
                response = self.client.post(path,
                    headers={"Authorization": "Bearer admin-test-key"}, json=payload)
            self.assertEqual(response.status_code, 200, response.json)
            self.assertEqual(transport.call_count, 1)
            self.assertNotIn("Authorization", transport.call_args.kwargs["headers"])

    def test_keyed_provider_without_key_still_refuses(self):
        credentials = importlib.import_module("routes.provider_credentials")
        auth = self.app_module.AuthService
        with patch.object(auth, "get_api_key", return_value=None):
            with self.assertRaises(credentials.AutoRouteCandidateUnavailable):
                credentials._provider_token(self.app, auth, self.app_module.ProxyService, "openai")
