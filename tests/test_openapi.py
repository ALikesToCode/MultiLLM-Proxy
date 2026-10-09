"""Static contract, authenticated publication and runtime route coverage."""

import json
import re
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator

from tests.unified_api_test_case import UnifiedApiTestCase

ROOT = Path(__file__).resolve().parents[1]
ADMIN = {"Authorization": "Bearer admin-test-key"}


def test_snapshot_is_deterministic_and_independent():
    from services.openapi_spec import build_openapi_spec, render_openapi_spec

    expected = (ROOT / "docs/openapi.json").read_text(encoding="utf-8")
    assert render_openapi_spec() == expected == render_openapi_spec()
    first = build_openapi_spec()
    first["paths"].clear()
    assert build_openapi_spec()["paths"]
    assert json.loads(expected) == build_openapi_spec()


def test_contract_is_bounded_and_has_no_private_configuration():
    from services.openapi_spec import build_openapi_spec

    spec = build_openapi_spec()
    assert spec["openapi"] == "3.1.0"
    assert spec["servers"] == [{"url": "/"}]
    assert spec["security"] == [{"BearerAuth": []}, {"ProxyKeyAuth": []}]
    assert spec["components"]["securitySchemes"]["BearerAuth"] == {
        "type": "http", "scheme": "bearer",
    }
    encoded = json.dumps(spec)
    for private in ("ADMIN_API_KEY", "OPENCODE_GO_API_KEY", "api.navy", "container.internal",
                    "https://", "/admin/", "/v1/prompt-templates", "/v1/batches", "native_token_count"):
        assert private not in encoded
    assert not any("credentials" in path or "knowledge" in path for path in spec["paths"])
    assert spec["x-multillm-runtime"]["catalog_refresh"] is False


def test_protocol_media_types_and_error_schemas():
    from services.openapi_spec import build_openapi_spec

    spec = build_openapi_spec()
    schemas = spec["components"]["schemas"]
    for schema in schemas.values():
        Draft202012Validator.check_schema(schema)
    for name, body in (
        ("GatewayError", {"error": "Authentication required", "message": "Use bearer auth"}),
        ("OpenAIError", {"error": {"message": "Invalid request", "type": "invalid_request_error",
                                  "code": None, "param": None}}),
        ("AnthropicError", {"type": "error", "error": {"type": "api_error", "message": "Unavailable"}}),
    ):
        Draft202012Validator(schemas[name]).validate(body)
    for path in ("/v1/chat/completions", "/v1/responses", "/v1/messages"):
        operation = spec["paths"][path]["post"]
        content = operation["responses"]["200"]["content"]
        assert set(content) == {"application/json", "text/event-stream"}
        assert content["text/event-stream"]["schema"]["type"] == "string"
        assert "description" not in content["text/event-stream"]
        assert operation["x-multillm-runtime"]["mode"] == "managed"
        assert "application/json" in operation["responses"]["default"]["content"]
    assert "text/event-stream" not in spec["paths"]["/v1/images/generations"]["post"]["responses"]["200"]["content"]
    assert spec["paths"]["/v1/messages/count_tokens"]["post"]["x-multillm-runtime"]["token_count"] == {"source": "estimate", "provider_call": False}
    assert schemas["MessagesRequest"]["properties"]["max_tokens"]["minimum"] == 1


def test_refs_and_header_definitions_are_complete():
    from services.openapi_spec import build_openapi_spec

    spec = build_openapi_spec()
    def check(value):
        if isinstance(value, dict):
            if "$ref" in value:
                target = spec
                for part in value["$ref"].removeprefix("#/").split("/"):
                    target = target[part]
            for child in value.values():
                check(child)
        elif isinstance(value, list):
            for child in value:
                check(child)
    check(spec)
    parameters = spec["components"]["parameters"].values()
    assert {item["name"] for item in parameters} >= {
        "X-MultiLLM-Api-Key", "X-MultiLLM-Cache", "X-MultiLLM-Tool-Repair",
        "X-MultiLLM-Image-QA", "X-MultiLLM-Cascade", "Anthropic-Version", "Anthropic-Beta",
    }
    assert "X-MultiLLM-External-Origin" not in json.dumps(spec)


class OpenAPIEndpointTest(UnifiedApiTestCase):
    def setUp(self):
        self.no_env = patch("env_loader.load_runtime_env")
        self.no_env.start()
        self.addCleanup(self.no_env.stop)
        import config
        self.config_env = patch.object(config, "load_runtime_env")
        self.config_env.start()
        self.addCleanup(self.config_env.stop)
        self.no_http = patch("requests.sessions.Session.request", side_effect=AssertionError("Unexpected HTTP"))
        self.no_http.start()
        self.addCleanup(self.no_http.stop)
        self.no_ledger = patch("services.usage_ledger.start")
        self.no_ledger.start()
        self.addCleanup(self.no_ledger.stop)
        super().setUp()

    def test_denial_matches_documentation_and_invalid_bearer_is_rejected(self):
        for path in ("/docs.json", "/openapi.json"):
            assert self.client.get(path).status_code == 302
            assert self.client.get(path, headers={"Accept": "application/json"}).status_code == 401
        denied = self.client.get("/openapi.json", headers={"Authorization": "Bearer invalid-synthetic"})
        assert denied.status_code == 401
        assert denied.is_json

    def test_bearer_and_dashboard_publish_only_static_contract(self):
        from services.openapi_spec import build_openapi_spec

        with patch("routes.documentation.refresh_model_catalogs", side_effect=AssertionError("Catalog refresh")), \
             patch("services.proxy_documentation_service.build_model_catalog", side_effect=AssertionError("Catalog read")), \
             patch("services.rate_limit_service.RateLimitService.enforce_request", side_effect=AssertionError("Generation budget")):
            response = self.client.get("/openapi.json", headers=ADMIN)
            assert response.status_code == 200
            assert response.mimetype == "application/json"
            assert response.get_json() == build_openapi_spec()
            proxy_header = self.client.get("/openapi.json", headers={"X-MultiLLM-Api-Key": "admin-test-key"})
            assert proxy_header.status_code == 200
            assert proxy_header.get_json() == response.get_json()
            assert "no-store" in response.headers["Cache-Control"]
            with patch("route_helpers.AuthService.is_authenticated", return_value=True):
                dashboard = self.client.get("/openapi.json")
            assert dashboard.status_code == 200
            assert dashboard.get_json() == response.get_json()
        assert self.client.get("/openapi.json", headers=ADMIN).get_json() == build_openapi_spec()

    def test_documented_methods_match_flask_and_worker_boundaries(self):
        from services.openapi_spec import build_openapi_spec

        spec = build_openapi_spec()
        worker = (ROOT / "cloudflare-worker.mjs").read_text()
        prefixes = (ROOT / "worker/api-paths.mjs").read_text()
        ids = []
        for path, item in spec["paths"].items():
            for method, operation in item.items():
                if method.startswith("x-"):
                    continue
                ids.append(operation["operationId"])
                rule, _ = self.app.url_map.bind("localhost").match(path, method=method.upper(), return_rule=True)
                assert method.upper() in rule.methods
                runtime = operation["x-multillm-runtime"]
                if runtime["mode"] == "native":
                    assert f'"{path.split("/")[1]}"' in prefixes
                    if path.startswith("/opencode/"):
                        assert path.removeprefix("/opencode") in worker
                        assert runtime["worker"] == "native-when-enabled"
                    else:
                        assert 'suffix.startsWith("/v1/images/")' in worker
                        assert runtime["worker"] == "native"
                    from services.provider_access_policy import provider_route_scope
                    provider, suffix = path.lstrip("/").split("/", 1)
                    assert runtime["required_scope"] == provider_route_scope(provider, suffix, method)
                    if method == "post":
                        assert operation["requestBody"]["content"]["application/json"]["schema"] == {}
                else:
                    assert runtime["worker"] == "forwarded"
        assert len(ids) == len(set(ids))
        assert re.search(r"const forwardedRequest = new Request\(containerUrl", worker)

    def test_existing_docs_payload_and_refresh_behavior_stay_unchanged(self):
        payload = {"base_url": "http://localhost", "generated_at": "fixed"}
        with patch("route_helpers.AuthService.is_authenticated", return_value=True), \
             patch("routes.documentation.refresh_model_catalogs") as refresh, \
             patch("routes.documentation.build_proxy_documentation", return_value=payload):
            assert self.client.get("/docs.json").get_json() == payload
            assert self.client.get("/docs?format=json").get_json() == payload
        assert refresh.call_count == 2

    def test_models_scope_is_required_for_api_credentials(self):
        user = {"username": "contract-reader", "scopes": ["chat"], "is_admin": False}
        with patch("route_helpers.AuthService.verify_api_key", return_value=user):
            denied = self.client.get("/openapi.json", headers=ADMIN)
            assert denied.status_code == 403
            user["scopes"] = ["models"]
            allowed = self.client.get("/openapi.json", headers=ADMIN)
            assert allowed.status_code == 200

    def test_method_rejection_cannot_publish_the_contract(self):
        from services.openapi_spec import build_openapi_spec

        # The pre-existing provider catch-all handles unsupported documentation methods.
        for method in ("post", "put", "delete"):
            response = getattr(self.client, method)("/openapi.json", headers=ADMIN, json={})
            assert response.status_code >= 400
            assert response.get_json() != build_openapi_spec()
