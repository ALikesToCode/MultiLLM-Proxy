import io
from unittest.mock import patch
import pytest
from flask import Flask
from error_handlers import APIError
from services.intelligence_route_policy import authorize_integration_route
from services.intelligence_store import IntelligenceStore
from tests.intelligence_fixtures import IntelligenceApiTestCase, completion, upstream
from tests.test_intelligence_policy import candidate

PRINCIPAL = {
    "id": "integration:omni",
    "username": "integration:omni",
    "is_admin": False,
    "scopes": ["chat", "models", "audio", "embeddings"],
}


class IntegrationRouteTests(IntelligenceApiTestCase):
    def setUp(self):
        super().setUp()
        auth = patch.object(
            self.app_module.AuthService, "verify_api_key", return_value=PRINCIPAL
        )
        auth.start()
        self.addCleanup(auth.stop)

    def test_legacy_spend_routes_are_denied_before_admission_or_provider(self):
        paths = [
            "/v1/chat/completions",
            "/openai/v1/chat/completions",
            "/navyai/v1/chat/completions",
            "/optimize/v1/chat/completions",
            "/v1/images/generations",
            "/openai/v1/audio/speech",
            "/openai/v1/embeddings",
            "/v1/responses",
        ]
        with (
            self.requests() as provider,
            patch.object(IntelligenceStore, "reserve") as ledger,
            patch("route_helpers.RateLimitService.enforce_request") as rate,
        ):
            for path in paths:
                with self.subTest(path=path):
                    response = self.client.post(
                        path,
                        headers=self.headers,
                        json={
                            "model": "openai:small",
                            "messages": [{"role": "user", "content": "test"}],
                        },
                    )
                    assert response.status_code == 403, (path, response.status_code)
            provider.assert_not_called()
            ledger.assert_not_called()
            rate.assert_not_called()

    def test_permitted_chat_paths_use_gateway_admission(self):
        self.seed()
        for path, extra in [
            ("/v1/chat/completions", {"model": "auto:intelligence"}),
            ("/v1/chat/completions", {"model": "openai:small", "routing": {}}),
            ("/intelligence/v1/chat/completions", {"model": "openai:small"}),
        ]:
            with (
                self.subTest(path=path, extra=extra),
                self.requests(return_value=upstream(completion())) as provider,
                patch.object(
                    IntelligenceStore, "reserve", wraps=IntelligenceStore.reserve
                ) as ledger,
            ):
                response = self.client.post(
                    path,
                    headers=self.headers,
                    json={"messages": [{"role": "user", "content": "test"}], **extra},
                )
                assert response.status_code == 200, response.data
                assert ledger.call_count >= 1
                assert provider.call_count == 1

    def test_canonical_media_uses_gateway_admission(self):
        self.seed(
            media={
                name: {
                    "candidate": candidate(model, capabilities=capabilities),
                    "max_input_bytes": 4096,
                    "daily_requests": 4,
                    "principal_daily_requests": 4,
                    **extra,
                }
                for name, model, capabilities, extra in [
                    ("speech", "openai:speak", ["audio"], {"voice": "pinned-voice"}),
                    ("transcriptions", "openai:transcribe", ["audio"], {}),
                    ("embeddings", "openai:embed", [], {"dimensions": 3}),
                ]
            }
        )
        cases = [
            (
                "/v1/audio/speech",
                {"json": {"model": "openai:speak", "input": "hello"}},
                upstream(b"synthetic-audio", headers={"Content-Type": "audio/mpeg"}),
            ),
            (
                "/v1/audio/transcriptions",
                {
                    "data": {
                        "model": "openai:transcribe",
                        "file": (io.BytesIO(b"audio"), "test.wav"),
                    }
                },
                upstream({"text": "hello"}),
            ),
            (
                "/v1/embeddings",
                {"json": {"model": "openai:embed", "input": "hello"}},
                upstream(
                    {
                        "data": [{"index": 0, "embedding": [0.1, 0.2, 0.3]}],
                        "usage": {"prompt_tokens": 1, "total_tokens": 1},
                    }
                ),
            ),
        ]
        for path, body, result in cases:
            with (
                self.subTest(path=path),
                self.requests(return_value=result) as provider,
                patch.object(
                    IntelligenceStore, "reserve", wraps=IntelligenceStore.reserve
                ) as ledger,
            ):
                response = self.client.post(path, headers=self.headers, **body)
                assert response.status_code == 200, response.data
                assert ledger.call_count == 1
                assert provider.call_count == 1


@pytest.mark.parametrize(
    "path,method",
    [
        ("/v1/models", "GET"),
        ("/v1/audio/speech", "POST"),
        ("/v1/audio/transcriptions", "POST"),
        ("/v1/embeddings", "POST"),
        ("/mcp", "POST"),
        ("/v1/knowledge/context", "POST"),
        ("/v1/knowledge/artifacts/art-1", "GET"),
        ("/v1/knowledge/sources/src-1/refresh", "POST"),
    ],
)
def test_exact_reviewed_routes_are_allowed(path, method):
    with Flask(__name__).test_request_context(path, method=method):
        authorize_integration_route(PRINCIPAL)


@pytest.mark.parametrize(
    "path,method",
    [
        ("/v1/models", "POST"),
        ("/v1/audio/speech/", "POST"),
        ("/admin/models", "GET"),
        ("/openai/v1/models", "GET"),
        ("/v1/audio/speech", "GET"),
        ("/mcpx", "POST"),
        ("/admin/knowledge/status", "GET"),
        ("/v1/knowledge", "POST"),
    ],
)
def test_other_routes_and_methods_fail_closed(path, method):
    with Flask(__name__).test_request_context(path, method=method):
        with pytest.raises(APIError) as caught:
            authorize_integration_route(PRINCIPAL)
        assert caught.value.status_code == 403


@pytest.mark.parametrize("payload", [None, [], "routing", {"model": "openai:small"}])
def test_unified_chat_requires_gateway_discriminator(payload):
    with Flask(__name__).test_request_context(
        "/v1/chat/completions", method="POST", json=payload
    ):
        with pytest.raises(APIError):
            authorize_integration_route(PRINCIPAL)


def test_ordinary_and_admin_principals_are_not_restricted():
    with Flask(__name__).test_request_context(
        "/openai/v1/chat/completions", method="POST"
    ):
        authorize_integration_route({"id": "ordinary", "is_admin": False})
        authorize_integration_route({"id": "admin", "is_admin": True})
