import os
from unittest.mock import patch

import pytest

from services.proxy_service import ProxyService
from services.client_headers import client_context_headers, with_client_defaults
from tests.unified_api_test_case import UnifiedApiTestCase


@pytest.mark.parametrize(
    "path",
    [
        "chat/completions",
        "v1/chat/completions",
        "v1/responses",
        "v1/messages",
        "v1/models",
    ],
)
@pytest.mark.parametrize(
    "provider",
    [
        "opencode",
        "openai",
        "linkapi",
        "nanogpt",
        "openrouter",
        "kimi-code",
        "gemini",
        "groq",
        "aihubmix",
        "codex-easy",
    ],
)
def test_missing_client_identity_defaults_to_codex(path, provider):
    with patch.dict(
        os.environ,
        {"UPSTREAM_DEFAULT_USER_AGENT": "", "UPSTREAM_DEFAULT_ORIGINATOR": ""},
    ):
        headers = ProxyService.prepare_headers(
            {}, provider, "test-key", upstream_path=path
        )
    assert headers["User-Agent"] == "codex-cli"
    assert headers["Originator"] == "codex_cli_rs"
    assert "X-Opencode-Session" not in headers


def test_client_override_wins_over_environment_default():
    with patch.dict(
        os.environ,
        {
            "UPSTREAM_DEFAULT_USER_AGENT": "fleet-client/2",
            "UPSTREAM_DEFAULT_ORIGINATOR": "fleet",
        },
    ):
        headers = ProxyService.prepare_headers(
            {"uSeR-aGeNt": "my-client/3", "originator": "my-client"}, "opencode"
        )
        defaulted = ProxyService.prepare_headers({}, "opencode")
    assert headers["User-Agent"] == "my-client/3"
    assert headers["Originator"] == "my-client"
    assert defaulted["User-Agent"] == "fleet-client/2"
    assert defaulted["Originator"] == "fleet"


@pytest.mark.parametrize(
    "name",
    [
        "thread-id",
        "session_id",
        "session-id",
        "x-session-id",
        "x-codex-session-id",
        "x-session-affinity",
    ],
)
def test_session_aliases_survive_and_supply_opencode_session(name):
    incoming = {name: "conversation-a"}
    first = ProxyService.prepare_headers(incoming, "opencode")
    retry = ProxyService.prepare_headers(incoming, "opencode")
    assert (
        first["X-Opencode-Session"] == retry["X-Opencode-Session"] == "conversation-a"
    )
    assert dict((k.lower(), v) for k, v in first.items())[name] == "conversation-a"
    second = ProxyService.prepare_headers({name: "conversation-b"}, "opencode")
    assert second["X-Opencode-Session"] == "conversation-b"


def test_explicit_opencode_session_wins_and_secrets_are_not_forwarded():
    headers = ProxyService.prepare_headers(
        {
            "x-opencode-session": "explicit-session",
            "session_id": "native-session",
            "x-opencode-client": "terminal",
            "Cookie": "private-cookie",
            "X-Unrelated-Secret": "private-value",
        },
        "opencode",
    )
    assert headers["X-Opencode-Session"] == "explicit-session"
    assert headers["X-Opencode-Client"] == "terminal"
    assert "Cookie" not in headers
    assert "X-Unrelated-Secret" not in headers


def test_native_session_forwarded_without_opencode_specific_headers():
    headers = ProxyService.prepare_headers(
        {"session_id": "native-session", "x-opencode-session": "specific"}, "openrouter"
    )
    assert headers["User-Agent"] == "codex-cli"
    assert "X-Opencode-Session" not in headers
    assert headers["session_id"] == "native-session"


def test_thread_precedence_preserves_both_native_headers():
    headers = with_client_defaults(
        {"Session-Id": "vm", "thread-id": "conversation"}, "opencode"
    )
    assert headers["X-Opencode-Session"] == "conversation"
    assert headers["Session-Id"] == "vm"
    assert headers["Thread-Id"] == "conversation"


def test_defaults_are_validated_case_insensitive_and_do_not_mutate_input():
    incoming = {
        "uSeR-aGeNt": "custom/1",
        "originator": "",
        "Authorization": "Bearer upstream-test",
    }
    original = dict(incoming)
    with patch.dict(os.environ, {"UPSTREAM_DEFAULT_ORIGINATOR": "invalid\r\nvalue"}):
        headers = with_client_defaults(incoming)
    assert incoming == original
    assert headers["User-Agent"] == "custom/1"
    assert headers["Originator"] == "codex_cli_rs"
    assert headers["Authorization"] == "Bearer upstream-test"
    assert "Authorization" not in client_context_headers(incoming)
    assert "ChatGPT-Account-Id" not in client_context_headers(
        {"ChatGPT-Account-Id": "account"}
    )


@pytest.mark.parametrize(
    "provider", ["opencode", "openai", "nanogpt", "openrouter", "groq"]
)
def test_shared_transport_supplies_defaults_for_internal_requests(provider):
    incoming = {"Authorization": "Bearer upstream-test"}
    with patch.object(ProxyService, "_make_base_request") as send:
        ProxyService.make_request(
            "GET",
            "https://provider.example/v1/models",
            incoming,
            {},
            None,
            provider,
            force_raw_passthrough=True,
        )
    assert send.call_args.kwargs["headers"]["User-Agent"] == "codex-cli"
    assert send.call_args.kwargs["headers"]["Originator"] == "codex_cli_rs"
    assert incoming == {"Authorization": "Bearer upstream-test"}


class ClientHeaderRouteTest(UnifiedApiTestCase):
    def test_headerless_native_and_unified_calls_reach_transport_with_session(self):
        self.client.environ_base.pop("HTTP_USER_AGENT", None)
        for route, model in (
            ("/opencode/v1/chat/completions", "glm-5.3-flash"),
            ("/opencode/v1/responses", "gpt-5.6-luna"),
            ("/opencode/v1/messages", "minimax-m3"),
            ("/v1/chat/completions", "opencode:glm-5.3-flash"),
        ):
            with self.subTest(route=route):
                with patch.object(ProxyService, "_make_base_request", return_value=self._chat_response()) as send:
                    response = self.client.post(route, headers={"Authorization": "Bearer admin-test-key"}, json={
                        "model": model, "messages": [{"role": "user", "content": "Synthetic request"}], "input": "Synthetic request",
                    })
                assert response.status_code == 200
                assert send.call_args.kwargs["headers"]["X-Opencode-Session"].startswith("multillm_v1_")

    def test_headers_reach_upstream_from_native_and_unified_routes(self):
        self.client.environ_base.pop("HTTP_USER_AGENT", None)
        for route in ("/opencode/v1/chat/completions", "/v1/chat/completions"):
            for override in (None, "fleet-override/1"):
                with self.subTest(route=route, override=override):
                    incoming = {
                        "Authorization": "Bearer admin-test-key",
                        "session_id": "vm-conversation-a",
                    }
                    if override:
                        incoming["User-Agent"] = override
                    model = (
                        "opencode:glm-5.3-flash"
                        if route == "/v1/chat/completions"
                        else "glm-5.3-flash"
                    )
                    with (
                        patch.dict(
                            os.environ, {"UPSTREAM_DEFAULT_USER_AGENT": "codex-cli"}
                        ),
                        patch(
                            "app.ProxyService.make_request",
                            return_value=self._chat_response(),
                        ) as send,
                    ):
                        response = self.client.post(
                            route,
                            headers=incoming,
                            json={
                                "model": model,
                                "messages": [
                                    {"role": "user", "content": "Synthetic header test"}
                                ],
                            },
                        )
                    assert response.status_code == 200
                    forwarded = send.call_args.kwargs["headers"]
                    assert forwarded["User-Agent"] == (override or "codex-cli")
                    assert forwarded["X-Opencode-Session"] == "vm-conversation-a"

    def test_session_headers_are_allowed_by_cors(self):
        response = self.client.options(
            "/opencode/v1/responses", headers={"Origin": "https://example.com"}
        )
        allowed = response.headers["Access-Control-Allow-Headers"].lower()
        for header in (
            "x-opencode-session",
            "session_id",
            "session-id",
            "user-agent",
            "originator",
        ):
            assert header in {value.strip() for value in allowed.split(",")}

    def test_free_failover_preserves_identity_without_proxy_credentials(self):
        from tests.test_free_routes import catalog_row

        self.client.environ_base.pop("HTTP_USER_AGENT", None)
        rows = [
            catalog_row("opencode", "mimo-v2.5-free", vision=True),
            catalog_row("aihubmix", "gemma-4-31b-it-free", vision=True),
        ]
        failed = self._chat_response()
        failed.status_code = 429
        with (
            patch("services.free_model_policy.build_model_catalog", return_value=rows),
            patch(
                "app.ProxyService.make_request",
                side_effect=[failed, self._chat_response("synthetic classification")],
            ) as send,
        ):
            response = self.client.post(
                "/v1/free/vision/chat/completions",
                headers={
                    "Authorization": "Bearer admin-test-key",
                    "User-Agent": "fleet/3",
                    "Originator": "custom",
                    "thread-id": "thread-1",
                    "Cookie": "private-cookie",
                },
                json={"messages": [{"role": "user", "content": "Synthetic test"}]},
            )
        assert response.status_code == 200
        assert send.call_count == 2
        for call in send.call_args_list:
            headers = call.kwargs["headers"]
            assert headers["User-Agent"] == "fleet/3"
            assert headers["Originator"] == "custom"
            assert headers["Thread-Id"] == "thread-1"
            assert headers["Authorization"] != "Bearer admin-test-key"
            assert "Cookie" not in headers
