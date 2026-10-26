"""Claude API key pool: refusal classification, key rests and failover to the spare key."""

import io
import json
import os
from unittest.mock import patch

import pytest
import requests

from providers.anthropic import anthropic_credential_refusal
from tests.intelligence_fixtures import IntelligenceApiTestCase
from tests.intelligence_fixtures import upstream as cached_upstream
from tests.unified_api_test_case import UnifiedApiTestCase

MODEL = "claude-haiku-5-5"
SELECTOR = f"anthropic:{MODEL}"
ADMIN = {"Authorization": "Bearer admin-test-key"}
KEYS = {"ANTHROPIC_API_KEY": "key-a", "ANTHROPIC_API_KEY_1": "key-b"}
CREDIT = {
    "type": "error",
    "error": {
        "type": "invalid_request_error",
        "message": "Your credit balance is too low to access the Anthropic API. "
        "Please go to Plans & Billing to upgrade or purchase credits.",
    },
}
MESSAGE = {
    "id": "msg_haiku",
    "type": "message",
    "role": "assistant",
    "model": MODEL,
    "content": [{"type": "text", "text": "Hello"}],
    "stop_reason": "end_turn",
    "stop_sequence": None,
    "usage": {"input_tokens": 8, "output_tokens": 4},
}


def error(error_type, message, **details):
    body = {"type": "error", "error": {"type": error_type, "message": message}}
    if details:
        body["error"]["details"] = details
    return body


def upstream(body, status=200, content_type="application/json"):
    """A response whose body still sits on the socket, like a streamed upstream reply."""
    response = requests.Response()
    response.status_code = status
    response.raw = io.BytesIO(body if isinstance(body, bytes) else json.dumps(body).encode())
    response.headers["Content-Type"] = content_type
    return response


@pytest.fixture
def pool(monkeypatch):
    from services import pool_reset_schedule
    from services.credential_pool import CredentialPool
    from services.model_cooldown import model_cooldown

    for name, value in KEYS.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(pool_reset_schedule, "pool_reset_schedule", pool_reset_schedule.PoolResetSchedule())
    CredentialPool.reset()
    model_cooldown.reset()
    yield CredentialPool
    CredentialPool.reset()
    model_cooldown.reset()


@pytest.mark.parametrize(
    ("status", "body", "expected"),
    [
        (400, CREDIT, "credit_exhausted"),
        (400, error("invalid_request_error", "You have reached your specified API usage limits. "
                    "You will regain access on 2026-11-01 at 00:00 UTC."), "spend_limit"),
        (400, error("invalid_request_error", "You have reached your specified workspace API usage limits."),
         "spend_limit"),
        (429, error("rate_limit_error", "You have reached your API usage limits.",
                    error_code="enforced_spend_limit_reached"), "spend_cap"),
        (402, error("billing_error", "Payment details are invalid."), "billing_error"),
        (400, error("invalid_request_error", "messages.1.content.0: Invalid `signature` in `thinking` block."), None),
        (400, error("invalid_request_error", "max_tokens: Field required"), None),
        (429, error("rate_limit_error", "Number of request tokens has exceeded your rate limit."), None),
        (401, error("authentication_error", "invalid x-api-key"), None),
        (200, MESSAGE, None),
    ],
)
def test_only_account_wide_refusals_are_classified(status, body, expected):
    assert anthropic_credential_refusal(upstream(body, status)) == expected


def test_unreadable_or_oversized_error_bodies_are_not_refusals():
    assert anthropic_credential_refusal(upstream(b"credit balance is too low", 400, "text/plain")) is None
    assert anthropic_credential_refusal(upstream(b"{not json", 400)) is None
    oversized = upstream(CREDIT, 400)
    oversized.headers["Content-Length"] = "65537"
    assert anthropic_credential_refusal(oversized) is None


def test_a_classified_body_is_still_relayed_from_the_cache():
    from services.upstream_transport import _stream_content

    response = upstream(CREDIT, 400)
    assert anthropic_credential_refusal(response) == "credit_exhausted"
    assert response.raw.read() == b"", "classification drained the socket"
    assert json.loads(b"".join(_stream_content(response))) == CREDIT


def test_the_base_key_comes_first_and_x_api_key_results_rest_it(pool):
    from services.auth_service import AuthService

    assert pool.pooled("anthropic")
    assert AuthService.get_api_keys("anthropic") == ["key-a", "key-b"]
    assert AuthService.get_api_key("anthropic") == "key-a"
    pool.record_headers("anthropic", {"X-Api-Key": "key-a"}, 401)
    assert AuthService.get_api_key("anthropic") == "key-b"


@pytest.mark.parametrize("production_flags", [False, True])
def test_dispatch_rests_a_key_whose_account_ran_out_of_credit(pool, monkeypatch, production_flags):
    from services.auth_service import AuthService
    from services.credential_context import selection_context
    from services.proxy_service import ProxyService

    flag = "true" if production_flags else "false"
    monkeypatch.setenv("MODEL_COOLDOWN_ENABLED", flag)
    monkeypatch.setenv("POOL_RESET_SCHEDULING_ENABLED", flag)

    def send(body, status):
        with patch.object(ProxyService, "_make_base_request", return_value=upstream(body, status)):
            return ProxyService.make_request(
                method="POST",
                url="https://api.anthropic.com/v1/messages",
                headers={"X-Api-Key": "key-a", "Anthropic-Version": "2023-06-01"},
                params={},
                data=json.dumps({"model": MODEL, "max_tokens": 16, "messages": []}).encode(),
                api_provider="anthropic",
                use_cache=False,
                force_raw_passthrough=True,
            )

    scope = selection_context("anthropic", MODEL)
    response = send(error("invalid_request_error", "max_tokens: Field required"), 400)
    assert getattr(response, "multillm_credential_refusal", None) is None
    assert AuthService.get_api_key("anthropic", **scope) == "key-a", "a bad request is not the key's fault"

    response = send(CREDIT, 400)
    assert response.status_code == 400
    assert response.multillm_credential_refusal == "credit_exhausted"
    assert json.loads(response.content) == CREDIT
    assert AuthService.get_api_key("anthropic", **scope) == "key-b"
    assert AuthService.get_api_key("anthropic", **selection_context("anthropic", "claude-other")) == "key-b", (
        "an empty balance refuses every model"
    )


class AnthropicKeyFailoverRouteTest(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        from services.credential_pool import CredentialPool
        from services.model_cooldown import model_cooldown

        os.environ.update(KEYS)
        CredentialPool.reset()
        model_cooldown.reset()
        self.addCleanup(CredentialPool.reset)
        self.addCleanup(model_cooldown.reset)

    def upstreams(self, *replies):
        """Serve replies in order through the real dispatch path and record each key used."""
        from services.proxy_service import ProxyService

        self.sent_keys = []
        pending = list(replies)

        def reply(**kwargs):
            self.sent_keys.append(kwargs["headers"].get("X-Api-Key"))
            return upstream(*pending.pop(0))

        return patch.object(ProxyService, "_make_base_request", side_effect=reply)

    def chat(self):
        return self.client.post(
            "/v1/chat/completions",
            json={"model": SELECTOR, "messages": [{"role": "user", "content": "Hello"}]},
            headers=ADMIN,
        )

    def test_unified_chat_moves_to_the_spare_when_credit_runs_out(self):
        with self.upstreams((CREDIT, 400), (MESSAGE, 200)):
            result = self.chat()
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.get_json()["choices"][0]["message"]["content"], "Hello")
        self.assertEqual(self.sent_keys, ["key-a", "key-b"])
        self.assertEqual(result.headers["X-MultiLLM-Credential-Attempts"], "2")
        with self.upstreams((MESSAGE, 200)):
            self.assertEqual(self.chat().status_code, 200)
        self.assertEqual(self.sent_keys, ["key-b"], "the refused key rests")

    def test_unified_request_errors_are_not_repeated_on_the_spare(self):
        invalid = error("invalid_request_error", "messages: Field required")
        with self.upstreams((invalid, 400)):
            result = self.chat()
        self.assertEqual(result.status_code, 400)
        self.assertEqual(self.sent_keys, ["key-a"])

    def test_native_messages_move_to_the_spare_after_a_key_refusal(self):
        with self.upstreams((error("authentication_error", "invalid x-api-key"), 401), (MESSAGE, 200)):
            result = self.client.post(
                "/anthropic/v1/messages",
                json={"model": MODEL, "max_tokens": 16, "messages": [{"role": "user", "content": "Hi"}]},
                headers={"X-Api-Key": "admin-test-key", "Anthropic-Version": "2023-06-01"},
            )
            self.assertEqual(result.get_json(), MESSAGE)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(self.sent_keys, ["key-a", "key-b"])

    def test_native_messages_relay_the_last_refusal_when_every_key_is_refused(self):
        with self.upstreams((CREDIT, 400), (CREDIT, 400)):
            result = self.client.post(
                "/anthropic/v1/messages",
                json={"model": MODEL, "max_tokens": 16, "messages": [{"role": "user", "content": "Hi"}]},
                headers={"X-Api-Key": "admin-test-key", "Anthropic-Version": "2023-06-01"},
            )
            self.assertEqual(result.get_json(), CREDIT)
        self.assertEqual(result.status_code, 400)
        self.assertEqual(self.sent_keys, ["key-a", "key-b"])


class AnthropicKeyFailoverIntelligenceTest(IntelligenceApiTestCase):
    def test_haiku_runs_on_the_spare_key_before_falling_back_to_another_model(self):
        from services.credential_pool import CredentialPool
        from services.intelligence_anthropic import HAIKU_INTELLIGENCE_MODEL
        from services.intelligence_store import IntelligenceStore
        from services.proxy_service import ProxyService
        from tests.test_intelligence_policy import candidate, policy

        CredentialPool.reset()
        self.addCleanup(CredentialPool.reset)
        IntelligenceStore.seed(
            policy(
                allow_paid_overage=True,
                principal_daily_tokens=1_048_576,
                global_daily_tokens=1_048_576,
                candidates=[
                    candidate(HAIKU_INTELLIGENCE_MODEL, billing="payg", context_window=1_000_000),
                    candidate("openai:fallback", quality_tier=5),
                ],
            )
        )
        sent = []
        replies = [upstream(CREDIT, 400), cached_upstream(MESSAGE)]

        def reply(**kwargs):
            sent.append(kwargs["headers"].get("X-Api-Key"))
            return replies.pop(0)

        with (
            patch.object(self.app_module.AuthService, "get_api_keys", return_value=["key-a", "key-b"]),
            patch.object(ProxyService, "_make_base_request", side_effect=reply),
        ):
            response = self.post(routing={"allow_paid_overage": True})
        assert response.status_code == 200
        assert response.json["model"] == HAIKU_INTELLIGENCE_MODEL
        assert response.json["multillm"]["attempts"] == 2
        assert sent == ["key-a", "key-b"]
