"""Reviewed NanoGPT subscription calls are pinned to an isolated key."""

import json
import logging
import os
import threading
import time
from contextlib import contextmanager
from unittest.mock import patch

import pytest

from services.intelligence_contract import GatewayError
from services.intelligence_store import IntelligenceStore
from services.intelligence_transport import IntelligenceTransport
from services.nanogpt_key_pool import NanoGPTUnifiedKeyPool
from tests.intelligence_fixtures import IntelligenceApiTestCase, completion, upstream
from tests.test_intelligence_policy import candidate, policy

ISOLATED = "INTELLIGENCE_NANOGPT_SUBSCRIPTION_API_KEY"
PINNED = "synthetic-isolated-subscription-key"
POOL = ["synthetic-pool-key-a", "synthetic-pool-key-b"]
SUBSCRIPTION_URL = "https://subscription.invalid/v1/chat/completions"


@pytest.fixture(autouse=True)
def shared_pool():
    NanoGPTUnifiedKeyPool.reset()
    yield
    NanoGPTUnifiedKeyPool.reset()


@contextmanager
def isolated_key(value):
    """Replace any deployment value so only synthetic keys reach the test."""
    with patch.dict(os.environ):
        os.environ.pop(ISOLATED, None)
        if value is not None:
            os.environ[ISOLATED] = value
        yield


class Auth:
    """A synthetic general credential source that records every lookup."""

    def __init__(self):
        self.lookups = []

    def get_api_keys(self, provider):
        self.lookups.append(provider)
        return list(POOL)

    def get_api_key(self, provider):
        self.lookups.append(provider)
        return f"synthetic-{provider}-key"


def transport(proxy=None):
    config = {
        "API_BASE_URLS": {
            "nanogpt": "https://pool.invalid",
            "openai": "https://openai.invalid",
        },
        "NANOGPT_SUBSCRIPTION_BASE_URL": "https://subscription.invalid",
        "NANOGPT_STANDARD_BASE_URL": "https://standard.invalid",
    }
    return IntelligenceTransport(config, Auth(), proxy)


def subscription(name="a"):
    return candidate(f"nanogpt:model-{name}", billing="subscription")


def test_subscription_uses_only_the_isolated_key_while_the_shared_pool_is_unavailable():
    NanoGPTUnifiedKeyPool.record_result(POOL[0], 401)
    NanoGPTUnifiedKeyPool.record_result(POOL[1], 429)
    gateway = transport()
    with isolated_key(f"  {PINNED}\n"):
        assert gateway.credential(subscription()) == PINNED
        # A rejection recorded for the pinned key neither retires it nor revives a
        # general key: the next reviewed candidate still receives the same key.
        NanoGPTUnifiedKeyPool.record_result(PINNED, 401)
        NanoGPTUnifiedKeyPool.record_result(PINNED, 429)
        assert gateway.credential(subscription("b")) == PINNED
    assert gateway.auth.lookups == []
    # The general keys' cooldowns were not pruned by the isolated selection.
    assert NanoGPTUnifiedKeyPool.select_available_key(POOL) is None


def test_without_an_isolated_key_subscription_keeps_the_shared_pool():
    gateway = transport()
    with isolated_key(None):
        assert gateway.credential(subscription()) == POOL[0]
        NanoGPTUnifiedKeyPool.record_result(POOL[0], 429)
        assert gateway.credential(subscription()) == POOL[1]
        NanoGPTUnifiedKeyPool.record_result(POOL[1], 401)
        assert gateway.credential(subscription()) is None
    assert gateway.auth.lookups == ["nanogpt"] * 3


@pytest.mark.parametrize("value", ["", " \n"])
def test_an_explicitly_empty_isolated_key_refuses_shared_pool_fallback(value):
    gateway = transport()
    with isolated_key(value):
        assert gateway.credential(subscription()) is None
    assert gateway.auth.lookups == []


@pytest.mark.parametrize("billing", ["payg", "allowance", "free"])
def test_other_billing_and_providers_ignore_the_isolated_key(billing):
    gateway = transport()
    general = candidate("nanogpt:model-a", billing=billing)
    with isolated_key(PINNED):
        assert gateway.credential(general) == POOL[0]
        assert (
            gateway.credential(candidate("openai:small", billing="subscription"))
            == "synthetic-openai-key"
        )
        NanoGPTUnifiedKeyPool.record_result(POOL[0], 401)
        NanoGPTUnifiedKeyPool.record_result(POOL[1], 429)
        assert gateway.credential(general) is None
    assert gateway.auth.lookups == ["nanogpt", "openai", "nanogpt"]


def test_subscription_media_is_refused_before_the_isolated_key_is_used():
    used = []

    class Proxy:
        def prepare_headers(self, *args, **kwargs):
            used.append("headers")

        def make_request(self, **kwargs):
            used.append("request")

    gateway = transport(Proxy())
    with isolated_key(PINNED), pytest.raises(GatewayError) as caught:
        gateway.start(
            subscription(),
            {"input": "synthetic"},
            gateway.credential(subscription()),
            time.monotonic() + 5,
            threading.Event(),
            1024,
            path="v1/audio/speech",
        )
    assert caught.value.code == "billing_policy" and used == []
    assert PINNED not in repr((caught.value.args, caught.value.message))


class LogCapture(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.messages = []

    def emit(self, record):
        self.messages.append(record.getMessage())


class IsolatedSubscriptionGatewayTests(IntelligenceApiTestCase):
    """Uses the real gateway, transport and header preparation; only sending is mocked."""

    def setUp(self):
        super().setUp()
        os.environ.pop(ISOLATED, None)
        self.app.config["NANOGPT_SUBSCRIPTION_BASE_URL"] = (
            "https://subscription.invalid"
        )

    @staticmethod
    def authorizations(send):
        return [call.kwargs["headers"]["Authorization"] for call in send.call_args_list]

    def test_fallback_keeps_the_isolated_key_within_bounded_attempts(self):
        IntelligenceStore.seed(
            policy(candidates=[subscription(name) for name in "abc"], max_attempts=2)
        )
        os.environ[ISOLATED] = PINNED
        NanoGPTUnifiedKeyPool.record_result("synthetic-provider-key", 401)
        capture, root = LogCapture(), logging.getLogger()
        level = root.level
        root.addHandler(capture)
        root.setLevel(logging.DEBUG)
        try:
            with patch.object(
                NanoGPTUnifiedKeyPool, "select_key", side_effect=AssertionError("probe")
            ):
                with self.requests(
                    side_effect=[upstream(status=401), upstream(completion())]
                ) as send:
                    recovered = self.post()
                with self.requests(
                    side_effect=[upstream(status=429), upstream(status=429)]
                ) as limited:
                    exhausted = self.post()
        finally:
            root.removeHandler(capture)
            root.setLevel(level)
        assert (
            recovered.status_code == 200
            and recovered.json["model"] == "nanogpt:model-b"
        )
        assert recovered.json["multillm"]["attempts"] == 2
        assert [
            json.loads(call.kwargs["data"])["model"] for call in send.call_args_list
        ] == ["model-a", "model-b"]
        assert exhausted.status_code == 429 and limited.call_count == 2
        assert exhausted.json["error"]["code"] == "upstream_rate_limited"
        for mock in (send, limited):
            assert self.authorizations(mock) == [f"Bearer {PINNED}"] * 2
            assert {call.kwargs["url"] for call in mock.call_args_list} == {
                SUBSCRIPTION_URL
            }
        exposed = " ".join(
            [
                *capture.messages,
                recovered.get_data(as_text=True),
                exhausted.get_data(as_text=True),
            ]
        )
        assert PINNED not in exposed

    def test_missing_isolated_key_keeps_the_pooled_subscription_credential(self):
        IntelligenceStore.seed(policy(candidates=[subscription()]))
        with self.requests(return_value=upstream(completion())) as send:
            assert self.post().status_code == 200
        assert self.authorizations(send) == ["Bearer synthetic-provider-key"]
        NanoGPTUnifiedKeyPool.record_result("synthetic-provider-key", 401)
        with self.requests() as send:
            response = self.post()
        assert response.status_code == 503 and send.call_count == 0
        assert response.json["error"]["code"] == "missing_credentials"

    def test_non_subscription_candidates_keep_their_general_credentials(self):
        IntelligenceStore.seed(
            policy(candidates=[candidate("nanogpt:model-a"), candidate("openai:small")])
        )
        os.environ[ISOLATED] = PINNED
        with self.requests(
            side_effect=[upstream(status=429), upstream(completion())]
        ) as send:
            response = self.post()
        assert response.status_code == 200 and response.json["model"] == "openai:small"
        assert self.authorizations(send) == ["Bearer synthetic-provider-key"] * 2
        assert SUBSCRIPTION_URL not in {
            call.kwargs["url"] for call in send.call_args_list
        }

    def test_empty_isolated_key_refuses_dispatch_with_general_keys_available(self):
        IntelligenceStore.seed(policy(candidates=[subscription()]))
        os.environ[ISOLATED] = " \n"
        with self.requests() as send:
            response = self.post()
        assert response.status_code == 503
        assert response.json["error"]["code"] == "missing_credentials"
        send.assert_not_called()
