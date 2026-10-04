import json
import os
from unittest.mock import patch

from providers.codex_everywhere import (
    CODEX_EVERYWHERE_BASE_URL,
    CODEX_EVERYWHERE_POOLS,
    is_valid_codex_everywhere_path,
)
from tests.intelligence_fixtures import IntelligenceApiTestCase, completion, upstream

OPENAI_POOLS = ("ce-gpt-plus", "ce-gpt-pro", "ce-grok-heavy")
CLAUDE_POOLS = ("ce-claude-kiro-cheap", "ce-claude-kiro", "ce-claude-max")


def test_every_pool_is_a_separate_provider_with_its_own_key():
    from config import Config
    from providers.image_relays import image_relay_spec
    from providers.registry import get_adapter
    from services.auth_primitives import provider_api_key_env_names
    from services.provider_catalog_service import PROVIDER_CATALOG_SPECS
    from services.transport_policy import RAW_PASSTHROUGH_PROVIDERS

    assert {pool.provider for pool in CODEX_EVERYWHERE_POOLS} == {*OPENAI_POOLS, *CLAUDE_POOLS}
    keys = [provider_api_key_env_names(pool.provider) for pool in CODEX_EVERYWHERE_POOLS]
    assert len({names for names in keys}) == len(keys), "no two pools share a key"
    assert provider_api_key_env_names("ce-gpt-pro") == ("CODEX_EVERYWHERE_API_KEY_GPT_PRO_POOL",)
    assert provider_api_key_env_names("ce-claude-kiro-cheap") == (
        "CODEX_EVERYWHERE_API_KEY_CLAUDE_UNSTABLE",
    )
    for pool in CODEX_EVERYWHERE_POOLS:
        assert Config.API_BASE_URLS[pool.provider] == CODEX_EVERYWHERE_BASE_URL
        assert Config.API_TIMEOUTS[pool.provider] == (5, 600)
        adapter = get_adapter(pool.provider, Config.API_BASE_URLS)
        assert adapter.chat_completions_url() == "https://codex-everywhere.com/v1/chat/completions"
        assert pool.provider in RAW_PASSTHROUGH_PROVIDERS
        assert PROVIDER_CATALOG_SPECS[pool.provider].proxy_path == f"/{pool.provider}/v1/models"
    image = image_relay_spec("ce-image")
    assert image.credential_env == "CODEX_EVERYWHERE_API_KEY_GPT_IMAGE"
    assert image.base_url == CODEX_EVERYWHERE_BASE_URL and not image.supports_chat


def test_gpt_and_grok_pools_speak_chat_and_responses_while_claude_pools_speak_messages():
    from providers.protocols import chat_bridge_endpoint, native_endpoints
    from services.intelligence_policy import CHAT_PROVIDERS

    for provider in OPENAI_POOLS:
        assert native_endpoints(provider, "gpt-6.1-sol") == {"v1/chat/completions", "v1/responses"}
        assert chat_bridge_endpoint(provider, "gpt-6.1-sol") is None
        assert provider in CHAT_PROVIDERS
    for provider in CLAUDE_POOLS:
        assert native_endpoints(provider, "claude-opus-5-5") == {"v1/messages"}
        assert chat_bridge_endpoint(provider, "claude-opus-5-5") == "v1/messages"
        assert provider not in CHAT_PROVIDERS, "the intelligence chain sends Chat Completions only"


def test_raw_routes_allow_only_each_protocols_documented_paths():
    assert is_valid_codex_everywhere_path("ce-gpt-pro", "v1/responses")
    assert is_valid_codex_everywhere_path("ce-grok-heavy", "v1/chat/completions")
    assert not is_valid_codex_everywhere_path("ce-gpt-pro", "v1/messages")
    assert is_valid_codex_everywhere_path("ce-claude-kiro", "v1/messages")
    assert is_valid_codex_everywhere_path("ce-claude-max", "v1/messages/count_tokens")
    assert not is_valid_codex_everywhere_path("ce-claude-kiro", "v1/chat/completions")
    for path in ("v1/images/generations", "v1/../admin", "v1/models?key=x", "v1/models%2f", ""):
        assert not is_valid_codex_everywhere_path("ce-gpt-plus", path), path
    assert not is_valid_codex_everywhere_path("codex-easy", "v1/models")


def test_claude_pools_get_a_bearer_token_and_an_anthropic_version():
    from services.proxy_service import ProxyService

    headers = ProxyService.prepare_headers(
        {"Content-Type": "application/json", "anthropic-beta": "tools-2024"},
        "ce-claude-kiro",
        "pool-key",
        upstream_path="v1/messages",
    )
    assert headers["Authorization"] == "Bearer pool-key"
    assert headers["Anthropic-Version"] == "2023-06-01"
    assert headers["Anthropic-Beta"] == "tools-2024"
    gpt = ProxyService.prepare_headers({}, "ce-gpt-pro", "pool-key", upstream_path="v1/chat/completions")
    assert gpt["Authorization"] == "Bearer pool-key" and "Anthropic-Version" not in gpt


class CodexEverywhereIntelligenceTests(IntelligenceApiTestCase):
    def test_a_pool_candidate_uses_its_own_key_and_the_shared_origin(self):
        from services.auth_service import AuthService
        from services.intelligence_store import IntelligenceStore
        from tests.test_intelligence_policy import candidate, policy

        self.keys.stop()
        self.pool.stop()
        env = {
            "CODEX_EVERYWHERE_API_KEY_GPT_PLUS_POOL": "synthetic-plus-key",
            "CODEX_EVERYWHERE_API_KEY_GPT_PRO_POOL": "synthetic-pro-key",
        }
        with patch.dict(os.environ, env):
            AuthService._load_provider_api_keys()
            IntelligenceStore.seed(
                policy(candidates=[candidate("ce-gpt-plus:gpt-6.1-sol"), candidate("ce-gpt-pro:gpt-6.1-sol")])
            )
            with self.requests(
                side_effect=[upstream({"code": "INSUFFICIENT_BALANCE"}, 403), upstream(completion("done"))]
            ) as send:
                response = self.post()
        AuthService._load_provider_api_keys()
        assert response.status_code == 200
        assert response.json["multillm"]["selected_model"] == "ce-gpt-pro:gpt-6.1-sol"
        plus, pro = send.call_args_list
        for call, key in ((plus, "synthetic-plus-key"), (pro, "synthetic-pro-key")):
            assert call.kwargs["url"] == "https://codex-everywhere.com/v1/chat/completions"
            assert call.kwargs["headers"]["Authorization"] == f"Bearer {key}"
            assert json.loads(call.kwargs["data"])["model"] == "gpt-6.1-sol"


def test_pool_keys_run_base_first_then_numbered_spares_and_rest_refused_ones():
    from services.credential_pool import (
        RATE_LIMITED_REST_SECONDS,
        REFUSED_REST_SECONDS,
        CredentialPool,
    )

    env = {
        "CODEX_EVERYWHERE_API_KEY_GPT_PRO_POOL": "key-a",
        "CODEX_EVERYWHERE_API_KEY_GPT_PRO_POOL_10": "key-d",
        "CODEX_EVERYWHERE_API_KEY_GPT_PRO_POOL_2": "key-c",
        "CODEX_EVERYWHERE_API_KEY_GPT_PRO_POOL_1": "key-b",
        "CODEX_EVERYWHERE_API_KEY_GPT_PRO_POOL_3": "key-a",
        "CODEX_EVERYWHERE_API_KEY_GPT_PRO_POOL_4": "your-ce-pro-pool-key",
        "CODEX_EVERYWHERE_API_KEY_GPT_PLUS_POOL_1": "other-pool",
    }
    assert CredentialPool.keys("ce-gpt-pro", env) == ["key-a", "key-b", "key-c", "key-d"]
    assert CredentialPool.keys("ce-gpt-plus", env) == ["other-pool"], "a spare works without a base key"
    assert CredentialPool.keys("openai", env) == [] and not CredentialPool.pooled("openai")
    keys = ["key-a", "key-b"]
    CredentialPool.reset()
    try:
        CredentialPool.record("ce-gpt-pro", "key-a", 403, now=100)
        assert CredentialPool.available("ce-gpt-pro", keys, now=101) == ["key-b"]
        assert CredentialPool.available("ce-gpt-plus", ["key-a"], now=101) == ["key-a"], "rests are per pool"
        assert CredentialPool.available("ce-gpt-pro", keys, now=100 + REFUSED_REST_SECONDS) == keys
        CredentialPool.record("ce-gpt-pro", "key-b", 429, now=1000)
        assert CredentialPool.available("ce-gpt-pro", keys, now=1001) == ["key-a"]
        assert CredentialPool.available("ce-gpt-pro", keys, now=1000 + RATE_LIMITED_REST_SECONDS) == keys
        CredentialPool.record("ce-gpt-pro", "key-a", 403, now=2000)
        CredentialPool.record("ce-gpt-pro", "key-a", 200, now=2001)
        assert CredentialPool.available("ce-gpt-pro", keys, now=2002) == keys, "a success ends the rest"
        CredentialPool.record("ce-gpt-pro", "key-a", 400, now=3000)
        assert CredentialPool.available("ce-gpt-pro", keys, now=3001) == keys, "a bad request is not the key's fault"
    finally:
        CredentialPool.reset()


def test_auth_service_moves_to_the_spare_after_a_raw_refusal():
    import requests

    from services.auth_service import AuthService
    from services.credential_pool import CredentialPool
    from services.proxy_service import ProxyService

    env = {
        "CODEX_EVERYWHERE_API_KEY_GPT_IMAGE": "image-a",
        "CODEX_EVERYWHERE_API_KEY_GPT_IMAGE_1": "image-b",
    }
    refused = requests.Response()
    refused.status_code = 403
    CredentialPool.reset()
    try:
        with patch.dict(os.environ, env):
            assert AuthService.get_api_keys("ce-image") == ["image-a", "image-b"]
            assert AuthService.get_api_key("ce-image") == "image-a"
            with patch.object(ProxyService, "_make_base_request", return_value=refused):
                ProxyService.make_request(
                    method="POST",
                    url="https://codex-everywhere.com/v1/images/generations",
                    headers={"Authorization": "Bearer image-a"},
                    params={},
                    data=b"{}",
                    api_provider="ce-image",
                    use_cache=False,
                )
            assert AuthService.get_api_key("ce-image") == "image-b"
            CredentialPool.record("ce-image", "image-b", 403)
            assert AuthService.get_api_key("ce-image") == "image-a", "with every key resting, the first is used"
    finally:
        CredentialPool.reset()


class CodexEverywhereKeyFallbackTests(IntelligenceApiTestCase):
    def seed_pool(self, *models):
        from services.intelligence_store import IntelligenceStore
        from tests.test_intelligence_policy import candidate, policy

        IntelligenceStore.seed(policy(candidates=[candidate(model) for model in models]))

    def pool_keys(self, *keys):
        return patch.object(self.app_module.AuthService, "get_api_keys", return_value=list(keys))

    def test_a_refused_key_retries_the_same_model_on_the_spare(self):
        self.seed_pool("ce-gpt-pro:gpt-6.1-sol", "navyai:large")
        with self.pool_keys("pro-a", "pro-b"), self.requests(
            side_effect=[upstream({"code": "INSUFFICIENT_BALANCE"}, 403), upstream(completion("done"))]
        ) as send:
            response = self.post()
        assert response.status_code == 200
        assert response.json["multillm"]["selected_model"] == "ce-gpt-pro:gpt-6.1-sol"
        assert response.json["multillm"]["attempts"] == 2
        sent = [call.kwargs["headers"]["Authorization"] for call in send.call_args_list]
        assert sent == ["Bearer pro-a", "Bearer pro-b"]

    def test_a_pinned_pool_model_also_falls_back_to_its_spare(self):
        self.seed_pool("ce-gpt-pro:gpt-6.1-sol")
        with self.pool_keys("pro-a", "pro-b"), self.requests(
            side_effect=[upstream({}, 429), upstream(completion("done"))]
        ) as send:
            response = self.post(model="ce-gpt-pro:gpt-6.1-sol", routing={})
        assert response.status_code == 200 and send.call_count == 2

    def test_a_request_refusal_moves_on_without_trying_the_spare(self):
        self.seed_pool("ce-gpt-pro:gpt-6.1-sol", "navyai:large")
        with self.pool_keys("pro-a", "pro-b"), self.requests(
            side_effect=[upstream({}, 400), upstream(completion("done"))]
        ) as send:
            response = self.post()
        assert response.status_code == 200
        assert response.json["multillm"]["selected_model"] == "navyai:large"
        assert send.call_count == 2, "the same request would fail on every key"

    def test_resting_keys_are_skipped_and_an_all_resting_pool_costs_no_attempt(self):
        from services.credential_pool import CredentialPool

        self.seed_pool("ce-gpt-pro:gpt-6.1-sol", "navyai:large")
        CredentialPool.reset()
        self.addCleanup(CredentialPool.reset)
        CredentialPool.record("ce-gpt-pro", "pro-a", 403)
        with self.pool_keys("pro-a", "pro-b"), self.requests(return_value=upstream(completion("done"))) as send:
            self.post()
        assert send.call_args.kwargs["headers"]["Authorization"] == "Bearer pro-b"
        CredentialPool.record("ce-gpt-pro", "pro-b", 403)
        with self.pool_keys("pro-a", "pro-b"), self.requests(return_value=upstream(completion("done"))) as send:
            response = self.post()
        assert response.json["multillm"]["selected_model"] == "navyai:large"
        assert response.json["multillm"]["attempts"] == 1


def test_gpt_models_get_instructions_so_codexs_coding_prompt_is_not_added():
    from providers.codex_everywhere import (
        DEFAULT_CODEX_INSTRUCTIONS,
        with_codex_instructions,
    )

    user = {"role": "user", "content": "hi"}
    payload = {
        "model": "gpt-6.1-sol",
        "messages": [
            {"role": "system", "content": "You are Omni."},
            {"role": "developer", "content": [{"type": "text", "text": "Be brief."}]},
            user,
            {"role": "system", "content": "Later note."},
        ],
    }
    lifted = with_codex_instructions(payload, "ce-gpt-pro", "gpt-6.1-sol")
    assert lifted["instructions"] == "You are Omni.\n\nBe brief."
    assert lifted["messages"] == [user, {"role": "system", "content": "Later note."}]
    assert payload["messages"][0]["role"] == "system", "the caller's payload is not mutated"
    bare = with_codex_instructions({"messages": [user]}, "codex-easy", "codex-auto-review")
    assert bare == {"messages": [user], "instructions": DEFAULT_CODEX_INSTRUCTIONS}
    own = {"messages": [user], "instructions": "mine"}
    assert with_codex_instructions(own, "ce-gpt-plus", "gpt-6-luna") is own
    for provider, model in (("ce-grok-heavy", "grok-4.7"), ("openai", "gpt-6.1-sol"), ("ce-gpt-pro", "gpt-image-2")):
        assert with_codex_instructions(payload, provider, model) is payload, (provider, model)


class CodexEverywhereInstructionTests(IntelligenceApiTestCase):
    def test_the_chain_sends_system_messages_to_a_gpt_pool_as_instructions(self):
        from services.intelligence_store import IntelligenceStore
        from tests.test_intelligence_policy import candidate, policy

        IntelligenceStore.seed(policy(candidates=[candidate("ce-gpt-pro:gpt-6.1-sol")]))
        with self.requests(return_value=upstream(completion("done"))) as send:
            response = self.post(
                messages=[
                    {"role": "system", "content": "You are Omni."},
                    {"role": "user", "content": "test"},
                ]
            )
        assert response.status_code == 200
        sent = json.loads(send.call_args.kwargs["data"])
        assert sent["instructions"] == "You are Omni."
        assert sent["messages"] == [{"role": "user", "content": "test"}]
