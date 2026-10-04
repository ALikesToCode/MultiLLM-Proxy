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
