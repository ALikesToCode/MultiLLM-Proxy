"""Reviewed free-pool contracts, separate from general paid provider routing."""

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class FreeProvider:
    chat_url: str
    # Only these reviewed models are seeded; a provider is not universally free.
    models: tuple[tuple[str, bool | None], ...] = ()
    requires_free_tier: bool = False
    extra: bool = False
    headers: tuple[tuple[str, str], ...] = ()


# Fixed official origins prevent a custom relay from reinterpreting free aliases.
# Sources and account restrictions: docs/free-provider-setup.md.
FREE_PROVIDERS = {
    "groq": FreeProvider(
        "https://api.groq.com/openai/v1/chat/completions",
        (
            ("qwen/qwen3.8-27b", True),
            ("qwen/qwen3.6-27b", True),
            ("openai/gpt-oss-120b", False),
        ),
        requires_free_tier=True,
    ),
    "opencode": FreeProvider("https://opencode.ai/zen/v1/chat/completions"),
    "aihubmix": FreeProvider("https://aihubmix.com/v1/chat/completions"),
    "gemini": FreeProvider(
        "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
        (("gemini-3.1-flash-lite", True),),
        requires_free_tier=True,
    ),
    "openrouter": FreeProvider(
        "https://openrouter.ai/api/v1/chat/completions",
        (("openrouter/free", True),),
    ),
    "mistral": FreeProvider(
        "https://api.mistral.ai/v1/chat/completions",
        (("mistral-small-latest", True),),
        requires_free_tier=True,
        extra=True,
    ),
    "workersai": FreeProvider(
        "https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/v1/chat/completions",
        (("@cf/meta/llama-4-scout-17b-16e-instruct", True),),
        requires_free_tier=True,
        extra=True,
    ),
    "zai": FreeProvider(
        "https://api.z.ai/api/paas/v4/chat/completions",
        (("glm-4.5-flash", False),),
        extra=True,
    ),
    "orcarouter": FreeProvider(
        "https://api.orcarouter.ai/v1/chat/completions",
        (("orcarouter/free", None),),
        extra=True,
    ),
    "bazaarlink": FreeProvider(
        "https://api.bazaarlink.ai/v1/chat/completions",
        (("auto:free", False),),
        extra=True,
        # Its default permits paid spillover on funded accounts after quota.
        headers=(("X-Free-Fallback", "false"),),
    ),
    "llm7": FreeProvider(
        "https://api.llm7.io/v1/chat/completions",
        (("fast", None),),
        requires_free_tier=True,
        extra=True,
    ),
}
PROVIDER_ORDER = tuple(FREE_PROVIDERS)
FREE_TIER_MODELS = {
    name: tuple(model for model, _ in spec.models)
    for name, spec in FREE_PROVIDERS.items()
    if spec.requires_free_tier
}
SEED_VISION = {
    f"{name}:{model}": vision
    for name, spec in FREE_PROVIDERS.items()
    for model, vision in spec.models
}


def configured_names(config, setting: str) -> set[str]:
    return {name.strip() for name in config.get(setting, "").split(",")}


def provider_enabled(config, provider: str) -> bool:
    spec = FREE_PROVIDERS.get(provider)
    if spec is None:
        return False
    if spec.extra:
        return provider in configured_names(config, "FREE_ROUTE_EXTRA_PROVIDERS")
    return provider in config["API_BASE_URLS"]


def provider_tier_confirmed(config, provider: str) -> bool:
    return not FREE_PROVIDERS[
        provider
    ].requires_free_tier or provider in configured_names(
        config, "FREE_ROUTE_FREE_TIER_PROVIDERS"
    )


def free_chat_url(config, provider: str) -> str | None:
    spec = FREE_PROVIDERS.get(provider)
    if spec is None:
        return None
    if provider != "workersai":
        return spec.chat_url
    account_id = config.get("FREE_ROUTE_WORKERSAI_ACCOUNT_ID", "")
    # Never accept URLs, path segments or a deployment credential as an account.
    if not re.fullmatch(r"[a-fA-F0-9]{32}", account_id):
        return None
    return spec.chat_url.format(account_id=account_id)


def provider_setup(config, auth) -> list[dict]:
    """Safe setup diagnostics: names and booleans, never secret/account values."""
    result = []
    for name, spec in FREE_PROVIDERS.items():
        enabled = provider_enabled(config, name)
        tier = provider_tier_confirmed(config, name)
        key = bool(auth.get_api_key(name))
        endpoint = bool(free_chat_url(config, name))
        missing = []
        if not enabled:
            missing.append("provider_not_enabled")
        if not tier:
            missing.append("free_tier_not_confirmed")
        if not key:
            missing.append("api_key_missing")
        if not endpoint:
            missing.append("account_id_missing_or_invalid")
        result.append(
            {
                "id": name,
                "api_key_env_names": list(auth.provider_credential_env_names(name)),
                "account_id_setting": "FREE_ROUTE_WORKERSAI_ACCOUNT_ID"
                if name == "workersai"
                else None,
                "extra_provider": spec.extra,
                "requires_free_tier": spec.requires_free_tier,
                "enabled": enabled,
                "free_tier_confirmed": tier,
                "configured": key and endpoint,
                "ready": not missing,
                "missing": missing,
            }
        )
    return result
