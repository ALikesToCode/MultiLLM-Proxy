"""Codex Everywhere pools: one provider per purchased key group.

A Codex Everywhere (CE) key belongs to one group and serves only that group's models,
so each pool is its own provider with its own key. Every pool shares one origin
(docs.codex-everywhere.com/integrations). Usage is billed as a fraction of the model
vendor's list price, shown beside each pool (docs.codex-everywhere.com/models, Oct 2026).

The original `codex-easy` provider is a separate single-key integration and is unchanged.
The GPT Image pool is an image relay (`ce-image`, see providers/image_relays.py).
"""

from __future__ import annotations

from dataclasses import dataclass

CODEX_EVERYWHERE_BASE_URL = "https://codex-everywhere.com"
OPENAI_PROTOCOL = "openai"
ANTHROPIC_PROTOCOL = "anthropic"


@dataclass(frozen=True)
class CodexEverywherePool:
    provider: str
    display_name: str
    credential_env: str
    protocol: str
    # Fraction of the vendor's list price CE charges for this pool.
    price_multiplier: float


CODEX_EVERYWHERE_POOLS = (
    # GPT-6 series (Astra, 6.1 Sol, Sol, Luna) and GPT-5.6. CE warns that Plus Pool Astra
    # and gpt-6-sol answers are sometimes downgraded; Pro Pool isolates those accounts.
    CodexEverywherePool(
        "ce-gpt-plus",
        "Codex Everywhere Plus Pool",
        "CODEX_EVERYWHERE_API_KEY_GPT_PLUS_POOL",
        OPENAI_PROTOCOL,
        0.03,
    ),
    CodexEverywherePool(
        "ce-gpt-pro",
        "Codex Everywhere Pro Pool",
        "CODEX_EVERYWHERE_API_KEY_GPT_PRO_POOL",
        OPENAI_PROTOCOL,
        0.05,
    ),
    # Grok 4.7, 4.6 and 4.5.
    CodexEverywherePool(
        "ce-grok-heavy",
        "Codex Everywhere Grok Heavy Pool",
        "CODEX_EVERYWHERE_API_KEY_GROK_HEAVY",
        OPENAI_PROTOCOL,
        0.06,
    ),
    # Claude Opus 5.5 and earlier through Kiro. CE notes some system prompt contamination;
    # the cheap pool is labelled unstable.
    CodexEverywherePool(
        "ce-claude-kiro-cheap",
        "Codex Everywhere Claude via Kiro (Cheap)",
        "CODEX_EVERYWHERE_API_KEY_CLAUDE_UNSTABLE",
        ANTHROPIC_PROTOCOL,
        0.045,
    ),
    CodexEverywherePool(
        "ce-claude-kiro",
        "Codex Everywhere Claude via Kiro",
        "CODEX_EVERYWHERE_API_KEY_CLAUDE_KIRO",
        ANTHROPIC_PROTOCOL,
        0.08,
    ),
    # Claude Fable 5.1 and the rest at full quality. CE limits this pool to Claude Code.
    CodexEverywherePool(
        "ce-claude-max",
        "Codex Everywhere Claude Max Pool",
        "CODEX_EVERYWHERE_API_KEY_CLAUDE_MAX",
        ANTHROPIC_PROTOCOL,
        0.24,
    ),
)
CODEX_EVERYWHERE_PROVIDERS = frozenset(pool.provider for pool in CODEX_EVERYWHERE_POOLS)
CODEX_EVERYWHERE_OPENAI_PROVIDERS = frozenset(
    pool.provider for pool in CODEX_EVERYWHERE_POOLS if pool.protocol == OPENAI_PROTOCOL
)
CODEX_EVERYWHERE_ANTHROPIC_PROVIDERS = frozenset(
    pool.provider for pool in CODEX_EVERYWHERE_POOLS if pool.protocol == ANTHROPIC_PROTOCOL
)
# The raw paths each protocol documents; anything else never reaches CE.
CODEX_EVERYWHERE_PATHS = {
    OPENAI_PROTOCOL: frozenset({"v1/models", "v1/responses", "v1/chat/completions"}),
    ANTHROPIC_PROTOCOL: frozenset({"v1/models", "v1/messages", "v1/messages/count_tokens"}),
}


def codex_everywhere_pool(provider: str) -> CodexEverywherePool | None:
    normalized = str(provider or "").strip().lower()
    return next((pool for pool in CODEX_EVERYWHERE_POOLS if pool.provider == normalized), None)


def codex_everywhere_base_urls() -> dict[str, str]:
    return {pool.provider: CODEX_EVERYWHERE_BASE_URL for pool in CODEX_EVERYWHERE_POOLS}


def codex_everywhere_credential_env_names() -> dict[str, tuple[str, ...]]:
    return {pool.provider: (pool.credential_env,) for pool in CODEX_EVERYWHERE_POOLS}


def is_valid_codex_everywhere_path(provider: str, path: str) -> bool:
    pool = codex_everywhere_pool(provider)
    if pool is None or not path or any(delimiter in path for delimiter in "%?#\\"):
        return False
    if any(ord(character) < 32 or ord(character) == 127 for character in path):
        return False
    return path in CODEX_EVERYWHERE_PATHS[pool.protocol]


def codex_everywhere_model_endpoint(model_id: str) -> str | None:
    """Claude pools speak only Anthropic Messages, so unified Chat is translated to it."""
    return "v1/messages"


# CE serves its GPT models through Codex, which prepends its own coding-agent system prompt
# (about 4,400 tokens) unless the request sets `instructions`
# (docs.codex-everywhere.com/models/openai). Observed 2026-10-04 on Chat Completions: with
# only a system message the model introduced itself as Codex, a software engineer; with
# `instructions` the prompt was 44 tokens and the system prompt was followed. Grok pools
# follow system messages and need nothing.
CODEX_INSTRUCTION_PROVIDERS = frozenset({"codex-easy", "ce-gpt-plus", "ce-gpt-pro"})
DEFAULT_CODEX_INSTRUCTIONS = "You are a helpful assistant."


def _message_text(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list) and all(
        isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str)
        for part in content
    ):
        return "\n".join(part["text"] for part in content)
    return None


def with_codex_instructions(payload: dict, provider: str, model: str) -> dict:
    """Give a Chat Completions request to a CE GPT model its own `instructions`.

    Leading system and developer messages become the instructions and leave the message
    list; later ones stay where they are. A request with none gets a neutral instruction,
    so Codex's coding prompt is never added. A caller's own `instructions` is kept.
    """
    name = str(model or "").strip().lower()
    if (
        provider not in CODEX_INSTRUCTION_PROVIDERS
        or not name.startswith(("gpt-", "codex-"))
        or name.startswith("gpt-image")
        or "instructions" in payload
    ):
        return payload
    messages = payload.get("messages")
    messages = list(messages) if isinstance(messages, list) else []
    lifted = []
    while (
        messages
        and isinstance(messages[0], dict)
        and messages[0].get("role") in {"system", "developer"}
        and (text := _message_text(messages[0].get("content"))) is not None
    ):
        lifted.append(text)
        messages.pop(0)
    instructions = "\n\n".join(text for text in lifted if text.strip()) or DEFAULT_CODEX_INSTRUCTIONS
    result = {**payload, "instructions": instructions}
    if "messages" in payload:
        result["messages"] = messages
    return result
