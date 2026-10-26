"""Lean mode: keep Claude API requests cached and under Haiku's long-prompt price.

`/lean/v1/...` serves the unified Messages, Chat Completions and Responses routes
(middleware/lean_path.py). For a request that reaches the Claude API, the body is
changed only in ways that give every later request of the conversation the same
bytes up to its new turn, so prompt caching and preserved thinking keep working:

* shell tool output is condensed by rules that read only that output;
* an oversized tool result keeps its head and tail;
* prompt caching is turned on when the caller placed no breakpoints;
* old tool results are cleared by server-side context editing, which never
  invalidates thinking blocks;
* a prompt that would still pay the long-prompt price is refused with the
  caller's own "prompt is too long" error, so the harness compacts and retries.

Changing these rules changes the bytes of conversations already in flight and
invalidates their replayed thinking blocks; bump LEAN_RULES_VERSION when you do.
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from typing import Any

from flask import g, has_request_context, request

from middleware.lean_path import LEAN_ENVIRON_KEY
from providers.protocols import MESSAGES
from services.native_token_count import NativeTokenCountError, count_claude_prompt_tokens

logger = logging.getLogger(__name__)

LEAN_RULES_VERSION = "1"
CONTEXT_MANAGEMENT_BETA = "context-management-2025-06-27"
CLEAR_TOOL_USES = "clear_tool_uses_20250919"
STYLE_HEADER = "X-MultiLLM-Lean-Style"
# Haiku 5.5 bills a request whose prompt is over 100,000 tokens, cache reads and
# writes included, at five times the price of the whole request. The default sits
# 1,000 tokens lower because count_tokens is itself an estimate.
DEFAULT_PROMPT_TOKEN_LIMIT = 99_000
DEFAULT_CLEAR_TRIGGER_TOKENS = 80_000
DEFAULT_CLEAR_KEEP_TOOL_USES = 3
DEFAULT_CLEAR_AT_LEAST_TOKENS = 20_000
DEFAULT_TOOL_RESULT_MAX_CHARS = 100_000
# The local estimate (about three characters per token) can read a third low:
# Haiku 5.5's tokenizer and tool definitions add tokens it does not see. Counting
# from 40% of the limit leaves that margin before a prompt can cross it uncounted.
COUNT_FROM_LIMIT_SHARE = 0.4
MEDIA_BLOCK_TOKENS = 1_600
# count_tokens rejects URL and file sources and every server tool but the
# advisor, so those are estimated at these sizes instead.
REMOTE_DOCUMENT_TOKENS = 10_000
SERVER_TOOL_TOKENS = 1_000
UNCOUNTABLE_SOURCES = frozenset({"url", "file"})
REPEATED_LINE_MIN_RUN = 4
SHELL_TOOL_NAMES = frozenset(
    {
        "bash",
        "exec_command",
        "execute_command",
        "local_shell",
        "run_command",
        "run_shell_command",
        "run_terminal_cmd",
        "shell",
        "shell_command",
        "terminal",
    }
)
CONCISE_STYLE = (
    "Response style: be brief. Lead with the answer or the next action. Skip "
    "preamble, filler, apologies and restating the request. Keep code, commands, "
    "file paths, error messages, numbers and negations exact and complete. Write "
    "plain full sentences for risky or irreversible steps and whenever the user "
    "seems unsure."
)
_ANSI_ESCAPE = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]"  # CSI: colours, cursor movement, erase line
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC: titles, hyperlinks
    r"|\x1b[@-Z\\-_]"  # other two-byte escapes
)


class LeanPromptTooLong(Exception):
    """The prompt, after every lean stage, would still pay the long-prompt price."""

    def __init__(self, tokens: int, limit: int):
        super().__init__(f"prompt is too long: {tokens} tokens > {limit} maximum")
        self.tokens = tokens
        self.limit = limit


@dataclass(frozen=True)
class LeanPolicy:
    prompt_token_limit: int = DEFAULT_PROMPT_TOKEN_LIMIT
    clear_trigger_tokens: int = DEFAULT_CLEAR_TRIGGER_TOKENS
    clear_keep_tool_uses: int = DEFAULT_CLEAR_KEEP_TOOL_USES
    clear_at_least_tokens: int = DEFAULT_CLEAR_AT_LEAST_TOKENS
    clear_exclude_tools: tuple[str, ...] = ()
    cache_ttl: str = "5m"
    condense_shell_output: bool = True
    tool_result_max_chars: int = DEFAULT_TOOL_RESULT_MAX_CHARS
    style: str = "none"
    # Whether the price limit applies to the prompt before ("original") or after
    # ("cleared") context editing. Anthropic's pricing page does not say which
    # size picks the price, so the default assumes the larger one does.
    price_limit_basis: str = "original"


@dataclass(frozen=True)
class LeanRequest:
    body: dict
    active: bool = False
    betas: tuple[str, ...] = ()
    stages: tuple[str, ...] = ()
    prompt_tokens: int | None = None
    prompt_count: str = ""
    prompt_tokens_after_clearing: int | None = None
    condensed_chars: int = 0


def _env_int(environ: Mapping[str, str], name: str, default: int) -> int:
    value = str(environ.get(name, "")).strip()
    try:
        return max(0, int(value)) if value else default
    except ValueError:
        return default


def _env_flag(environ: Mapping[str, str], name: str, default: bool) -> bool:
    value = str(environ.get(name, "")).strip().lower()
    if not value:
        return default
    return value in {"1", "true", "yes", "on"}


def _style(value: Any) -> str | None:
    normalized = str(value or "").strip().lower()
    if normalized in {"concise", "caveman"}:
        return "concise"
    if normalized in {"none", "off"}:
        return "none"
    return None


def lean_policy(environ: Mapping[str, str] | None = None) -> LeanPolicy:
    environ = os.environ if environ is None else environ
    exclude = str(environ.get("LEAN_CLEAR_EXCLUDE_TOOLS", ""))
    return LeanPolicy(
        prompt_token_limit=_env_int(environ, "LEAN_PROMPT_TOKEN_LIMIT", DEFAULT_PROMPT_TOKEN_LIMIT),
        clear_trigger_tokens=_env_int(environ, "LEAN_CLEAR_TRIGGER_TOKENS", DEFAULT_CLEAR_TRIGGER_TOKENS),
        clear_keep_tool_uses=_env_int(environ, "LEAN_CLEAR_KEEP_TOOL_USES", DEFAULT_CLEAR_KEEP_TOOL_USES),
        clear_at_least_tokens=_env_int(environ, "LEAN_CLEAR_AT_LEAST_TOKENS", DEFAULT_CLEAR_AT_LEAST_TOKENS),
        clear_exclude_tools=tuple(name.strip() for name in exclude.split(",") if name.strip()),
        cache_ttl="1h" if str(environ.get("LEAN_CACHE_TTL", "")).strip().lower() == "1h" else "5m",
        condense_shell_output=_env_flag(environ, "LEAN_CONDENSE_SHELL_OUTPUT", True),
        tool_result_max_chars=_env_int(environ, "LEAN_TOOL_RESULT_MAX_CHARS", DEFAULT_TOOL_RESULT_MAX_CHARS),
        style=_style(environ.get("LEAN_STYLE")) or "none",
        price_limit_basis=(
            "cleared"
            if str(environ.get("LEAN_PRICE_LIMIT_BASIS", "")).strip().lower() == "cleared"
            else "original"
        ),
    )


def lean_requested() -> bool:
    return has_request_context() and request.environ.get(LEAN_ENVIRON_KEY) is True


def _header(headers: Mapping[str, Any] | None, name: str) -> str:
    for key, value in (headers or {}).items():
        if str(key).lower() == name.lower() and isinstance(value, str):
            return value.strip()
    return ""


def condense_shell_output(text: str) -> str:
    """Drop what a terminal shows but a reader does not need, deterministically.

    Removes ANSI escapes, keeps only the last redraw of a carriage-return
    progress line, collapses a run of identical lines to one line and a count,
    and collapses runs of blank lines.
    """
    condensed = _ANSI_ESCAPE.sub("", text)
    if "\r" in condensed:
        condensed = condensed.replace("\r\n", "\n")
        condensed = "\n".join(
            next((part for part in reversed(line.split("\r")) if part), "")
            for line in condensed.split("\n")
        )
    lines = condensed.split("\n")
    kept: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        end = index + 1
        while end < len(lines) and lines[end] == line:
            end += 1
        run = end - index
        if not line.strip():
            kept.extend([line] if run < 3 else [""])
        elif run >= REPEATED_LINE_MIN_RUN:
            kept.extend([line, f"[previous line repeated {run - 1} more times]"])
        else:
            kept.extend(lines[index:end])
        index = end
    return "\n".join(kept)


def clip_tool_text(text: str, max_chars: int) -> str:
    """Keep the head and tail of an oversized tool result, marking the cut."""
    if max_chars <= 0 or len(text) <= max_chars:
        return text
    head = max_chars // 2
    tail = max_chars - head
    omitted = len(text) - head - tail
    return (
        f"{text[:head]}\n[MultiLLM lean: {omitted} characters omitted from the middle "
        f"of this tool result]\n{text[-tail:]}"
    )


def _tool_names(messages: list) -> dict[str, str]:
    names: dict[str, str] = {}
    for message in messages:
        if not isinstance(message, dict) or message.get("role") != "assistant":
            continue
        content = message.get("content")
        for block in content if isinstance(content, list) else ():
            if isinstance(block, dict) and block.get("type") == "tool_use" and isinstance(block.get("id"), str):
                names[block["id"]] = str(block.get("name") or "")
    return names


def _condense_text(text: str, *, terminal_output: bool, max_chars: int, stages: set[str]) -> str:
    result = text
    if terminal_output:
        condensed = condense_shell_output(result)
        if condensed != result:
            stages.add("condense-shell")
            result = condensed
    clipped = clip_tool_text(result, max_chars)
    if clipped != result:
        stages.add("clip-tool-result")
        result = clipped
    return result


def _condense_tool_result(block: dict, *, terminal_output: bool, max_chars: int, stages: set[str]) -> dict:
    content = block.get("content")
    if isinstance(content, str):
        condensed = _condense_text(content, terminal_output=terminal_output, max_chars=max_chars, stages=stages)
        return block if condensed == content else {**block, "content": condensed}
    if not isinstance(content, list):
        return block
    parts = []
    for part in content:
        if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str):
            condensed = _condense_text(part["text"], terminal_output=terminal_output, max_chars=max_chars, stages=stages)
            parts.append(part if condensed == part["text"] else {**part, "text": condensed})
        else:
            parts.append(part)
    return block if parts == content else {**block, "content": parts}


def _condense_tool_results(messages: Any, policy: LeanPolicy, stages: set[str]) -> tuple[Any, int]:
    """Condense every tool result by rules that read only that result and its tool's name."""
    if not isinstance(messages, list):
        return messages, 0
    names = _tool_names(messages)
    before = _text_length(messages)
    condensed_messages = []
    for message in messages:
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(message, dict) or message.get("role") != "user" or not isinstance(content, list):
            condensed_messages.append(message)
            continue
        blocks = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "tool_result":
                tool_name = names.get(block.get("tool_use_id"), "").lower()
                block = _condense_tool_result(
                    block,
                    terminal_output=policy.condense_shell_output and tool_name in SHELL_TOOL_NAMES,
                    max_chars=policy.tool_result_max_chars,
                    stages=stages,
                )
            blocks.append(block)
        condensed_messages.append(message if blocks == content else {**message, "content": blocks})
    if condensed_messages == messages:
        return messages, 0
    return condensed_messages, before - _text_length(condensed_messages)


def _text_length(value: Any) -> int:
    if isinstance(value, str):
        return len(value)
    if isinstance(value, dict):
        return sum(_text_length(item) for item in value.values())
    if isinstance(value, list):
        return sum(_text_length(item) for item in value)
    return 0


def _has_cache_breakpoint(body: Mapping[str, Any]) -> bool:
    """Whether the caller placed a breakpoint where the API reads one.

    Only blocks count: a tool schema or a tool call's input can have an ordinary
    property named `cache_control`.
    """
    if "cache_control" in body:
        return True
    candidates: list = []
    for key in ("system", "tools"):
        if isinstance(body.get(key), list):
            candidates.extend(body[key])
    for block in _blocks(body.get("messages")):
        candidates.append(block)
        if block.get("type") == "tool_result" and isinstance(block.get("content"), list):
            candidates.extend(block["content"])
    return any(isinstance(block, dict) and "cache_control" in block for block in candidates)


def _with_style(body: dict) -> dict:
    style = {"type": "text", "text": CONCISE_STYLE}
    system = body.get("system")
    if isinstance(system, str) and system:
        blocks = [{"type": "text", "text": system}, style]
    elif isinstance(system, list):
        blocks = [*system, style]
    else:
        blocks = [style]
    return {**body, "system": blocks}


def _with_cache_breakpoints(body: dict, ttl: str) -> tuple[dict, bool]:
    """Cache the conversation, plus the tools and system prompt on their own.

    The top-level marker moves with the conversation's last block. The second
    breakpoint keeps the tools and system prompt cached when context editing
    clears an old tool result and the rest of the prefix must be written again.
    """
    if _has_cache_breakpoint(body):
        return body, False
    marker = {"type": "ephemeral"} if ttl == "5m" else {"type": "ephemeral", "ttl": ttl}
    cached = {**body, "cache_control": dict(marker)}
    system = body.get("system")
    tools = body.get("tools")
    if isinstance(system, str) and system:
        cached["system"] = [{"type": "text", "text": system, "cache_control": dict(marker)}]
    elif isinstance(system, list) and system and isinstance(system[-1], dict):
        cached["system"] = [*system[:-1], {**system[-1], "cache_control": dict(marker)}]
    elif isinstance(tools, list) and tools and isinstance(tools[-1], dict):
        cached["tools"] = [*tools[:-1], {**tools[-1], "cache_control": dict(marker)}]
    return cached, True


def _blocks(messages: Any) -> Iterable[dict]:
    for message in messages if isinstance(messages, list) else ():
        content = message.get("content") if isinstance(message, dict) else None
        for block in content if isinstance(content, list) else ():
            if isinstance(block, dict):
                yield block


def _with_tool_clearing(body: dict, policy: LeanPolicy) -> tuple[dict, bool]:
    """Clear old tool results server-side once the prompt passes the trigger.

    Skipped when the caller manages context itself, and for signed compaction
    blocks, which cannot be combined with context editing.
    """
    blocks = list(_blocks(body.get("messages")))
    uses_tools = bool(body.get("tools")) or any(block.get("type") == "tool_result" for block in blocks)
    if (
        policy.clear_trigger_tokens <= 0
        or not uses_tools
        or "context_management" in body
        or "compaction" in body
        or any(block.get("type") == "compaction" for block in blocks)
    ):
        return body, False
    edit: dict[str, Any] = {
        "type": CLEAR_TOOL_USES,
        "trigger": {"type": "input_tokens", "value": policy.clear_trigger_tokens},
        "keep": {"type": "tool_uses", "value": policy.clear_keep_tool_uses},
    }
    if policy.clear_at_least_tokens:
        edit["clear_at_least"] = {"type": "input_tokens", "value": policy.clear_at_least_tokens}
    if policy.clear_exclude_tools:
        edit["exclude_tools"] = list(policy.clear_exclude_tools)
    return {**body, "context_management": {"edits": [edit]}}, True


def _is_server_tool(tool: Any) -> bool:
    return isinstance(tool, dict) and tool.get("type") not in (None, "custom")


def _estimate(body: Mapping[str, Any]) -> tuple[int, bool]:
    """Estimate the prompt and say whether count_tokens can count it.

    Text counts three characters per token, an image a flat size, a text
    document its characters and a base64 PDF a token per three decoded bytes.
    """
    characters = 0
    tokens = 0
    countable = True

    def walk(value: Any) -> None:
        nonlocal characters, tokens, countable
        if isinstance(value, dict):
            kind = value.get("type")
            raw_source = value.get("source")
            source: dict[str, Any] = raw_source if isinstance(raw_source, dict) else {}
            if kind in {"image", "document"}:
                data = source.get("data")
                if source.get("type") in UNCOUNTABLE_SOURCES:
                    countable = False
                    tokens += MEDIA_BLOCK_TOKENS if kind == "image" else REMOTE_DOCUMENT_TOKENS
                elif kind == "image":
                    tokens += MEDIA_BLOCK_TOKENS
                elif source.get("type") == "content":
                    walk(source.get("content"))
                elif isinstance(data, str):
                    tokens += len(data) // 4 if source.get("type") == "base64" else len(data) // 3
                else:
                    tokens += REMOTE_DOCUMENT_TOKENS
                return
            for key, item in value.items():
                if key != "cache_control":
                    walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
        elif isinstance(value, str):
            characters += len(value)

    for key in ("system", "tools", "messages"):
        walk(body.get(key))
    raw_tools = body.get("tools")
    tools: list[Any] = raw_tools if isinstance(raw_tools, list) else []
    tokens += SERVER_TOOL_TOKENS * sum(1 for tool in tools if _is_server_tool(tool))
    return characters // 3 + tokens, countable


def estimate_prompt_tokens(body: Mapping[str, Any]) -> int:
    """A rough estimate that decides when to count exactly."""
    return _estimate(body)[0]


def _count_body(body: dict) -> tuple[dict, int]:
    """Drop the server tools count_tokens rejects; return the body and their allowance."""
    tools = body.get("tools")
    if not isinstance(tools, list) or not any(_is_server_tool(tool) for tool in tools):
        return body, 0
    client_tools = [tool for tool in tools if not _is_server_tool(tool)]
    counted = {key: value for key, value in body.items() if key != "tools"}
    if client_tools:
        counted["tools"] = client_tools
    choice = body.get("tool_choice")
    if isinstance(choice, dict) and choice.get("type") == "tool" and not any(
        tool.get("name") == choice.get("name") for tool in client_tools if isinstance(tool, dict)
    ):
        counted.pop("tool_choice", None)
    return counted, SERVER_TOOL_TOKENS * (len(tools) - len(client_tools))


def merged_beta_value(existing: str, betas: Iterable[str]) -> str:
    values = [item.strip() for item in str(existing or "").split(",") if item.strip()]
    for beta in betas:
        if beta not in values:
            values.append(beta)
    return ",".join(values)


def merge_beta_header(headers: dict, betas: Iterable[str]) -> None:
    """Add lean betas to an upstream header dict without dropping the caller's."""
    betas = tuple(betas)
    if not betas:
        return
    name = next((key for key in headers if key.lower() == "anthropic-beta"), "Anthropic-Beta")
    headers[name] = merged_beta_value(headers.get(name, ""), betas)


def check_lean_prompt(
    decision: LeanRequest,
    credential: str | None,
    *,
    request_headers: Mapping[str, Any] | None,
    base_urls: Mapping[str, str],
) -> None:
    """Refuse a prepared prompt that would pay the long-prompt price.

    Counts with the key that will send the request: thinking blocks from another
    account are dropped before counting, so any other key can undercount. When
    the prompt cannot be counted, the estimate decides.
    """
    if not decision.active:
        return
    policy = lean_policy()
    limit = policy.prompt_token_limit
    estimate, countable = _estimate(decision.body)
    tokens, source, after = estimate, "estimate", None
    if limit > 0 and countable and estimate >= limit * COUNT_FROM_LIMIT_SHARE:
        count_body, allowance = _count_body(decision.body)
        beta_header = merged_beta_value(_header(request_headers, "anthropic-beta"), decision.betas)
        try:
            after, before = count_claude_prompt_tokens(count_body, beta_header, base_urls, credential=credential)
        except NativeTokenCountError as error:
            logger.warning("Lean prompt count failed status=%s; using the estimate", error.status)
        else:
            after, before = after + allowance, before + allowance
            tokens, source = (before if policy.price_limit_basis == "original" else after), "provider"
    g.lean_request = replace(
        decision, prompt_tokens=tokens, prompt_count=source, prompt_tokens_after_clearing=after
    )
    if limit > 0 and tokens > limit:
        raise LeanPromptTooLong(tokens, limit)


def prepare_lean_request(
    body: dict,
    *,
    provider: str,
    endpoint: str,
    request_headers: Mapping[str, Any] | None,
) -> LeanRequest:
    """Apply lean mode to a Claude API Messages body; other requests pass unchanged.

    check_lean_prompt then sizes the result against the price limit.
    """
    if not lean_requested():
        return LeanRequest(body=body)
    if provider != "anthropic" or endpoint != MESSAGES:
        g.lean_request = LeanRequest(body=body)
        return g.lean_request
    policy = lean_policy()
    stages: set[str] = set()
    prepared = dict(body)
    messages, condensed_chars = _condense_tool_results(body.get("messages"), policy, stages)
    if messages is not body.get("messages"):
        prepared["messages"] = messages
    if (_style(_header(request_headers, STYLE_HEADER)) or policy.style) == "concise":
        prepared = _with_style(prepared)
        stages.add("concise-style")
    prepared, cached = _with_cache_breakpoints(prepared, policy.cache_ttl)
    if cached:
        stages.add("cache")
    prepared, clearing = _with_tool_clearing(prepared, policy)
    betas = (CONTEXT_MANAGEMENT_BETA,) if clearing else ()
    if clearing:
        stages.add("clear-tool-uses")
    decision = LeanRequest(
        body=prepared,
        active=True,
        betas=betas,
        stages=tuple(sorted(stages)),
        condensed_chars=max(0, condensed_chars),
    )
    g.lean_request = decision
    return decision


def lean_response_headers(response):
    """Report what lean mode did, so callers can see why a request stayed cheap."""
    if not lean_requested():
        return response
    decision = getattr(g, "lean_request", None)
    active = decision is not None and decision.active
    response.headers["X-MultiLLM-Lean"] = "applied" if active else "inactive"
    response.headers["X-MultiLLM-Lean-Rules"] = LEAN_RULES_VERSION
    if active:
        response.headers["X-MultiLLM-Lean-Stages"] = ",".join(decision.stages) or "none"
        if decision.prompt_tokens is not None:
            response.headers["X-MultiLLM-Lean-Prompt-Tokens"] = str(decision.prompt_tokens)
            response.headers["X-MultiLLM-Lean-Prompt-Count"] = decision.prompt_count
        after = decision.prompt_tokens_after_clearing
        if after is not None and after != decision.prompt_tokens:
            response.headers["X-MultiLLM-Lean-Prompt-Tokens-After-Clearing"] = str(after)
        if decision.condensed_chars:
            response.headers["X-MultiLLM-Lean-Condensed-Chars"] = str(decision.condensed_chars)
    return response
