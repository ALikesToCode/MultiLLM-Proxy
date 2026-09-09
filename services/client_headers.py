"""Client identity defaults and conversation-header forwarding, without credentials."""

import os
from collections.abc import Mapping

CLIENT_HEADER_NAMES = {
    "user-agent": "User-Agent",
    "originator": "Originator",
    "session-id": "Session-Id",
    "thread-id": "Thread-Id",
    "session_id": "session_id",
    "x-session-id": "X-Session-Id",
    "x-codex-session-id": "X-Codex-Session-Id",
    "x-session-affinity": "X-Session-Affinity",
}
OPENCODE_CLIENT_HEADER_NAMES = {
    f"x-opencode-{name}": f"X-Opencode-{name.title()}"
    for name in ("session", "client", "project", "request")
}
SESSION_HEADER_NAMES = (
    "thread-id",
    "session-id",
    "session_id",
    "x-session-id",
    "x-codex-session-id",
    "x-session-affinity",
)


def _value(value: str) -> str:
    if not isinstance(value, str) or any(
        ord(char) < 32 or ord(char) > 126 for char in value
    ):
        return ""
    return value.strip()


def client_context_headers(
    headers: Mapping[str, str], provider: str = ""
) -> dict[str, str]:
    names = {**CLIENT_HEADER_NAMES}
    if provider == "opencode":
        names.update(OPENCODE_CLIENT_HEADER_NAMES)
    return {
        names[name.lower()]: value
        for name, value in headers.items()
        if name.lower() in names and _value(value)
    }


def with_client_defaults(
    headers: Mapping[str, str], provider: str = ""
) -> dict[str, str]:
    """Fill missing identity only; keep explicit identity, auth and protocol headers."""
    result = dict(headers)
    names = {**CLIENT_HEADER_NAMES, **OPENCODE_CLIENT_HEADER_NAMES}
    for name in list(result):
        if name.lower() in names:
            value = result.pop(name)
            if _value(value):
                result[names[name.lower()]] = value
    for name, env_name, fallback in (
        ("User-Agent", "UPSTREAM_DEFAULT_USER_AGENT", "codex-cli"),
        ("Originator", "UPSTREAM_DEFAULT_ORIGINATOR", "codex_cli_rs"),
    ):
        result.setdefault(name, _value(os.environ.get(env_name, "")) or fallback)
    if provider == "opencode" and "X-Opencode-Session" not in result:
        for name in SESSION_HEADER_NAMES:
            value = result.get(CLIENT_HEADER_NAMES[name])
            if value:
                result["X-Opencode-Session"] = value
                break
    return result
