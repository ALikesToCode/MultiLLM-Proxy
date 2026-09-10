"""Best-effort conversation affinity for clients without session headers."""

import hashlib
import hmac
import json
import uuid
from collections.abc import Mapping

from services.client_headers import with_client_defaults

MAX_SESSION_BODY_BYTES = 1024 * 1024


def _conversation_anchor(payload):
    if not isinstance(payload, dict):
        return None
    metadata = payload.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    conversation = payload.get("conversation")
    for value in (
        payload.get("session_id"),
        payload.get("conversation_id"),
        metadata.get("session_id"),
        metadata.get("conversation_id"),
        conversation.get("id") if isinstance(conversation, dict) else conversation,
    ):
        if isinstance(value, str) and value.strip():
            return ["conversation", value]

    messages = payload.get("messages", payload.get("input"))
    if isinstance(messages, str):
        messages = [{"role": "user", "content": messages}]
    if not isinstance(messages, list):
        return None
    opening = []
    for message in messages:
        if not isinstance(message, dict):
            continue
        role, content = message.get("role"), message.get("content")
        if role not in ("system", "developer", "assistant", "user"):
            continue
        if not isinstance(content, (str, list)) or not content:
            continue
        opening.append([role, content])
        if role == "user":
            return [
                "opening",
                payload.get("system"),
                payload.get("instructions"),
                opening,
            ]
    return None


def with_opencode_request_session(
    headers: Mapping[str, str], data: bytes | None
) -> dict[str, str]:
    """Preserve real IDs; otherwise infer affinity without storing prompts or keys."""
    result = with_client_defaults(headers, "opencode")
    if result.get("X-Opencode-Session"):
        return result

    lower = {name.lower(): value for name, value in headers.items()}
    scope = lower.get("authorization") or lower.get("x-api-key") or ""
    anchor = None
    if scope and data and len(data) <= MAX_SESSION_BODY_BYTES:
        try:
            anchor = _conversation_anchor(json.loads(data))
            encoded = json.dumps(
                anchor,
                sort_keys=True,
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        except (ValueError, UnicodeError, RecursionError):
            anchor = None
    if anchor is not None:
        digest = hmac.new(scope.encode("utf-8"), encoded, hashlib.sha256).hexdigest()
        session = f"multillm_v1_{digest}"
    else:
        # No conversation evidence: isolate this logical request, not the fleet.
        session = f"multillm_request_{uuid.uuid4()}"
    result["X-Opencode-Session"] = session
    return result
