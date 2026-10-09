"""Exact, principal-scoped context pages with a durable storage boundary."""
from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import logging
import os
import re
import time
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Callable, Mapping

from services.retention_policy import RetentionPolicy

MAX_PAGE_BYTES = 64 * 1024
MAX_SESSION_BYTES = 1024 * 1024
TTL_SECONDS = 3600
PAGE_ID = re.compile(r"cp_[a-f0-9]{32}_[A-Za-z0-9_-]{43}\Z")
TOOL_SCHEMA = {"type": "function", "function": {
    "name": "multillm_context_retrieve", "description": "Retrieve an exact stored historical context page.",
    "parameters": {"type": "object", "properties": {"page_id": {"type": "string"}},
                   "required": ["page_id"], "additionalProperties": False}}}
logger = logging.getLogger(__name__)


class ContextPageError(ValueError):
    def __init__(self, code: str, status: int = 503):
        super().__init__(code)
        self.code = code
        self.status = status


@dataclass(frozen=True)
class PageScope:
    principal: str
    session: str
    revision: str

    def wire(self) -> dict[str, str]:
        values = {"principal": self.principal, "session": self.session, "revision": self.revision}
        if any(not isinstance(value, str) or not value or len(value.encode()) > 256 for value in values.values()):
            raise ContextPageError("context_paging_authority_unavailable")
        return values


@dataclass(frozen=True)
class PagingResult:
    payload: Mapping[str, Any]
    pages: tuple[dict[str, Any], ...] = ()


@dataclass(frozen=True)
class PagingRequest:
    service: ContextPageService
    scope: PageScope
    capabilities: list[str]
    retention_policy: RetentionPolicy
    managed: bool = False

    def eligible(self) -> bool:
        return paging_enabled() and self.managed and self.retention_policy.allows_content and capability_enabled(self.capabilities)


@lru_cache(maxsize=1)
def _warn_invalid_flag() -> None:
    logger.warning("Invalid CONTEXT_PAGING_ENABLED; context paging disabled")


def paging_enabled(env: Mapping[str, str] | None = None) -> bool:
    flag = str((os.environ if env is None else env).get("CONTEXT_PAGING_ENABLED", "")).strip().lower()
    if flag in {"", "0", "false", "no", "off"}:
        return False
    if flag in {"1", "true", "yes", "on"}:
        return True
    _warn_invalid_flag()
    return False


def capability_enabled(capabilities: Any) -> bool:
    return isinstance(capabilities, (list, tuple)) and "multillm_context_retrieve" in capabilities


def encode_group(group: list[dict[str, Any]]) -> bytes:
    try:
        return json.dumps(group, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise ContextPageError("invalid_context_messages", 400) from None


def _complete(group: list[Any]) -> bool:
    pending: set[str] = set()
    seen: set[str] = set()
    for message in group:
        if not isinstance(message, dict) or message.get("role") not in {"user", "assistant", "tool"}:
            return False
        if any(key in message for key in ("function_call", "tool_use", "tool_uses")):
            return False
        calls = message.get("tool_calls", [])
        if not isinstance(calls, list) or (calls and message["role"] != "assistant"):
            return False
        if pending and message["role"] != "tool":
            return False
        for call in calls:
            call_id = call.get("id") if isinstance(call, dict) else None
            if not isinstance(call_id, str) or not call_id or call_id in seen:
                return False
            pending.add(call_id)
            seen.add(call_id)
        if message["role"] == "tool":
            call_id = message.get("tool_call_id")
            if not isinstance(call_id, str) or call_id not in pending:
                return False
            pending.remove(call_id)
    return not pending and bool(group) and group[-1].get("role") in {"assistant", "tool"}


def removable_groups(messages: list[Any], protected_indices: tuple[int, ...] = ()) -> list[tuple[int, int]]:
    starts = [index for index, message in enumerate(messages)
              if isinstance(message, dict) and message.get("role") == "user"]
    return [(start, end) for start, end in zip(starts, starts[1:])
            if not any(start <= index < end for index in protected_indices) and _complete(messages[start:end])]


def page_marker(metadata: Mapping[str, Any]) -> dict[str, str]:
    handle = {key: metadata[key] for key in ("page_id", "sha256", "expires_at")}
    return {"role": "assistant", "content": "[Stored historical context; retrieve explicitly with multillm_context_retrieve]\n"
            + json.dumps(handle, separators=(",", ":"))}


def _metadata(value: Any, body: bytes, now: int) -> dict[str, Any]:
    if (not isinstance(value, dict) or not isinstance(value.get("page_id"), str)
            or not PAGE_ID.fullmatch(value["page_id"]) or value.get("sha256") != hashlib.sha256(body).hexdigest()
            or type(value.get("expires_at")) is not int or not now < value["expires_at"] <= now + TTL_SECONDS
            or value.get("tool_schema") != TOOL_SCHEMA):
        raise ContextPageError("context_page_integrity_failed")
    return {key: copy.deepcopy(value[key]) for key in ("page_id", "sha256", "expires_at", "tool_schema")}


class PrivatePageStore:
    """The authenticated private dispatcher supplies this fixed transport callback."""
    def __init__(self, call: Callable[[dict[str, Any]], dict[str, Any]]):
        self.call = call

    def _request(self, payload):
        try:
            result = self.call(payload)
        except Exception as error:
            status = getattr(error, "status", 503)
            code = getattr(error, "code", "context_paging_unavailable")
            if status not in {400, 403, 404, 413, 503} or not isinstance(code, str) or not re.fullmatch(r"[a-z_]{1,64}", code):
                status, code = 503, "context_paging_unavailable"
            raise ContextPageError(code, status) from None
        if not isinstance(result, dict):
            raise ContextPageError("context_paging_unavailable")
        if isinstance(result.get("error"), dict):
            raise ContextPageError("context_paging_unavailable")
        return result

    def put(self, scope: PageScope, bodies: list[bytes]) -> list[dict[str, Any]]:
        return self._request({"operation": "put", "scope": scope.wire(), "granted": True,
                          "retention_policy": {"mode": "inherit", "enabled": False},
                          "bodies": [base64.b64encode(body).decode() for body in bodies]})["pages"]

    def get(self, scope: PageScope, page_id: str) -> dict[str, Any]:
        return self._request({"operation": "get", "scope": scope.wire(), "page_id": page_id, "granted": True,
                          "retention_policy": {"mode": "inherit", "enabled": False}})


class ContextPageService:
    def __init__(self, store=None, *, clock: Callable[[], float] = time.time):
        self.store = store
        self.clock = clock

    def _call(self, operation: str, *args):
        if self.store is None:
            raise ContextPageError("context_paging_unavailable")
        try:
            return getattr(self.store, operation)(*args)
        except ContextPageError:
            raise
        except Exception:
            # Never log storage exceptions: adapters may include request content.
            raise ContextPageError("context_paging_unavailable") from None

    def page_payload(self, payload: Mapping[str, Any], *, scope: PageScope, capabilities: list[str],
                     target_input_tokens: int, retention_policy: RetentionPolicy, managed: bool = False,
                     protected_indices: tuple[int, ...] = (),
                     estimate_tokens: Callable[[Mapping[str, Any]], int] | None = None) -> PagingResult:
        if not paging_enabled() or not managed or not capability_enabled(capabilities) or not retention_policy.allows_content:
            return PagingResult(payload)
        scope.wire()
        if type(target_input_tokens) is not int or target_input_tokens <= 0:
            raise ContextPageError("context_window_exceeded", 413)
        if estimate_tokens is None:
            from services.context_optimizer import estimate_payload_tokens
            estimate_tokens = estimate_payload_tokens
        if self.store is None:
            raise ContextPageError("context_paging_unavailable")
        if estimate_tokens(payload) <= target_input_tokens:
            return PagingResult(payload)
        view = copy.deepcopy(dict(payload))
        messages = view.get("messages")
        if not isinstance(messages, list):
            raise ContextPageError("invalid_context_messages", 400)
        tools = view.get("tools", [])
        if not isinstance(tools, list) or any(not isinstance(tool, dict) or not isinstance(tool.get("function"), dict) for tool in tools):
            raise ContextPageError("invalid_context_tools", 400)
        if any(tool.get("function", {}).get("name") == "multillm_context_retrieve" for tool in tools if isinstance(tool, dict)):
            raise ContextPageError("context_retrieval_tool_conflict", 400)
        view["tools"] = [*tools, copy.deepcopy(TOOL_SCHEMA)]
        selected: list[tuple[int, int, bytes]] = []
        replacements: dict[int, dict[str, str]] = {}
        removed: set[int] = set()
        now = int(self.clock())
        for start, end in removable_groups(messages, protected_indices):
            body = encode_group(messages[start:end])
            if len(body) > MAX_PAGE_BYTES:
                raise ContextPageError("context_page_limit", 413)
            selected.append((start, end, body))
            if sum(len(item[2]) for item in selected) > MAX_SESSION_BYTES:
                raise ContextPageError("context_session_limit", 413)
            replacements[start] = page_marker({"page_id": "cp_" + "0" * 32 + "_" + "s" * 43,
                "sha256": hashlib.sha256(body).hexdigest(), "expires_at": now + TTL_SECONDS})
            removed.update(range(start + 1, end))
            view["messages"] = [replacements.get(index, message) for index, message in enumerate(messages) if index not in removed]
            if estimate_tokens(view) <= target_input_tokens:
                break
        if estimate_tokens(view) > target_input_tokens or not selected:
            raise ContextPageError("context_window_exceeded", 413)
        stored = self._call("put", scope, [item[2] for item in selected])
        if not isinstance(stored, list) or len(stored) != len(selected):
            raise ContextPageError("context_page_integrity_failed")
        metadata = tuple(_metadata(meta, item[2], now) for meta, item in zip(stored, selected))
        for meta, (start, _, _) in zip(metadata, selected):
            replacements[start] = page_marker(meta)
        view["messages"] = [replacements.get(index, message) for index, message in enumerate(messages) if index not in removed]
        if estimate_tokens(view) > target_input_tokens:
            raise ContextPageError("context_window_exceeded", 413)
        return PagingResult(view, metadata)

    def retrieve(self, scope: PageScope, page_id: str, *, retention_policy: RetentionPolicy,
                 granted: bool = True) -> dict[str, Any]:
        if not paging_enabled():
            raise ContextPageError("context_page_not_found", 404)
        if not granted or not retention_policy.allows_content:
            raise ContextPageError("context_page_forbidden", 403)
        scope.wire()
        if not isinstance(page_id, str) or not PAGE_ID.fullmatch(page_id):
            raise ContextPageError("context_page_not_found", 404)
        result = self._call("get", scope, page_id)
        if not isinstance(result, dict):
            raise ContextPageError("context_page_integrity_failed")
        if type(result.get("expires_at")) is not int or result["expires_at"] <= int(self.clock()):
            raise ContextPageError("context_page_not_found", 404)
        try:
            body = base64.b64decode(result["body_base64"], validate=True)
            messages = json.loads(body)
        except (ValueError, KeyError, TypeError):
            raise ContextPageError("context_page_integrity_failed") from None
        if (len(body) > MAX_PAGE_BYTES or not isinstance(messages, list) or not _complete(messages)
                or result.get("page_id") != page_id or not isinstance(result.get("sha256"), str)
                or not re.fullmatch(r"[a-f0-9]{64}", result["sha256"])
                or not hmac.compare_digest(hashlib.sha256(body).hexdigest(), result["sha256"])):
            raise ContextPageError("context_page_integrity_failed")
        return {"page_id": page_id, "sha256": result["sha256"], "expires_at": result["expires_at"],
                "body_base64": result["body_base64"], "messages": messages}

    def retrieve_tool(self, arguments: Any, **authority) -> dict[str, Any]:
        if not isinstance(arguments, dict) or set(arguments) != {"page_id"}:
            raise ContextPageError("invalid_context_retrieve", 400)
        return self.retrieve(page_id=arguments["page_id"], **authority)
