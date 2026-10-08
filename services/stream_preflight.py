"""Validate a bounded Chat SSE prefix before releasing the real stream."""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import requests
from flask import Response
from urllib3.exceptions import ReadTimeoutError

from services.redaction import redact_text

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class StreamPreflightResult:
    response: Response
    validated: bool
    outcome: str


class _InvalidStream(Exception):
    def __init__(self, provider_error: dict[str, str] | None = None):
        self.provider_error = provider_error


def _provider_context(error: Any) -> dict[str, str]:
    if not isinstance(error, dict):
        return {}
    return {
        key: redact_text(error[key])
        for key in ("message", "type", "code")
        if isinstance(error.get(key), str)
    }


def _arguments_useful(function: Any) -> bool:
    if not isinstance(function, dict):
        raise _InvalidStream()
    arguments = function.get("arguments")
    if arguments is not None and not isinstance(arguments, str):
        raise _InvalidStream()
    return bool(arguments)


def _delta_useful(delta: dict) -> bool:
    useful = False
    for key in ("content", "reasoning_content", "reasoning", "thinking"):
        value = delta.get(key)
        if value is not None and not isinstance(value, str):
            raise _InvalidStream()
        if value:
            # JSON permits escaped lone surrogates; they are not valid UTF-8 output.
            value.encode("utf-8")
            useful = True
    if "function_call" in delta and delta["function_call"] is not None:
        useful = _arguments_useful(delta["function_call"]) or useful
    tools = delta.get("tool_calls")
    if tools is not None:
        if not isinstance(tools, list):
            raise _InvalidStream()
        for tool in tools:
            if not isinstance(tool, dict):
                raise _InvalidStream()
            if "function" in tool:
                useful = _arguments_useful(tool["function"]) or useful
    return useful


def _payload_useful(data: str, event: str) -> bool:
    if data.strip() == "[DONE]":
        raise _InvalidStream()
    payload = json.loads(data)
    if not isinstance(payload, dict):
        raise _InvalidStream()
    if "error" in payload or event == "error":
        raise _InvalidStream(_provider_context(payload.get("error", payload)))
    choices = payload.get("choices")
    if not isinstance(choices, list):
        raise _InvalidStream()
    useful = False
    terminal = False
    for choice in choices:
        if not isinstance(choice, dict):
            raise _InvalidStream()
        delta = choice.get("delta")
        terminal = terminal or choice.get("finish_reason") is not None
        if delta is None and choice.get("finish_reason") is not None:
            delta = {}
        if not isinstance(delta, dict):
            raise _InvalidStream()
        useful = _delta_useful(delta) or useful
    if terminal and not useful:
        raise _InvalidStream()
    return useful


class _PrefixParser:
    def __init__(self, max_events: int):
        self.max_events = max_events
        self.events = 0
        self.line = bytearray()
        self.skip_lf = False
        self.data: list[str] = []
        self.event = ""
        self.has_fields = False

    def _dispatch(self) -> bool:
        if not self.has_fields:
            return False
        self.events += 1
        data = "\n".join(self.data)
        if self.event == "error" and not data:
            raise _InvalidStream({})
        useful = _payload_useful(data, self.event) if data.strip() else False
        self.data = []
        self.event = ""
        self.has_fields = False
        if not useful and self.events >= self.max_events:
            raise _InvalidStream()
        return useful

    def _consume_line(self) -> bool:
        line = self.line.decode("utf-8")
        self.line.clear()
        if not line:
            return self._dispatch()
        self.has_fields = True
        if line.startswith(":"):
            return False
        field, _, value = line.partition(":")
        value = value.removeprefix(" ")
        if field == "data":
            self.data.append(value)
        elif field == "event":
            self.event = value
        elif field not in {"id", "retry"}:
            raise _InvalidStream()
        return False

    def feed(self, chunk: bytes) -> bool:
        # Parse bytes before decoding so an uninspected tail cannot invalidate a
        # useful event earlier in the same socket read.
        for byte in chunk:
            if self.skip_lf:
                self.skip_lf = False
                if byte == 10:
                    continue
            if byte in (10, 13):
                self.skip_lf = byte == 13
                if self._consume_line():
                    return True
            else:
                self.line.append(byte)
        return False


class _StreamOwner:
    def __init__(self, response: Response):
        self.response = response
        self.iterator = response.iter_encoded()
        self.closed = False

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        # The Flask response owns its body and callbacks. Close that owner once,
        # including when the replay iterator has never been started.
        for close in (self.iterator.close, self.response.close):
            try:
                close()
            except Exception as error:
                logger.warning("Stream cleanup failed type=%s", type(error).__name__)


class _ReplayStream:
    def __init__(self, owner: _StreamOwner, prefix: list[bytes]):
        self.owner = owner
        self.prefix = prefix

    def __iter__(self) -> Iterator[bytes]:
        try:
            yield from self.prefix
            self.prefix.clear()
            yield from self.owner.iterator
        finally:
            self.close()

    def close(self) -> None:
        self.prefix.clear()
        self.owner.close()


def _read_timeout(error: BaseException) -> bool:
    pending = [error]
    seen: set[int] = set()
    while pending and len(seen) < 16:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, (TimeoutError, requests.exceptions.Timeout, ReadTimeoutError)):
            return True
        pending.extend(item for item in current.args if isinstance(item, BaseException))
        pending.extend(
            item for item in (current.__cause__, current.__context__) if item is not None
        )
    return False


def _failure(owner: _StreamOwner, error: Exception) -> StreamPreflightResult:
    owner.close()
    timeout = _read_timeout(error)
    provider_error = getattr(error, "provider_error", None)
    if provider_error is None:
        # A lazy protocol bridge can raise its typed failure before yielding SSE.
        from services.protocol_translation import UpstreamFailure

        if isinstance(error, UpstreamFailure):
            provider_error = _provider_context({
                "message": error.message, "type": error.error_type, "code": error.code,
            })
    outcome = (
        "upstream_stream_timeout" if timeout else
        "upstream_stream_error" if provider_error is not None else
        "upstream_stream_invalid"
    )
    message = (
        "Upstream stream timed out before useful output." if timeout else
        "Upstream provider reported a stream error." if provider_error is not None else
        "Upstream stream ended without a valid useful prefix."
    )
    body: dict[str, Any] = {"message": message, "type": "upstream_error", "code": outcome}
    if provider_error:
        body["provider_error"] = provider_error
    headers = [
        (name, value) for name, value in owner.response.headers
        if name.lower() not in {
            "content-type", "content-length", "content-encoding", "transfer-encoding",
        }
    ]
    response = Response(
        json.dumps({"error": body}), status=504 if timeout else 502,
        headers=headers, content_type="application/json",
    )
    return StreamPreflightResult(response, False, outcome)


def preflight_chat_stream(
    response: Response, *, max_bytes: int = 65536, max_events: int = 32,
) -> StreamPreflightResult:
    """Inspect one bounded prefix; failures never grant permission to replay a POST."""
    if not 200 <= response.status_code < 300:
        return StreamPreflightResult(response, False, "skipped")
    if max_bytes < 1 or max_events < 1:
        raise ValueError("Stream prefix bounds must be positive")
    owner = _StreamOwner(response)
    prefix: list[bytes] = []
    parser = _PrefixParser(max_events)
    buffered_bytes = 0
    try:
        if response.mimetype != "text/event-stream":
            raise _InvalidStream()
        while buffered_bytes < max_bytes:
            chunk = next(owner.iterator)
            remaining = max_bytes - buffered_bytes
            # Inspect only the bytes inside the bound; a useful event there still
            # validates a socket read that carries more data past it.
            if parser.feed(chunk[:remaining]):
                prefix.append(chunk)
                replay = _ReplayStream(owner, prefix)
                downstream = Response(replay, status=response.status_code, headers=response.headers)
                downstream.call_on_close(replay.close)
                downstream.headers["X-MultiLLM-Stream-Preflight"] = "validated"
                return StreamPreflightResult(downstream, True, "validated")
            if len(chunk) >= remaining:
                raise _InvalidStream()
            if chunk:
                prefix.append(chunk)
                buffered_bytes += len(chunk)
        raise _InvalidStream()
    except Exception as error:
        return _failure(owner, error)
    except BaseException:
        owner.close()
        raise
