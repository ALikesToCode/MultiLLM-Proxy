"""Apply protocol translation to Flask responses without buffering streams."""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from typing import Any

from flask import Response

from error_handlers import APIError, get_request_id
from providers.protocols import CHAT_COMPLETIONS, MESSAGES, RESPONSES
from route_helpers import stream_upstream_response
from services import protocol_translation as translation
from services.protocol_translation import TranslationError, UpstreamFailure

ENDPOINT_PROTOCOLS = {
    CHAT_COMPLETIONS: translation.CHAT,
    RESPONSES: translation.RESPONSES,
    MESSAGES: translation.MESSAGES,
}
PROTOCOL_ENDPOINTS = {protocol: endpoint for endpoint, protocol in ENDPOINT_PROTOCOLS.items()}
STREAM_HEADERS = {"Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no"}
# Anthropic protocol headers mean nothing to a translated upstream.
ANTHROPIC_REQUEST_HEADERS = frozenset(
    {"anthropic-version", "anthropic-beta", "anthropic-dangerous-direct-browser-access"}
)
_BODY_HEADERS = frozenset(
    {"content-type", "content-length", "transfer-encoding", "content-encoding"}
)


def translation_api_error(error: TranslationError) -> APIError:
    """A 400 whose body is also a valid OpenAI error envelope."""
    return APIError(
        error.message,
        status_code=400,
        payload=translation.openai_error_body(
            400, error.message, "invalid_request_error", "unsupported_parameter", error.param
        ),
    )


def translation_request_headers(headers: Mapping[str, Any]) -> dict[str, Any]:
    return {
        name: value
        for name, value in headers.items()
        if str(name).lower() not in ANTHROPIC_REQUEST_HEADERS
    }


def as_flask_response(upstream: Any) -> Response:
    return upstream if isinstance(upstream, Response) else stream_upstream_response(upstream)


def _carried_headers(response: Response) -> list[tuple[str, str]]:
    return [
        (name, value)
        for name, value in response.headers.items()
        if name.lower() not in _BODY_HEADERS
    ]


def _json_response(payload: Any, status: int, headers: list[tuple[str, str]]) -> Response:
    return Response(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
        status=status,
        headers=headers,
        content_type="application/json",
    )


def _read_body(response: Response) -> bytes:
    try:
        return response.get_data()
    finally:
        response.close()


def _decode(body: bytes) -> Any:
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return body.decode("utf-8", errors="replace")


def failure_response(
    failure: UpstreamFailure,
    target: str,
    headers: list[tuple[str, str]],
    status: int = 502,
) -> Response:
    body = translation.openai_error_body(status, failure.message, failure.error_type, failure.code)
    if target == translation.MESSAGES:
        body = translation.anthropic_error_body(
            status, failure.message, failure.error_type, get_request_id()
        )
    return _json_response(body, status, headers)


def _closing(events: Iterator[str], response: Response) -> Iterator[str]:
    try:
        yield from events
    finally:
        response.close()


def translate_downstream_response(
    upstream: Any,
    *,
    source: str,
    target: str,
    stream: bool,
    model: str | None = None,
    request_payload: Mapping[str, Any] | None = None,
) -> Response:
    """Convert a response from `source` to `target`, keeping status and routing headers.

    Error bodies are re-shaped, streams are translated event by event, and a body
    that arrives in the other mode (JSON for a stream request, or the reverse) is
    replayed or folded so the caller always receives the mode it asked for.
    """
    response = as_flask_response(upstream)
    if source == target:
        return response
    headers = _carried_headers(response)
    status = response.status_code
    if status >= 400:
        body = _decode(_read_body(response))
        return _json_response(
            translation.translate_error(body, status, source, target), status, headers
        )

    event_stream = response.mimetype == "text/event-stream"
    if event_stream and stream:
        events = translation.translate_stream(
            response.iter_encoded(), source, target, model=model, request=request_payload
        )
        downstream = Response(
            _closing(events, response),
            status=status,
            headers=[*headers, *STREAM_HEADERS.items()],
            content_type="text/event-stream",
        )
        downstream.call_on_close(response.close)
        return downstream

    body = _read_body(response)
    try:
        if event_stream:
            payload = translation.aggregate_stream(
                [body], source, target, model=model, request=request_payload
            )
            return _json_response(payload, status, headers)
        decoded = _decode(body)
        if not isinstance(decoded, dict):
            raise APIError("Upstream provider returned a non-JSON response", status_code=502)
        if stream:
            events = translation.completion_stream(
                decoded, source, target, model=model, request=request_payload
            )
            return Response(
                events,
                status=status,
                headers=[*headers, *STREAM_HEADERS.items()],
                content_type="text/event-stream",
            )
        payload = translation.translate_response(
            decoded, source, target, model=model, request=request_payload
        )
    except UpstreamFailure as failure:
        return failure_response(failure, target, headers)
    return _json_response(payload, status, headers)
