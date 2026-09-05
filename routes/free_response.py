"""Validate free-pool responses before selection; never replay a visible stream."""

import json
import time
from itertools import chain

import requests
from flask import Response

from route_helpers import copy_raw_provider_response_headers, stream_upstream_response
from services.free_json_contract import check_json_output, json_output_requested
from streaming.sse import format_sse_data, iter_sse_events

_AIHUBMIX_QUOTA_PREFIX = (
    "sorry, to prevent abuse of free resources, accounts that have not been "
    "recharged can only try 10 times."
)


class FreeUpstreamFailure(Exception):
    def __init__(self, status: int = 502):
        self.status = status


def _checked_chunks(response, deadline, limit=8 * 1024 * 1024):
    size = 0
    for chunk in response.response:
        size += len(chunk)
        if size > limit or time.monotonic() > deadline:
            raise FreeUpstreamFailure()
        yield chunk


def _event_payload(event):
    try:
        payload = json.loads(event.data)
    except ValueError as error:
        raise FreeUpstreamFailure() from error
    if not isinstance(payload, dict):
        raise FreeUpstreamFailure()
    if "error" in payload:
        upstream_error = payload["error"]
        code = upstream_error.get("code") if isinstance(upstream_error, dict) else None
        raise FreeUpstreamFailure(429 if str(code) == "429" else 502)
    choices = payload.get("choices")
    if not isinstance(choices, list) or any(not isinstance(c, dict) for c in choices):
        raise FreeUpstreamFailure()
    return payload


def _quota_text(provider, content):
    if provider != "aihubmix" or not isinstance(content, str):
        return ""
    text = " ".join(content.lower().split())
    if text.startswith(_AIHUBMIX_QUOTA_PREFIX):
        raise FreeUpstreamFailure(429)
    return text


def _initial_events(events, provider):
    first = next(event for event in events if event.data)
    if first.is_done or not _event_payload(first).get("choices"):
        raise FreeUpstreamFailure()
    if provider != "aihubmix":
        return [first]

    # AIHubMix can report exhausted free access as assistant text with HTTP 200.
    # Hold only its ambiguous prefix before committing the downstream stream;
    # other providers and ordinary answers retain their normal streaming path.
    buffered = []
    content = ""
    size = 0
    for event in chain([first], events):
        buffered.append(event)
        size += len(event.data.encode())
        if size > 64 * 1024 or len(buffered) > 256:
            raise FreeUpstreamFailure()
        if event.is_done:
            return buffered
        if not event.data:
            continue
        payload = _event_payload(event)
        finished = False
        for choice in payload["choices"]:
            delta = choice.get("delta") or {}
            if not isinstance(delta, dict):
                raise FreeUpstreamFailure()
            value = delta.get("content") or delta.get("refusal") or ""
            if not isinstance(value, str):
                raise FreeUpstreamFailure()
            content += value
            finished = finished or choice.get("finish_reason") is not None
        text = _quota_text(provider, content)
        if finished or (text and not _AIHUBMIX_QUOTA_PREFIX.startswith(text)):
            return buffered
    raise FreeUpstreamFailure()


def _stream_response(response, deadline, on_failure, provider):
    events = iter_sse_events(_checked_chunks(response, deadline))
    # Ignore heartbeats until the provider actually starts a completion. The
    # transport read timeout and whole-response byte/deadline bounds still apply.
    try:
        buffered = _initial_events(events, provider)
        events = chain(buffered, events)
    except (StopIteration, ValueError, requests.RequestException) as error:
        response.close()
        raise FreeUpstreamFailure() from error
    except FreeUpstreamFailure:
        response.close()
        raise

    def generate():
        finished = False
        visible = False
        try:
            event = next(events)
            while True:
                if event.is_done:
                    if not finished or not visible:
                        raise FreeUpstreamFailure()
                    yield format_sse_data("[DONE]")
                    return
                if event.data:
                    payload = _event_payload(event)
                    for choice in payload["choices"]:
                        delta = choice.get("delta") or {}
                        if not isinstance(delta, dict):
                            raise FreeUpstreamFailure()
                        visible = visible or bool(
                            delta.get("content") or delta.get("refusal")
                        )
                        finished = finished or choice.get("finish_reason") is not None
                    yield format_sse_data(event.data)
                else:
                    yield ": free-route-keepalive\n\n"
                event = next(events)
        except (
            StopIteration,
            ValueError,
            FreeUpstreamFailure,
            requests.RequestException,
        ) as error:
            if on_failure is not None:
                on_failure(
                    error.status if isinstance(error, FreeUpstreamFailure) else 502
                )
            yield format_sse_data(
                json.dumps(
                    {
                        "error": {
                            "code": "free_stream_interrupted",
                            "message": "The selected provider stream failed. No other model was appended; retry the request.",
                        }
                    }
                )
            )
        finally:
            response.close()

    downstream = Response(
        generate(),
        content_type="text/event-stream",
        headers=copy_raw_provider_response_headers(response.headers),
    )
    downstream.call_on_close(response.close)
    return downstream


def _checked_json_stream(response, response_format, deadline):
    """Hold structured output until JSON is complete, so invalid output can fail over."""
    try:
        body = b"".join(
            chunk.encode() if isinstance(chunk, str) else chunk
            for chunk in _checked_chunks(response, deadline)
        )
        answers = {}
        refusals = set()
        for event in iter_sse_events([body]):
            if not event.data or event.is_done:
                continue
            for choice in _event_payload(event)["choices"]:
                index = choice.get("index", 0)
                if type(index) is not int:
                    raise FreeUpstreamFailure()
                delta = choice.get("delta") or {}
                if delta.get("refusal"):
                    refusals.add(index)
                content = delta.get("content") or ""
                if not isinstance(content, str):
                    raise FreeUpstreamFailure()
                answers[index] = answers.get(index, "") + content
        if not answers:
            raise FreeUpstreamFailure()
        for index, content in answers.items():
            if index not in refusals:
                check_json_output(content, response_format)
        downstream = Response(
            body, content_type="text/event-stream", headers=response.headers
        )
        downstream.headers["X-MultiLLM-JSON-Buffered"] = "true"
        return downstream
    except (ValueError, requests.RequestException) as error:
        raise FreeUpstreamFailure() from error
    finally:
        response.close()


def validated_free_response(
    upstream,
    *,
    stream: bool,
    deadline: float,
    on_failure=None,
    provider="",
    response_format=None,
) -> Response:
    response = (
        upstream
        if isinstance(upstream, Response)
        else stream_upstream_response(upstream)
    )
    content_type = response.headers.get("Content-Type", "").split(";")[0].lower()
    if stream:
        if content_type != "text/event-stream":
            response.close()
            raise FreeUpstreamFailure()
        downstream = _stream_response(response, deadline, on_failure, provider)
        if json_output_requested(response_format):
            return _checked_json_stream(downstream, response_format, deadline)
        return downstream
    try:
        body = b"".join(
            chunk.encode() if isinstance(chunk, str) else chunk
            for chunk in _checked_chunks(response, deadline)
        )
        payload = json.loads(body)
        if not isinstance(payload, dict) or "error" in payload:
            raise FreeUpstreamFailure()
        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices:
            raise FreeUpstreamFailure()
        for choice in choices:
            message = choice.get("message") if isinstance(choice, dict) else None
            if not isinstance(message, dict) or not (
                message.get("content") or message.get("refusal")
            ):
                raise FreeUpstreamFailure()
            _quota_text(provider, message.get("content") or message.get("refusal"))
            if json_output_requested(response_format) and not message.get("refusal"):
                check_json_output(message.get("content"), response_format)
        return Response(
            body,
            content_type="application/json",
            headers=copy_raw_provider_response_headers(response.headers),
        )
    except (ValueError, requests.RequestException) as error:
        raise FreeUpstreamFailure() from error
    finally:
        response.close()
