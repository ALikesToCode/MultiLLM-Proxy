"""Managed attempt scheduling, separate from raw dispatch and normalization."""

import math
import json
import time
from typing import Callable

import requests
from flask import g, has_request_context

from services.retry_advice import parse_retry_advice, retry_advice_settings
from services.upstream_outcome import UpstreamOutcome
from services.upstream_transport import close_retry_response
from services.upstream_outcome import classify_upstream_outcome

Attempt = Callable[[int], requests.Response]
Outcome = Callable[[], UpstreamOutcome]


def execute_managed_attempt(send, model, credential):
    """Capture the actual dispatch credential; headers alone never bind affinity."""
    from services.prompt_cache_affinity import current_scope
    from services.managed_turn import before_provider_submission
    before_provider_submission()
    scope = current_scope()
    if scope is None:
        return send()
    try:
        response = send()
    except BaseException:
        scope.observer(model, credential)(classify_upstream_outcome(transport_failure="interrupted"))
        raise
    return capture_managed_attempt(response, model, credential)


def capture_managed_attempt(response, model, credential):
    from services.prompt_cache_affinity import current_scope
    scope = current_scope()
    if scope is not None:
        observer = scope.observer(model, credential)
        if not 200 <= response.status_code < 300:
            observer(classify_upstream_outcome(response.status_code))
        else:
            response.multillm_affinity_observer = observer
    return response


def _completed_body(body):
    if not isinstance(body, dict) or body.get("error"):
        return False
    if body.get("type") in {"error", "response.failed", "response.incomplete"}:
        return False
    if body.get("status") in {"failed", "incomplete", "cancelled", "in_progress"}:
        return False
    choices = body.get("choices")
    if isinstance(choices, list) and choices:
        return all(isinstance(choice, dict) and choice.get("finish_reason") is not None for choice in choices)
    return body.get("status") == "completed" or (
        body.get("type") == "message" and body.get("stop_reason") is not None)


class ManagedOutcomeIterator:
    """Observe final bytes without changing them or granting another dispatch."""

    def __init__(self, source, callback, *, event_stream, context=None):
        from services.prompt_cache_cost import CacheStreamObserver
        self.source = iter(source)
        self.callback = callback
        self.event_stream = event_stream
        self.context = context
        self.usage = CacheStreamObserver(65536)
        self.buffer = b""
        self.oversized = False
        self.complete = False
        self.failed = False
        self.closed = False

    def __iter__(self):
        return self

    def _event(self, line):
        if line.startswith(b"event:"):
            self.failed |= line[6:].strip() in {b"error", b"response.failed", b"response.incomplete"}
        if not line.startswith(b"data:"):
            return
        data = line[5:].strip()
        if data == b"[DONE]":
            self.complete = True
            return
        try:
            body = json.loads(data)
        except (ValueError, RecursionError):
            return
        if not isinstance(body, dict):
            return
        self.failed |= bool(body.get("error")) or body.get("type") in {
            "error", "response.failed", "response.incomplete"}
        self.complete |= _completed_body(body) or body.get("type") in {"message_stop", "response.completed"}

    def _feed(self, chunk):
        self.usage.feed(chunk)
        if not self.event_stream:
            if len(self.buffer) + len(chunk) <= 1024 * 1024 and not self.oversized:
                self.buffer += chunk
            else:
                self.buffer, self.oversized = b"", True
            return
        for index, part in enumerate(chunk.split(b"\n")):
            if index:
                if not self.oversized:
                    self._event(self.buffer.strip())
                self.buffer, self.oversized = b"", False
            if len(self.buffer) + len(part) <= 65536 and not self.oversized:
                self.buffer += part
            else:
                self.buffer, self.oversized = b"", True

    def _finish(self, outcome):
        if self.closed:
            return
        self.closed = True
        owned = getattr(self.context, "outcome", None)
        if owned is not None and owned.reason != "complete":
            outcome = owned.upstream
        self.callback(outcome, self.usage.finish())

    def _exhausted(self):
        if self.event_stream and not self.oversized:
            self._event(self.buffer.strip())
        if not self.event_stream and not self.oversized:
            try:
                body = json.loads(self.buffer)
                self.complete = _completed_body(body)
                from services.prompt_cache_cost import CacheObservation
                self.usage.observation = CacheObservation.from_body(body)
            except (ValueError, RecursionError):
                self.complete = False
        outcome = classify_upstream_outcome(200) if self.complete and not self.failed else classify_upstream_outcome(
            transport_failure="interrupted")
        self._finish(outcome)

    def __next__(self):
        if self.closed:
            raise StopIteration
        try:
            chunk = next(self.source)
        except StopIteration:
            self._exhausted()
            raise
        except BaseException:
            self._finish(classify_upstream_outcome(transport_failure="interrupted"))
            raise
        self._feed(chunk.encode("utf-8") if isinstance(chunk, str) else chunk)
        return chunk

    def close(self):
        # The existing Flask owner closes the body while reporting upstream EOF.
        owned = getattr(self.context, "outcome", None)
        if owned is not None and owned.reason == "complete":
            self._exhausted()
        else:
            self._finish(classify_upstream_outcome(cancelled=True))
        close = getattr(self.source, "close", None)
        if close is not None:
            close()


def observe_managed_response(downstream, upstream, *, stream=False):
    """Deliver classified final outcomes through the managed-dispatch callback."""
    from services.managed_turn import defer_affinity_response
    if defer_affinity_response(downstream, upstream, stream=stream):
        return downstream
    callback = getattr(upstream, "multillm_affinity_observer", None)
    if callback is None:
        return downstream
    if not 200 <= downstream.status_code < 300:
        callback(classify_upstream_outcome(downstream.status_code))
        return downstream
    event_stream = stream or downstream.mimetype == "text/event-stream"
    if event_stream or downstream.is_streamed:
        observer = ManagedOutcomeIterator(downstream.response, callback, event_stream=event_stream,
                                          context=getattr(upstream, "multillm_cancellation", None))
        downstream.response = observer
        downstream.call_on_close(observer.close)
    else:
        from services.prompt_cache_cost import CacheObservation
        try:
            body = json.loads(downstream.get_data())
        except (ValueError, RecursionError):
            body = None
        classified = classify_upstream_outcome(200) if _completed_body(body) else classify_upstream_outcome(
            transport_failure="interrupted")
        callback(classified, CacheObservation.from_body(body))
    return downstream


def retry_managed_attempt(
    attempt: Attempt,
    outcome: Outcome,
    *,
    retry_count: int,
    max_retries: int,
    retry_delay: float,
    response: requests.Response | None = None,
    deadline: float | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> requests.Response | None:
    """Dispatch again only under the existing transport's replay permission.

    A supplied deadline is monotonic. The existing cascade deadline is used when
    available; absent one, per-attempt timeouts remain the transport's policy.
    None means that the original response/error must finish normally.
    """
    classified = outcome()
    if not classified.replay_permission or retry_count >= max_retries:
        return None
    settings = retry_advice_settings()
    delay = retry_delay * (retry_count + 1)
    if settings.enabled:
        if response is not None:
            advice = parse_retry_advice(
                response.headers,
                now=time.time(),
                status_code=response.status_code,
                max_seconds=settings.max_seconds,
            )
            if advice is not None:
                delay = max(delay, advice.delay_seconds)
        if deadline is None and has_request_context():
            deadline = getattr(g, "cascade_deadline", None)
        if deadline is not None:
            if not math.isfinite(deadline) or delay >= deadline - time.monotonic():
                return None
            # Keep the original response usable if scheduling consumes the budget.
            sleep(delay)
            if time.monotonic() >= deadline:
                return None
            if response is not None:
                close_retry_response(response)
            return attempt(retry_count + 1)
    if response is not None:
        close_retry_response(response)
    sleep(delay)
    return attempt(retry_count + 1)
