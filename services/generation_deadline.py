"""A request-local generation budget; expiry never grants replay permission."""
from __future__ import annotations

import json
import logging
import math
import os
import re
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from flask import Response, current_app, g, has_request_context, request

from error_handlers import APIError
from services.request_cancellation import RequestCancellation, bind_cancellation

PUBLIC_HEADER = "X-MultiLLM-Deadline-Ms"
INTERNAL_HEADER = "X-MultiLLM-Internal-Deadline-Ms"
DEFAULT_MAX_MS = 300000
logger = logging.getLogger(__name__)
_invalid_max_logged = False


class InvalidGenerationDeadline(APIError):
    def __init__(self):
        super().__init__("Invalid generation deadline", status_code=400)


class GenerationDeadlineExceeded(APIError):
    code = "generation_deadline_exceeded"

    def __init__(self):
        super().__init__("Generation deadline exceeded", status_code=504)


def error_payload():
    return {"error": {"message": "Generation deadline exceeded",
                      "type": "timeout_error", "code": GenerationDeadlineExceeded.code}}


def error_response():
    return Response(json.dumps(error_payload()), status=504, content_type="application/json")


def settlement_information(owner, confirmed_usage=None):
    """Finalizers retain a handoff with no confirmed usage, including clean EOF."""
    return {"ambiguous": bool(owner.handed_off and confirmed_usage is None),
            "usage_state": "unknown" if confirmed_usage is None else "known",
            "usage": confirmed_usage, "replay_permission": False,
            "cancellation_outcome": owner.outcome}


def error_event(protocol="chat"):
    payload = error_payload()
    if protocol == "responses":
        payload = {**payload["error"], "type": "error"}
    elif protocol == "anthropic":
        payload = {"type": "error", "error": {**payload["error"], "type": "api_error"}}
    return ("event: error\ndata: " + json.dumps(payload) + "\n\n").encode()


def _maximum():
    global _invalid_max_logged
    raw = os.environ.get("GENERATION_DEADLINE_MAX_MS", "").strip()
    if not raw:
        return DEFAULT_MAX_MS
    if re.fullmatch(r"[0-9]{1,6}", raw) and 1 <= int(raw) <= DEFAULT_MAX_MS:
        return int(raw)
    if not _invalid_max_logged:
        logger.warning("Invalid GENERATION_DEADLINE_MAX_MS; generation deadlines disabled")
        _invalid_max_logged = True
    return None


def _milliseconds(value, maximum):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,6}", value) or not 1 <= int(value) <= maximum:
        raise InvalidGenerationDeadline()
    return int(value)


@dataclass
class Deadline:
    expires_at: float
    clock: Callable[[], float] = time.monotonic
    _timer: threading.Timer | None = field(default=None, init=False, repr=False)
    _cancellations: list[Callable[[], None]] = field(default_factory=list, init=False, repr=False)
    _expired: bool = field(default=False, init=False, repr=False)

    def expire(self):
        self._expired = True
        for cancel in tuple(self._cancellations):
            cancel()

    def remaining(self):
        return max(0.0, self.expires_at - self.clock())

    def remaining_ms(self):
        # Round down: transport must never increase another machine's budget.
        return max(0, math.floor(self.remaining() * 1000))

    def check(self):
        if self._expired or self.remaining() <= 0:
            self.expire()
            raise GenerationDeadlineExceeded()

    def arm(self, cancel):
        if cancel not in self._cancellations:
            self._cancellations.append(cancel)
        if self._timer is None:
            self._timer = threading.Timer(self.remaining(), self.expire)
            self._timer.daemon = True
            self._timer.start()
        self.check()

    def stop(self):
        if self._timer is not None:
            self._timer.cancel()

    def sleep(self, seconds, sleep=time.sleep):
        self.check()
        if seconds >= self.remaining():
            self.expire()
            raise GenerationDeadlineExceeded()
        sleep(seconds)
        self.check()


def deadline_from_headers(headers: Mapping, *, trusted_internal=False, limits_ms=(), clock=time.monotonic):
    maximum = _maximum()
    if maximum is None:
        return None
    normalized = {key.lower(): value for key, value in headers.items()}
    public = normalized.get(PUBLIC_HEADER.lower())
    internal = normalized.get(INTERNAL_HEADER.lower()) if trusted_internal else None
    if public is None and internal is None:
        return None
    budgets = [_milliseconds(value, maximum) for value in (public, internal) if value is not None]
    budgets.extend(value for value in limits_ms if type(value) is int and value > 0)
    return Deadline(clock() + min(budgets) / 1000, clock)


def forwarded_headers(headers, deadline):
    result = {key: value for key, value in headers.items() if key.lower() != INTERNAL_HEADER.lower()}
    if deadline is not None:
        deadline.check()
        remaining = deadline.remaining_ms()
        if remaining < 1:
            raise GenerationDeadlineExceeded()
        result[INTERNAL_HEADER] = str(remaining)
        # Public relative time must not restart when the receiving host converts it.
        result = {key: value for key, value in result.items() if key.lower() != PUBLIC_HEADER.lower()}
    return result


def current_deadline():
    return getattr(g, "generation_deadline", None) if has_request_context() else None


def check_deadline():
    deadline = current_deadline()
    if deadline is not None:
        deadline.check()
    return deadline


def check_response_deadline(response):
    try:
        check_deadline()
    except GenerationDeadlineExceeded:
        response.close()
        raise


def bounded_timeout(timeout):
    deadline = check_deadline()
    if deadline is None:
        return timeout
    remaining = deadline.remaining()
    if isinstance(timeout, (tuple, list)):
        return tuple(min(value, remaining / len(timeout)) for value in timeout)
    return min(timeout, remaining)


def deadline_sleep(seconds, sleep=time.sleep):
    deadline = current_deadline()
    if deadline is None:
        return sleep(seconds)
    return deadline.sleep(seconds, sleep)


def retry_with_deadline(attempt, outcome, **kwargs):
    from services.managed_dispatch import retry_managed_attempt
    from services.retry_advice import parse_retry_advice, retry_advice_settings
    deadline = current_deadline()
    if deadline is None:
        return retry_managed_attempt(attempt, outcome, **kwargs)
    deadline.check()
    if not outcome().replay_permission or kwargs["retry_count"] >= kwargs["max_retries"]:
        return None
    delay = kwargs["retry_delay"] * (kwargs["retry_count"] + 1)
    settings = retry_advice_settings()
    response = kwargs.get("response")
    if settings.enabled and response is not None:
        advice = parse_retry_advice(response.headers, now=time.time(),
            status_code=response.status_code, max_seconds=settings.max_seconds)
        if advice is not None:
            delay = max(delay, advice.delay_seconds)
    if delay >= deadline.remaining():
        if response is not None:
            bind_cancellation(response).cancel()
        raise GenerationDeadlineExceeded()
    sleep = kwargs.get("sleep", time.sleep)
    kwargs["sleep"] = lambda seconds: deadline.sleep(seconds, sleep)
    result = retry_managed_attempt(attempt, outcome, **kwargs)
    deadline.check()
    return result


def own_upstream(response):
    deadline = current_deadline()
    if deadline is None:
        return response
    context = bind_cancellation(response)
    owner = getattr(g, "gateway_cancellation", None) if has_request_context() else None
    deadline.arm(owner.cancel if owner is not None else context.cancel)
    deadline.arm(context.cancel)
    for name in ("iter_content", "iter_lines"):
        original = getattr(response, name, None)
        if callable(original) and not getattr(response, "multillm_deadline_wrapped", False):
            def guarded(*args, _original=original, **kwargs):
                iterator = iter(_original(*args, **kwargs))
                while True:
                    deadline.check()
                    try:
                        value = next(iterator)
                    except StopIteration:
                        deadline.check()
                        return
                    deadline.check()
                    yield value
            setattr(response, name, guarded)
    response.multillm_deadline_wrapped = True
    deadline.check()
    return response


class DeadlineIterator:
    """Check each read and suppress late completion bytes after cancellation."""
    def __init__(self, source, deadline, upstream, *, protocol="chat", sse=True):
        self.source = iter(source)
        self.deadline = deadline
        self.context = bind_cancellation(upstream)
        self.protocol = protocol
        self.sse = sse
        self.committed = False
        self.closed = False

    def __iter__(self):
        return self

    def __next__(self):
        if self.closed:
            raise StopIteration
        try:
            self.deadline.check()
            value = next(self.source)
            self.deadline.check()
            self.committed = True
            return value
        except GenerationDeadlineExceeded:
            self.close()
            if self.committed and self.sse:
                return error_event(self.protocol)
            raise
        except StopIteration:
            try:
                self.deadline.check()
            except GenerationDeadlineExceeded:
                self.close()
                if self.committed and self.sse:
                    return error_event(self.protocol)
                raise
            self.deadline.stop()
            self.closed = True
            raise
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.deadline.stop()
        self.context.cancel()
        close = getattr(self.source, "close", None)
        if close is not None:
            close()


def generation_deadline_hook():
    """Mount after authentication/identity and before setup or admission work."""
    from services.request_accounting import classify
    if classify() is None or getattr(g, "generation_deadline_initialized", False):
        return None
    g.generation_deadline_initialized = True
    options = current_app.extensions.get("generation_deadline", {})
    try:
        deadline = deadline_from_headers(request.headers,
            trusted_internal=bool(options.get("verify_internal", lambda: False)()),
            limits_ms=options.get("limits_ms", lambda: ())(), clock=options.get("clock", time.monotonic))
    except InvalidGenerationDeadline:
        return Response(json.dumps({"error": {"code": "invalid_generation_deadline",
            "message": "Invalid generation deadline"}}), status=400, content_type="application/json")
    if deadline is not None:
        g.generation_deadline = deadline
        # Existing admission/cascade scheduling consumes the same local deadline.
        g.cascade_deadline = min(getattr(g, "cascade_deadline", deadline.expires_at), deadline.expires_at)
        g.gateway_generation_deadline = min(getattr(g, "gateway_generation_deadline", deadline.expires_at), deadline.expires_at)
        owner = getattr(g, "gateway_cancellation", None)
        if owner is None:
            owner = g.gateway_cancellation = RequestCancellation()
        deadline.arm(owner.cancel)
    return None


def _useful_prefix(prefix):
    text = prefix.decode("utf-8", errors="replace").replace("\r\n", "\n")
    for event in text.split("\n\n")[:-1]:
        data = "\n".join(line[5:].lstrip() for line in event.splitlines() if line.startswith("data:"))
        if not data:
            continue
        try:
            payload = json.loads(data)
        except ValueError:
            continue
        if not isinstance(payload, dict):
            continue
        kind = payload.get("type", "")
        if payload.get("error") or kind == "error" or isinstance(kind, str) and kind.endswith(("delta", "completed", "failed", "stop")):
            return True
        candidates = payload.get("candidates", [])
        if isinstance(candidates, list) and any(
            isinstance(candidate, dict) and isinstance(candidate.get("content"), dict)
            and candidate["content"].get("parts") for candidate in candidates
        ):
            return True
    return False


def _prime_response(response, deadline):
    """Inspect a bounded protocol prefix before headers can be committed."""
    owner = bind_cancellation(response)
    deadline.arm(owner.cancel)
    source = iter(response.iter_encoded())
    prefix = []
    inspected = bytearray()
    sse = response.mimetype == "text/event-stream" and response.status_code < 400
    useful = not sse
    while len(inspected) < 65536:
        deadline.check()
        try:
            chunk = next(source)
        except StopIteration:
            deadline.check()
            break
        deadline.check()
        prefix.append(chunk)
        inspected.extend(chunk[:65536 - len(inspected)])
        useful = not sse or _useful_prefix(inspected)
        if useful:
            break
    if not useful:
        response.close()
        return Response(json.dumps({"error": {"type": "upstream_error", "code": "upstream_stream_invalid",
            "message": "Upstream stream ended without a useful bounded prefix"}}), status=502, content_type="application/json")
    def replay():
        try:
            yield from prefix
            prefix.clear()
            yield from source
        finally:
            source.close()
            response.close()
    downstream = Response(replay(), status=response.status_code, headers=response.headers)
    downstream.call_on_close(response.close)
    return downstream


def deadline_response(response):
    deadline = current_deadline()
    if deadline is None:
        return response
    try:
        deadline.check()
        if not response.is_streamed:
            deadline.stop()
            return response
        if response.mimetype == "text/event-stream" and request.path.endswith("/chat/completions"):
            from services.stream_preflight import preflight_chat_stream
            response = preflight_chat_stream(response).response
            deadline.check()
            if not response.is_streamed:
                deadline.stop()
                return response
        else:
            response = _prime_response(response, deadline)
            if not response.is_streamed:
                deadline.stop()
                return response
        protocol = "responses" if request.path.endswith("/responses") else "anthropic" if request.path.endswith("/messages") else "chat"
        response.response = DeadlineIterator(response.response, deadline, response,
            protocol=protocol, sse=response.mimetype == "text/event-stream")
        deadline.arm(response.response.context.cancel)
        response.call_on_close(response.response.close)
        return response
    except GenerationDeadlineExceeded:
        response.close()
        deadline.stop()
        return error_response()


def register_generation_deadline(app, *, verify_internal=lambda: False, limits_ms=lambda: (), clock=time.monotonic):
    """Register fixed callbacks; verification must authenticate the internal transport."""
    app.extensions["generation_deadline"] = {"verify_internal": verify_internal, "limits_ms": limits_ms, "clock": clock}
    app.extensions.setdefault("gateway_after_authentication", []).append(generation_deadline_hook)
    app.register_error_handler(GenerationDeadlineExceeded, lambda error: error_response())
    app.after_request(deadline_response)
