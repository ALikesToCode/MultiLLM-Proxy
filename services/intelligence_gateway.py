"""Bounded availability fallback and validated quality escalation for chat."""

import logging
import threading
import time
from datetime import timezone
from email.utils import format_datetime, parsedate_to_datetime

from routes.auto_routes import AUTO_ROUTE_FALLBACK_STATUS_CODES, _is_fallback_response
from services.credential_pool import is_key_rejection
from services.intelligence_contract import GatewayError
from services.intelligence_output import (
    Usage,
    decode_completion,
    validate_completion,
    visible_completion,
    with_thinking_tokens,
)
from services.intelligence_policy import input_reservation, select_candidates
from services.intelligence_store import IntelligenceStore
from services.intelligence_stream import ChatStream
from services.intelligence_transport import remaining
from services.intelligence_tool_repair import IntelligenceToolRepair
from services.route_health import RouteHealth

logger = logging.getLogger(__name__)
# A rate needs this much visible output over this long to say anything about a provider.
MIN_RATE_TOKENS = 16
MIN_RATE_SECONDS = 0.25


def rejection(head):
    status = head.status_code
    code = {
        401: "upstream_authentication",
        402: "payment_required",
        403: "upstream_forbidden",
        404: "upstream_model_unavailable",
        429: "upstream_rate_limited",
    }.get(status, "upstream_error")
    retry_after = head.headers.get("Retry-After", head.headers.get("retry-after"))
    if retry_after:
        try:
            if len(retry_after) > 64:
                raise ValueError("Invalid retry header")
            if not retry_after.isdigit():
                timestamp = parsedate_to_datetime(retry_after)
                if timestamp.tzinfo is None:
                    raise ValueError("Invalid retry date")
                retry_after = format_datetime(
                    timestamp.astimezone(timezone.utc), usegmt=True
                )
        except (TypeError, ValueError, OverflowError):
            retry_after = None
    return GatewayError(
        code,
        "The selected provider could not accept the request.",
        status if status in {402, 429} else 502,
        retryable=status == 429,
        retry_after=retry_after,
    )


def refused_before_output(head):
    """A client-error status arrives before any output: the provider declined the request
    and generated nothing, so the attempt is known to have used no tokens and the next
    candidate may run. A 504 or anything after a successful status is not a refusal; its
    outcome stays unknown and keeps the whole reservation.
    """
    return 400 <= head.status_code < 500


class ChatGateway:
    def __init__(
        self,
        request,
        policy,
        transport,
        principal,
        request_id,
        metrics=None,
        cancelled=None,
    ):
        self.request, self.policy, self.transport = request, policy, transport
        self.request_id, self.metrics = request_id, metrics
        self.created = int(time.time())
        self.deadline = time.monotonic() + request.deadline_ms / 1000
        self.cancelled = cancelled if cancelled is not None else threading.Event()
        self.candidates = select_candidates(policy, request, transport.config)
        if not self.candidates:
            raise GatewayError(
                "no_eligible_model",
                "No reviewed model satisfies this request's eligibility and capability requirements.",
                503,
            )
        self.reservation = IntelligenceStore.reserve(
            principal, request.max_total_tokens, policy
        )
        self.usage = Usage()
        self.attempts = self.escalations = self.consumed = 0
        self.selected = None
        self.reason = "explicit" if request.explicit else "policy"
        self.exchange = None
        self.unresolved = False
        self.emitted = False
        self.finished = False
        self.tool_repair = IntelligenceToolRepair(self)

    def metadata(self):
        model = self.selected["model"] if self.selected else None
        return {
            "version": 1,
            "request_id": self.request_id,
            "selected_provider": model.split(":", 1)[0] if model else None,
            "selected_model": model,
            "attempts": self.attempts,
            "escalations": self.escalations,
            "reason": self.reason,
            "usage_complete": self.usage.complete and not self.unresolved,
        }

    def decorate(self, value):
        identified = self.identify(value) if "choices" in value else value
        return {
            **identified,
            "usage": dict(self.usage.values) or None,
            "multillm": self.metadata(),
        }

    def identify(self, value):
        return {**value, "id": f"chatcmpl-{self.request_id}", "created": self.created}

    def cancel(self):
        self.cancelled.set()
        if self.exchange:
            self.exchange.close()

    def settle(self):
        if self.finished:
            return
        self.finished = True
        if self.unresolved:
            self.usage.complete = False
        IntelligenceStore.settle(
            self.reservation, self.usage.total, self.usage.complete
        )

    def events(self):
        last_error = GatewayError(
            "missing_credentials",
            "No eligible credential is configured or available.",
            503,
        )
        stronger_than = None
        self._key_refused = False
        try:
            for candidate, token, spare_keys in self._attempts():
                self._key_refused = False
                remaining(self.deadline, self.cancelled)
                if self.attempts >= self.request.max_attempts:
                    break
                if (
                    stronger_than is not None
                    and candidate.get("quality_tier", 0) <= stronger_than
                ):
                    continue
                payload, reserved = self._attempt_payload(candidate)
                self.selected = candidate
                if stronger_than is not None:
                    self.escalations += 1
                    self.reason = "quality_escalation"
                    stronger_than = None
                started = time.monotonic()
                answered = None
                # Constructing an exchange performs exactly one submission. No
                # provider retries or implicit classification calls occur inside it.
                self.exchange = self.transport.start(
                    candidate,
                    payload,
                    token,
                    self.deadline,
                    self.cancelled,
                    self.policy["max_response_bytes"],
                )
                self.attempts += 1
                self.unresolved = True
                final_status = 502
                try:
                    head = self.exchange.head()
                    answered = time.monotonic()
                    if _is_fallback_response(head) or refused_before_output(head):
                        final_status = head.status_code
                        self.unresolved = False
                        last_error = rejection(head)
                        # A refused key generated nothing, so the same model may run on the next key.
                        self._key_refused = is_key_rejection(head.status_code)
                        if self.request.explicit and not (self._key_refused and spare_keys):
                            break
                        if not self.escalations:
                            self.reason = "availability_fallback"
                        continue
                    if head.status_code != 200:
                        raise rejection(head)
                    try:
                        yield from self._completion(candidate, reserved, started, payload, token)
                    except ValueError:
                        last_error = GatewayError(
                            "output_validation_failed",
                            "The model output failed the requested JSON or tool contract.",
                            502,
                        )
                        if (
                            self.emitted
                            or self.request.explicit
                            or self.escalations >= self.request.max_escalations
                        ):
                            raise last_error from None
                        stronger_than = candidate.get("quality_tier", 0)
                        # A failed output contract says nothing about availability.
                        final_status = None
                        continue
                    final_status = 200
                    self.settle()
                    if self.request.payload.get("stream"):
                        yield self.decorate(
                            {
                                "id": "chatcmpl-intelligence",
                                "object": "chat.completion.chunk",
                                "model": candidate["model"],
                                "choices": [],
                            }
                        )
                    return
                except GatewayError as error:
                    final_status = error.status
                    raise
                finally:
                    self.exchange.close()
                    self._record(candidate, final_status, started, answered)
            raise last_error
        finally:
            self.settle()

    def _attempts(self):
        """Each candidate with its first usable key; the next key only after a key refusal."""
        for candidate in self.candidates:
            tokens = self.transport.credentials(candidate)
            for index, token in enumerate(tokens):
                yield candidate, token, index + 1 < len(tokens)
                if not self._key_refused:
                    break

    def _attempt_payload(self, candidate):
        prompt = input_reservation(candidate, self.request)
        output = min(
            self.request.output_tokens,
            self.request.max_total_tokens - self.consumed - prompt,
        )
        if output < 1:
            raise GatewayError(
                "token_budget_exhausted",
                "There is insufficient token budget for another generation.",
                429,
            )
        payload = dict(self.request.payload)
        payload["model"] = candidate["model"]
        field = (
            "max_completion_tokens"
            if "max_completion_tokens" in payload
            else "max_tokens"
        )
        payload[field] = output
        if payload.get("stream"):
            payload["stream_options"] = {"include_usage": True}
        return payload, prompt + output

    def _account(self, usage, reserved):
        attempt = Usage()
        attempt.add(usage)
        self.usage.add(usage)
        self.unresolved = False
        self.consumed += (
            attempt.total if attempt.complete else max(reserved, attempt.total)
        )
        if self.consumed > self.request.max_total_tokens:
            raise GatewayError(
                "upstream_budget_violation",
                "The provider reported usage above the reserved request ceiling.",
                502,
            )

    def _completion(self, candidate, reserved, started, payload=None, token=None):
        model = candidate["model"]
        gemini = model.split(":", 1)[0] == "gemini"
        if not self.request.payload.get("stream"):
            decoded = decode_completion(self.exchange.read())
            usage = decoded.get("usage")
            self._account(with_thinking_tokens(usage) if gemini else usage, reserved)
            completion = visible_completion(decoded, model)
            completion = self.tool_repair.completion(
                completion, candidate, payload or self.request.payload, token
            )
            validate_completion(completion, self.request)
            self.settle()
            self.emitted = True
            yield self.decorate(completion)
            return
        parsed = ChatStream(self.exchange.chunks(), model)
        buffered = []
        gated = "json" in self.request.required or (
            "tools" in self.request.required and self.tool_repair.mode == "off"
        )
        first_output = None
        try:
            for event in (
                repaired for original in parsed.events()
                for repaired in self.tool_repair.events(original)
            ):
                if first_output is None and visible(event):
                    first_output = time.monotonic()
                if gated:
                    buffered.append(event)
                else:
                    self.emitted = True
                    yield self.identify(event)
        except GatewayError:
            if not gated:
                for event in self.tool_repair.flush():
                    self.emitted = True
                    yield self.identify(event)
            if parsed.usage is not None:
                self.usage.add(parsed.usage)
            raise
        usage = with_thinking_tokens(parsed.usage) if gemini else parsed.usage
        self._account(usage, reserved)
        if first_output is not None:
            record_speed(model, usage, started, first_output, time.monotonic())
        self.tool_repair.finish_stream(parsed, candidate)
        validate_completion(parsed.completion(), self.request)
        for event in buffered:
            self.emitted = True
            yield self.identify(event)

    def _record(self, candidate, status, started, answered):
        model = candidate["model"]
        if status == 200:
            RouteHealth.record(model, ok=True, outcome="ok", status=200,
                               latency_ms=((answered or time.monotonic()) - started) * 1000)
        elif status is not None and (status in AUTO_ROUTE_FALLBACK_STATUS_CODES or 500 <= status < 600):
            # 499 is the caller leaving and other 4xx are the request's fault: neither is the candidate's.
            RouteHealth.record(model, ok=False, outcome=f"http_{status}", status=status)
        if self.metrics:
            self.metrics.get_instance().track_request(
                provider=candidate["model"].split(":", 1)[0],
                status_code=502 if status is None else status,
                response_time=(time.monotonic() - started) * 1000,
                model=candidate["model"],
                route_decision="intelligence",
            )


def visible(event):
    """Whether a stream event carries output the caller sees, not just a role or a finish."""
    delta = event["choices"][0]["delta"]
    return any(delta.get(key) for key in ("content", "refusal", "audio", "tool_calls"))


def record_speed(model, usage, started, first_output, finished):
    """Feed route health one streamed generation's time to first output and visible rate."""
    tokens = None
    if isinstance(usage, dict) and type(usage.get("completion_tokens")) is int:
        details = usage.get("completion_tokens_details")
        hidden = details.get("reasoning_tokens") if isinstance(details, dict) else None
        tokens = usage["completion_tokens"] - (hidden if type(hidden) is int and hidden >= 0 else 0)
    seconds = finished - first_output
    rate = (
        tokens / seconds
        if tokens is not None and tokens >= MIN_RATE_TOKENS and seconds >= MIN_RATE_SECONDS
        else None
    )
    RouteHealth.record_speed(
        model, ttft_ms=(first_output - started) * 1000, tokens_per_second=rate
    )
