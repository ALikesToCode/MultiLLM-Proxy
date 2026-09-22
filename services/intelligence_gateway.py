"""Bounded availability fallback and validated quality escalation for chat."""

import logging
import threading
import time
from email.utils import parsedate_to_datetime

from routes.auto_routes import _is_fallback_response
from services.intelligence_contract import GatewayError
from services.intelligence_output import (
    Usage,
    decode_completion,
    validate_completion,
    visible_completion,
)
from services.intelligence_policy import input_reservation, select_candidates
from services.intelligence_store import IntelligenceStore
from services.intelligence_stream import ChatStream
from services.intelligence_transport import remaining

logger = logging.getLogger(__name__)


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
                parsedate_to_datetime(retry_after)
        except (TypeError, ValueError, OverflowError):
            retry_after = None
    return GatewayError(
        code,
        "The selected provider could not accept the request.",
        status if status in {402, 429} else 502,
        retryable=status == 429,
        retry_after=retry_after,
    )


class ChatGateway:
    def __init__(self, request, policy, transport, principal, request_id, metrics=None):
        self.request, self.policy, self.transport = request, policy, transport
        self.request_id, self.metrics = request_id, metrics
        self.created = int(time.time())
        self.deadline = time.monotonic() + request.deadline_ms / 1000
        self.cancelled = threading.Event()
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
        try:
            for candidate in self.candidates:
                remaining(self.deadline, self.cancelled)
                if self.attempts >= self.request.max_attempts:
                    break
                if (
                    stronger_than is not None
                    and candidate.get("quality_tier", 0) <= stronger_than
                ):
                    continue
                token = self.transport.credential(candidate)
                if not token:
                    continue
                payload, reserved = self._attempt_payload(candidate)
                self.selected = candidate
                if stronger_than is not None:
                    self.escalations += 1
                    self.reason = "quality_escalation"
                    stronger_than = None
                started = time.monotonic()
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
                    if _is_fallback_response(head):
                        final_status = head.status_code
                        self.unresolved = False
                        last_error = rejection(head)
                        if self.request.explicit:
                            break
                        if not self.escalations:
                            self.reason = "availability_fallback"
                        continue
                    if head.status_code != 200:
                        raise rejection(head)
                    try:
                        yield from self._completion(candidate, reserved)
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
                    self._record(candidate, final_status, started)
            raise last_error
        finally:
            self.settle()

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

    def _completion(self, candidate, reserved):
        model = candidate["model"]
        if not self.request.payload.get("stream"):
            payload = decode_completion(self.exchange.read())
            self._account(payload.get("usage"), reserved)
            completion = visible_completion(payload, model)
            validate_completion(completion, self.request)
            self.settle()
            self.emitted = True
            yield self.decorate(completion)
            return
        parsed = ChatStream(self.exchange.chunks(), model)
        buffered = []
        gated = bool(self.request.required & {"tools", "json"})
        try:
            for event in parsed.events():
                if gated:
                    buffered.append(event)
                else:
                    self.emitted = True
                    yield self.identify(event)
        except GatewayError:
            if parsed.usage is not None:
                self.usage.add(parsed.usage)
            raise
        self._account(parsed.usage, reserved)
        validate_completion(parsed.completion(), self.request)
        for event in buffered:
            self.emitted = True
            yield self.identify(event)

    def _record(self, candidate, status, started):
        if self.metrics:
            self.metrics.get_instance().track_request(
                provider=candidate["model"].split(":", 1)[0],
                status_code=status,
                response_time=(time.monotonic() - started) * 1000,
                model=candidate["model"],
                route_decision="intelligence",
            )
