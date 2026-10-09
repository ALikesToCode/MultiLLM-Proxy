"""Delayed, two-attempt auto dispatch with separate durable usage ownership."""
from __future__ import annotations

import json
import logging
import math
import os
import re
import threading
import time
import uuid
from dataclasses import dataclass, replace

from flask import Response, copy_current_request_context, current_app, g, has_request_context, request

from error_handlers import APIError
from services import request_accounting as accounting, reservation_store
from services.budget_service import BudgetService, budgeted
from services.generation_deadline import Deadline, GenerationDeadlineExceeded, current_deadline
from services.idempotency_store import idempotency_enabled
from services.request_cancellation import CancellationContext, RequestCancellation, bind_cancellation

logger = logging.getLogger(__name__)
_warned: set[str] = set()
_warning_lock = threading.Lock()
_FIELDS = {"enabled", "delay_ms", "max_duplicates", "idempotent_safe"}


def _warn(name):
    with _warning_lock:
        if name in _warned:
            return
        _warned.add(name)
    logger.warning("Invalid %s; hedged requests disabled", name)


@dataclass(frozen=True)
class HedgePolicy:
    enabled: bool = False
    delay_ms: int = 150
    max_duplicates: int = 2
    idempotent_safe: bool = False


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate field")
        result[key] = value
    return result


def route_policy(route_id):
    flag = os.environ.get("HEDGED_REQUESTS_ENABLED", "").strip().lower()
    if flag in {"", "0", "false", "no", "off"}:
        return None
    if flag not in {"1", "true", "yes", "on"}:
        _warn("HEDGED_REQUESTS_ENABLED")
        return None
    try:
        raw = os.environ.get("HEDGED_REQUESTS_POLICY_JSON", "").strip() or "{}"
        if len(raw) > 65536:
            raise ValueError("Policy too large")
        document = json.loads(raw, object_pairs_hook=_unique_object)
        if not isinstance(document, dict) or len(document) > 256:
            raise ValueError("Invalid policy map")
        policies = {}
        for name, value in document.items():
            if (not re.fullmatch(r"auto:[A-Za-z0-9][A-Za-z0-9._:/+-]{0,255}", name)
                    or not isinstance(value, dict) or set(value) - _FIELDS):
                raise ValueError("Invalid route policy")
            policy = HedgePolicy(**value)
            if (type(policy.enabled) is not bool or type(policy.idempotent_safe) is not bool
                    or type(policy.delay_ms) is not int or not 1 <= policy.delay_ms <= 1000
                    or type(policy.max_duplicates) is not int or policy.max_duplicates != 2):
                raise ValueError("Invalid bounds")
            policies[name] = policy
        policy = policies.get(route_id)
        return policy if policy and policy.enabled and policy.idempotent_safe else None
    except (ValueError, TypeError, RecursionError):
        _warn("HEDGED_REQUESTS_POLICY_JSON")
        return None


@dataclass(frozen=True)
class HedgeResult:
    response: Response
    model: str
    position: int
    attempts: int
    failures: list[tuple[str, str]]


def _eligible(payload):
    if not has_request_context() or request.method != "POST" or request.path != "/v1/chat/completions":
        return False
    if (payload.get("stream") or any(name in payload for name in ("tools", "tool_choice", "functions", "function_call"))
            or not request.headers.get("Idempotency-Key") or not idempotency_enabled()
            or getattr(g, "managed_idempotency_claim", None) is None
            or not getattr(g, "managed_idempotency_handed_off", False) or not reservation_store.enabled()
            or request.headers.get("X-MultiLLM-Tool-Repair")):
        return False
    # A missing output bound cannot conservatively reserve a provider generation.
    output_limit = payload.get("max_completion_tokens", payload.get("max_tokens"))
    if type(output_limit) is not int or output_limit <= 0 or payload.get("n", 1) != 1:
        return False
    from services.managed_turn import current_turn
    turn = current_turn()
    if turn is not None and turn.paging is not None:
        return False
    context = getattr(g, "usage_context", None)
    user = getattr(g, "authenticated_user", None) or {}
    return isinstance(context, accounting.UsageContext) and bool(context.reservation) and budgeted(user)


def _expires_at(models, clock):
    deadline = current_deadline()
    now = clock()
    values = [deadline.expires_at] if deadline else []
    for name in ("cascade_deadline", "gateway_generation_deadline"):
        value = getattr(g, name, None)
        if type(value) in (int, float) and math.isfinite(value):
            values.append(value)
    timeouts = current_app.config.get("API_TIMEOUTS", {})
    for model in models:
        timeout = timeouts.get(model.split(":", 1)[0], timeouts.get("default", (5, 60)))
        seconds = sum(timeout) if isinstance(timeout, (tuple, list)) else timeout
        values.append(now + min(300, max(0.001, float(seconds))))
    return min(values)


def _prepare_holds(models, payload):
    outer = g.usage_context
    output_tokens = payload.get("max_completion_tokens", payload.get("max_tokens"))
    costs = [accounting.reservation_price([model], outer.input_tokens, output_tokens, 1) for model in models]
    if any(cost is None for cost in costs):
        raise APIError("Configure both candidate prices before hedging this route.", 503,
                       {"error": "unpriced_reservation"})
    try:
        held = reservation_store.get_store().get(outer.reservation)
    except reservation_store.ReservationError as error:
        raise APIError("The durable usage reservation is unavailable.", 503,
                       {"error": error.code}) from error
    if held["state"] != "reserved" or held["estimate_usd"] < costs[0]:
        return None
    decision = BudgetService.check_and_reserve(g.authenticated_user, costs[1])
    if not decision.allowed:
        if decision.error == "budget_exceeded":
            return None
        raise APIError(decision.message, decision.status_code, {"error": decision.error})
    if decision.reservation is None:
        return None
    return [outer.reservation, decision.reservation]


def _useful_response(response):
    from services.managed_turn import completed_envelope
    from services.stream_preflight import _InvalidStream, _delta_useful
    if response.status_code != 200 or response.is_streamed or response.mimetype != "application/json":
        return False
    raw = response.get_data()
    if len(raw) > 1024 * 1024:
        return False
    try:
        body = json.loads(raw)
        if not completed_envelope(body):
            return False
        choices = body.get("choices")
        return isinstance(choices, list) and bool(choices) and all(
            _delta_useful(choice["message"])
            and not choice["message"].get("tool_calls") and not choice["message"].get("function_call")
            for choice in choices)
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, _InvalidStream):
        return False


class _Attempt:
    def __init__(self, model, position, hold, outer, expires, clock, changed):
        self.model, self.position = model, position
        self.context = replace(outer, models=[model], selected=model, reservation=hold,
                               finished=False, ambiguous=False, output_tokens=outer.output_tokens)
        self.owner = RequestCancellation()
        self.deadline = Deadline(expires, clock)
        self.stopped = threading.Event()
        self.decision = threading.Event()
        self.bridge = CancellationContext(self.cancel)
        self.changed = changed
        self.submissions = 0
        self.started = False
        self.dispatched_at = None
        self.accepted = False
        self.response = None
        self.error = None
        self.usage = None
        self.upstreams = []
        self.useful = False
        self.reason = "interrupted"
        self.lease = None
        self.thread = None

    def cancel(self, error=None):
        self.stopped.set()
        self.owner.cancel()
        with self.changed:
            self.changed.notify_all()

    def before_submission(self):
        if self.submissions or self.stopped.is_set():
            raise APIError("A hedged attempt cannot submit another generation.", 503,
                           {"error": "hedged_submission_exhausted"})
        self.deadline.check()
        if self.lease is not None:
            self.lease.check()
        self._dispatch_started()
        self.submissions += 1

    def _dispatch_started(self):
        try:
            BudgetService.mark_dispatched(self.context.reservation)
        except reservation_store.ReservationError as error:
            raise APIError("The durable dispatch boundary is unavailable.", 503,
                           {"error": error.code}) from error
        self.bridge.handoff()
        with self.changed:
            self.dispatched_at = self.deadline.clock()
            self.changed.notify_all()

    def capture(self, response):
        self.upstreams.append(response)
        bind_cancellation(response)
        self.capture_buffered_usage(response)

    def _buffer(self, response):
        if not response.is_streamed or response.mimetype != "application/json":
            return response
        bind_cancellation(response)
        parts, size = [], 0
        for chunk in response.iter_encoded():
            self.deadline.check()
            if self.stopped.is_set():
                raise APIError("The caller cancelled the request.", 499)
            size += len(chunk)
            if size > 1024 * 1024:
                response.close()
                raise APIError("Hedged response exceeds the validation limit.", 502,
                               {"error": "upstream_response_invalid"})
            parts.append(chunk)
        response.set_data(b"".join(parts))
        return response

    def _observe(self, response):
        self.response = response
        response = self._buffer(response)
        self.useful = _useful_response(response)
        self.reason = "ok" if self.useful else "invalid_response" if response.status_code < 400 else f"http_{response.status_code}"
        self.usage = accounting._usage_from(accounting._json_body(response)) or self.usage

    def _settle(self):
        for upstream in self.upstreams:
            self.capture_buffered_usage(upstream)
        # Cancellation is an uncertain outcome, not evidence of zero provider cost.
        self.context.ambiguous = self.usage is None and (self.submissions > 0 or self.bridge.handed_off)
        if not self.bridge.handed_off and not self.submissions:
            BudgetService.settle(self.context.reservation, before_dispatch=True)
            self.context.finished = True
            return
        status = self.response.status_code if self.response is not None else getattr(self.error, "status_code", 502)
        accounting._record(self.context, status, self.usage, None)

    def capture_buffered_usage(self, upstream):
        raw = getattr(upstream, "_content", None)
        if isinstance(raw, bytes) and len(raw) <= 1024 * 1024:
            try:
                self.usage = accounting._usage_from(json.loads(raw)) or self.usage
            except (ValueError, RecursionError):
                pass

    def run(self, dispatch, body, decision, snapshot, turn, affinity, finished):
        from services.managed_dispatch import isolated_managed_attempt
        from services.prompt_cache_affinity import activate_scope
        from services.route_health import RouteHealth
        started = time.monotonic()
        g.__dict__.update(snapshot)
        g.usage_context = self.context
        g.gateway_cancellation = self.owner
        g.generation_deadline = self.deadline
        g.gateway_generation_deadline = g.cascade_deadline = self.deadline.expires_at
        # Worker teardown must not finalize the parent claim or release its lease.
        # The secondary lease is checked and released by this attempt alone.
        g.managed_idempotency_claim = None
        g.gateway_admission_lease = None
        g.hedged_attempt = self
        with isolated_managed_attempt(turn) as local_turn, activate_scope(affinity):
            try:
                self.deadline.check()
                if self.stopped.is_set():
                    raise APIError("The caller cancelled the request.", 499)
                if self.lease is not None:
                    self.lease.check()
                # Managed dispatch signals the actual provider boundary. Injected
                # candidate dispatchers without a managed turn own that boundary.
                if local_turn is None:
                    self._dispatch_started()
                self._observe(dispatch(body, self.model, decision))
                self.deadline.check()
                self.useful = self.useful and not self.stopped.is_set()
            except BaseException as error:
                self.error, self.useful = error, False
                self.reason = "interrupted"
            finally:
                try:
                    RouteHealth.record(self.model, ok=self.useful, latency_ms=(time.monotonic() - started) * 1000,
                                       outcome=self.reason)
                finally:
                    finished(self)
            # Keep finalizers inside this attempt's request context, after selection.
            self.decision.wait()
            try:
                for finalize in local_turn.finalizers if local_turn is not None else ():
                    finalize(self.accepted)
            finally:
                if self.accepted:
                    for context in tuple(self.owner.contexts):
                        context.complete()
                else:
                    self.owner.cancel()
                    if self.response is not None:
                        self.response.close()
                self.deadline.stop()
                try:
                    self._settle()
                finally:
                    if self.lease is not None:
                        self.lease.release()


class _Race:
    def __init__(self, models, payload, holds, expires, clock):
        self.clock, self.expires = clock, expires
        self.changed = threading.Condition()
        self.finished = []
        self.snapshot = dict(g.__dict__)
        self.payload = payload
        self.app = current_app._get_current_object()
        self.parent_owner = getattr(g, "gateway_cancellation", None)
        if self.parent_owner is None:
            self.parent_owner = g.gateway_cancellation = RequestCancellation()
        from services.managed_turn import current_turn
        from services.prompt_cache_affinity import current_scope
        self.turn, self.affinity = current_turn(), current_scope()
        self.original_lease = getattr(g, "gateway_admission_lease", None)
        self.attempts = [_Attempt(model, i, holds[i], g.usage_context, expires, clock, self.changed)
                         for i, model in enumerate(models)]
        # The registrar remains the primary lease's sole release owner.
        for attempt in self.attempts:
            self.parent_owner.bind(attempt.bridge)

    def _finished(self, attempt):
        with self.changed:
            self.finished.append(attempt)
            self.changed.notify_all()

    def _start(self, attempt, dispatch, decision):
        @copy_current_request_context
        def work():
            attempt.run(dispatch, {**self.payload, "model": attempt.model}, decision,
                        self.snapshot, self.turn, self.affinity, self._finished)
        attempt.thread = threading.Thread(target=work, name=f"hedged-auto-{attempt.position}")
        attempt.thread.start()
        attempt.started = True

    def _admit_second(self):
        from services.admission_leases import AdmissionError, AdmissionIdentity, principal_hash
        from services.admission_leases import model_group
        client = self.app.extensions.get("admission_client")
        if client is None or self.clock() >= self.expires:
            return False
        lease = self.original_lease
        identity = getattr(getattr(lease, "lease", lease), "identity", None)
        group = identity.model_group if identity is not None else model_group(self.payload["model"])
        user = self.snapshot.get("authenticated_user") or {}
        deadline_ms = math.floor((time.time() + self.expires - self.clock()) * 1000)
        identity = AdmissionIdentity(principal_hash(user["username"]), group, uuid.uuid4().hex, deadline_ms)
        second = self.attempts[1]
        try:
            second.lease = client.acquire(identity, on_lost=second.cancel)
            if second.lease is None:
                return False
            second.lease.check()
            return self.clock() < self.expires and not self.parent_owner.lost and not second.stopped.is_set()
        except AdmissionError:
            return False

    def _select(self, policy, dispatch, decision):
        self._start(self.attempts[0], dispatch, decision(0))
        considered_second = False
        while True:
            with self.changed:
                if self.parent_owner.lost:
                    raise APIError("The caller cancelled the request.", 499, {"error": "cancelled"})
                if self.clock() >= self.expires:
                    raise GenerationDeadlineExceeded()
                winner = next((attempt for attempt in self.finished if attempt.useful), None)
                if winner is not None:
                    return winner
                started = self.attempts[0].dispatched_at
                if started is None and self.attempts[0] in self.finished:
                    return self.attempts[0]
                due = started + policy.delay_ms / 1000 if started is not None else None
                if due is not None and due >= self.expires:
                    considered_second = True
                if considered_second and len(self.finished) == sum(attempt.started for attempt in self.attempts):
                    return self.finished[-1]
                remaining = self.expires - self.clock()
                if not considered_second and due is not None and self.clock() >= due:
                    considered_second = True
                else:
                    self.changed.wait(min(remaining, max(0, due - self.clock()))
                                      if not considered_second and due is not None else remaining)
                    continue
            # Shared admission decides immediately; never enqueue or retry acquisition.
            if self._admit_second():
                with self.changed:
                    complete = any(attempt.useful for attempt in self.finished)
                if not complete:
                    self._start(self.attempts[1], dispatch, decision(1))

    def execute(self, policy, dispatch, decision):
        selected = None
        try:
            if self.original_lease is not None:
                self.original_lease.check()
            selected = self._select(policy, dispatch, decision)
            if self.original_lease is not None:
                self.original_lease.check()
            if self.parent_owner.lost:
                raise APIError("The caller cancelled the request.", 499, {"error": "cancelled"})
            if self.clock() >= self.expires:
                raise GenerationDeadlineExceeded()
            selected.accepted = selected.useful
        finally:
            for attempt in self.attempts:
                if not attempt.accepted:
                    attempt.bridge.cancel()
                attempt.decision.set()
            for attempt in self.attempts:
                if attempt.thread is not None and attempt.started:
                    attempt.thread.join()
                elif not attempt.started:
                    BudgetService.settle(attempt.context.reservation, before_dispatch=True)
                    if attempt.lease is not None:
                        attempt.lease.release()
        if selected.error is not None:
            raise selected.error
        if selected.response is None:
            raise APIError("Hedged candidates did not return a complete response.", 502,
                           {"error": "upstream_response_invalid"})
        if selected.response.status_code < 400 and not selected.useful:
            selected.response = Response(json.dumps({"error": {"code": "upstream_response_invalid",
                "message": "Hedged candidates did not return a useful complete response."}}),
                status=502, content_type="application/json")
        failures = [(attempt.model, attempt.reason) for attempt in self.attempts
                    if attempt.started and attempt is not selected and not attempt.useful]
        return HedgeResult(selected.response, selected.model, selected.position,
                           sum(attempt.started for attempt in self.attempts), failures)


def dispatch_hedged_auto(payload, route_id, candidates, *, validate, dispatch, decision):
    """None leaves the existing route loop, response and accounting untouched."""
    policy = route_policy(route_id)
    if policy is None or not _eligible(payload) or len(candidates) < 2:
        return None
    from services import key_controls
    from services.model_cooldown import ModelCooldownCapacity, ModelCooldownExhausted
    models = list(candidates[:2])
    for model in models:
        if not key_controls.model_allowed(g.authenticated_user, model):
            return None
        try:
            validate(model)
        except (ModelCooldownExhausted, ModelCooldownCapacity, GenerationDeadlineExceeded):
            raise
        except (APIError, ValueError):
            return None
    deadline = current_deadline()
    clock = deadline.clock if deadline else time.monotonic
    expires = _expires_at(models, clock)
    if expires <= clock():
        raise GenerationDeadlineExceeded()
    holds = _prepare_holds(models, payload)
    if holds is None:
        return None
    # Per-attempt finalizers now own both holds; suppress the aggregate ledger row.
    g.usage_context.finished = True
    return _Race(models, payload, holds, expires, clock).execute(policy, dispatch, decision)
