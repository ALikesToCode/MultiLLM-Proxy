"""Managed protocol preparation and classified finalization."""

from __future__ import annotations

import json
import hashlib
import os
from contextvars import ContextVar
from dataclasses import dataclass, field
from functools import wraps

from flask import Response, current_app, g, has_request_context, request

from services import protocol_extras, session_tiers
from services.generation_deadline import (
    check_deadline,
    current_deadline,
    settlement_information,
)
from services.intelligence_contract import GatewayError
from services.protocol_translation import CHAT, TranslationError, translate_request
from services.upstream_outcome import classify_upstream_outcome


@dataclass
class ManagedTurn:
    source: str
    carrier: protocol_extras.ProtocolIR | None = None
    tier_metadata: dict | None = None
    finalizers: list = field(default_factory=list)
    submitted: bool = False
    canary: object = None
    canary_finalized: bool = False
    paging: object = None
    pages: list = field(default_factory=list)
    paged_candidates: dict = field(default_factory=dict)


_turn: ContextVar[ManagedTurn | None] = ContextVar(
    "managed_dispatch_turn", default=None
)


def current_turn():
    return _turn.get()


def completed_response(response):
    """Only terminal, nonstreaming JSON success is eligible for keyed replay."""
    if (
        response.status_code != 200
        or response.is_streamed
        or response.mimetype != "application/json"
    ):
        return False
    owner = getattr(g, "gateway_cancellation", None)
    if owner is not None and owner.lost:
        return False
    try:
        check_deadline()
        body = response.get_data()
        return len(body) <= 1024 * 1024 and completed_envelope(json.loads(body))
    except (ValueError, RecursionError):
        return False


def completed_envelope(body):
    from services.managed_dispatch import _completed_body

    if not _completed_body(body):
        return False
    if "choices" in body:
        return all(
            isinstance(choice.get("message"), dict)
            and choice.get("finish_reason")
            in {"stop", "end_turn", "stop_sequence", "eos", "tool_calls"}
            for choice in body["choices"]
        )
    if body.get("type") == "message":
        return body.get("stop_reason") in {"end_turn", "stop_sequence", "tool_use"}
    return body.get("status") == "completed"


def idempotency_policy_revision(payload=None):
    """Resolve the concrete policy identity without contacting a provider."""
    from services.auto_route_service import AutoRouteService
    from services.cascade_config import is_cascade
    from services.cascade_service import CascadeService

    payload = payload if payload is not None else request.get_json(silent=True) or {}
    model = payload.get("model")
    if model == "auto:intelligence" or "routing" in payload:
        from routes.intelligence import load_policy

        return load_policy()
    if is_cascade(model):
        cascade = CascadeService.get_route(model)
        return {"cascade": cascade} if cascade is not None else None
    if AutoRouteService.is_auto_route(model):
        route = AutoRouteService.get_route(model)
        return (
            {
                "route": model,
                "candidates": route.candidates,
                "updated_at": route.updated_at,
            }
            if route
            else None
        )
    from services import cache_policy

    policy = cache_policy.resolve_policy(payload)
    return {
        "model": model,
        "policy": cache_policy.policy_digest(policy) if policy is not None else None,
    }


def contract_payload(payload):
    """The body a contract check sees once enabled gateway options are removed."""
    from services import output_schema_validation

    hidden = set()
    from services.context_pages import paging_enabled
    if paging_enabled():
        hidden.add("capabilities")
    if output_schema_validation.enabled(current_app.config):
        hidden.add(output_schema_validation.OPTION)
    if protocol_extras.enabled():
        hidden.add("_multillm")
    if session_tiers.settings().enabled:
        hidden.add("session_tier")
    return {key: value for key, value in payload.items() if key not in hidden}


def _prepare(payload, source):
    turn = current_turn()
    cleaned = payload
    from services.context_pages import prepare_managed_paging, page_managed_candidate
    if turn is not None and turn.paging is None:
        cleaned, turn.paging = prepare_managed_paging(payload)
    tier_enabled = session_tiers.settings().enabled
    if protocol_extras.enabled() and (turn is None or turn.carrier is None):
        # Gateway metadata is not part of the protocol carrier. Validate extras
        # before preparing a session lane or copying a provider request.
        metadata = {
            key: value
            for key, value in cleaned.items()
            if key == "routing" or tier_enabled and key == "session_tier"
        }
        body = {key: value for key, value in cleaned.items() if key not in metadata}
        carrier = protocol_extras.request_to_ir(body, source)
        from routes.unified_bridge import record_conversion

        record_conversion(protocol_extras.managed_request_report(body, source, source))
        cleaned = {
            **protocol_extras.translate_managed_request(body, source, source),
            **metadata,
        }
        if turn is not None:
            turn.carrier = carrier
    cleaned = page_managed_candidate(cleaned, source)
    if tier_enabled and "session_tier" in cleaned:
        if turn is not None:
            turn.tier_metadata = cleaned["session_tier"]
        cleaned = {
            key: value for key, value in cleaned.items() if key != "session_tier"
        }
    return cleaned


def emit_managed_request(
    payload, source, target, *, admitted_fields=(), required_fields=()
):
    """Emit from a retained carrier after dispatch copies and optimization."""
    if not protocol_extras.enabled():
        return translate_request(payload, source, target)
    turn = current_turn()
    if turn is None or turn.carrier is None:
        return protocol_extras.translate_managed_request(
            payload,
            source,
            target,
            admitted_fields=admitted_fields,
            required_fields=required_fields,
        )
    pivot = translate_request(payload, source, CHAT)
    carrier = protocol_extras.ProtocolIR(pivot, turn.carrier.extras)
    return protocol_extras.request_from_ir(
        carrier,
        target,
        admitted_fields=admitted_fields,
        required_fields=required_fields,
    )


def defer_finalization(callback):
    turn = current_turn()
    if turn is None:
        return False
    turn.finalizers.append(callback)
    return True


def defer_affinity_response(downstream, upstream, *, stream=False):
    callback = getattr(upstream, "multillm_affinity_observer", None)
    if callback is None or stream or downstream.mimetype == "text/event-stream":
        return False
    from services.prompt_cache_cost import CacheObservation

    try:
        body = (
            json.loads(downstream.get_data()) if downstream.status_code < 400 else None
        )
    except (ValueError, RecursionError):
        body = None
    usage = CacheObservation.from_body(body)
    return defer_finalization(
        lambda complete: callback(
            classify_upstream_outcome(200)
            if complete and completed_envelope(body)
            else classify_upstream_outcome(transport_failure="interrupted"),
            usage,
        )
    )


def before_provider_submission():
    """Run in the request thread, after cancellation checks and before handoff."""
    check_deadline()
    owner = getattr(g, "gateway_cancellation", None) if has_request_context() else None
    if owner is not None and owner.lost:
        raise GatewayError("cancelled", "The caller cancelled the request.", 499)
    if has_request_context():
        from services.request_accounting import mark_dispatched

        mark_dispatched()
    turn = current_turn()
    if turn is not None:
        turn.submitted = True


def prepare_dispatch_kwargs(kwargs, protocol=CHAT, *, turn=None, scope=None):
    """Annotate only serialized provider bytes after the submission guard."""
    turn = turn or current_turn()
    if scope is None and has_request_context():
        scope = getattr(g, "context_canary_scope", None)
    if turn is None or scope is None:
        return kwargs
    from services.context_canary import ContextCanaryError, prepare_request
    try:
        payload = json.loads(kwargs["data"])
        prepared = prepare_request(payload, os.environ, route=scope["route"],
                                   key_scope=scope["key_scope"], protocol=protocol)
        if prepared.context is None:
            raise ContextCanaryError()
    except (ValueError, TypeError, KeyError, UnicodeError) as error:
        from error_handlers import APIError
        raise APIError("Managed request inspection could not be prepared.", 502,
                       {"error": "context_canary_scan_failed"}) from error
    if turn.canary is not None:
        turn.canary.close()
    turn.canary = prepared.context
    turn.canary_finalized = False
    def abandoned(complete):
        if not turn.canary_finalized:
            prepared.context.close()
    turn.finalizers.append(abandoned)
    return {**kwargs, "data": json.dumps(prepared.payload, ensure_ascii=False).encode("utf-8")}


class _CanaryProviderResponse:
    """Expose scanned bytes to the intelligence exchange before its own settlement."""

    def __init__(self, response, upstream):
        from requests.structures import CaseInsensitiveDict
        self.status_code = response.status_code
        self.headers = CaseInsensitiveDict(response.headers)
        self.response, self.upstream = response, upstream
        self.raw = None

    def iter_content(self, **kwargs):
        yield from self.response.response

    def close(self):
        self.response.close()
        self.upstream.close()


def canary_intelligence_proxy(proxy):
    """Capture opt-in state for the intelligence transport's detached send thread."""
    scope = getattr(g, "context_canary_scope", None)
    turn = current_turn()
    if scope is None or turn is None:
        return proxy
    accounting = getattr(g, "usage_context", None)

    class CanaryProxy:
        def __getattr__(self, name):
            return getattr(proxy, name)

        def make_request(self, **kwargs):
            from services.context_canary import finalize_response
            from services.request_cancellation import bind_cancellation
            from services.upstream_transport import iter_stream_content

            kwargs = prepare_dispatch_kwargs(kwargs, turn=turn, scope=scope)
            upstream = proxy.make_request(**kwargs)
            owner = bind_cancellation(upstream)
            response = Response(iter_stream_content(upstream), status=upstream.status_code,
                                headers=dict(upstream.headers))
            turn.canary_finalized = True
            scanned = finalize_response(response, turn.canary, cancel=owner.cancel, accounting=accounting)
            return _CanaryProviderResponse(scanned, upstream)

    return CanaryProxy()


def finalize_canary_response(turn, response):
    """Capture request owners before response iterators leave the request thread."""
    if turn is None or turn.canary is None or turn.canary_finalized:
        return response
    from services.context_canary import finalize_response
    turn.canary_finalized = True
    owner = getattr(g, "gateway_cancellation", None)
    accounting = getattr(g, "usage_context", None)

    def cancel():
        if owner is not None and not owner.lost:
            owner.cancel()

    return finalize_response(response, turn.canary, cancel=cancel, accounting=accounting,
                             protocol=turn.source)


def capture_submission_guard():
    """Capture request ownership for transport threads and lazy generation."""
    deadline = current_deadline()
    owner = getattr(g, "gateway_cancellation", None) if has_request_context() else None
    context = getattr(g, "usage_context", None) if has_request_context() else None

    def submit():
        if deadline is not None:
            deadline.check()
        if owner is not None and owner.lost:
            raise GatewayError("cancelled", "The caller cancelled the request.", 499)
        if context is not None:
            from services.budget_service import BudgetService

            BudgetService.mark_dispatched(context.reservation)

    return deadline, submit


def prepare_intelligence_selection(parsed, policy, transport, principal):
    """Eligibility, approved lane and affinity ordering share one candidate list."""
    from services.intelligence_policy import select_candidates
    from services.prompt_cache_affinity import make_scope, settings as affinity_settings

    candidates = select_candidates(policy, parsed, transport.config)
    if not has_request_context():
        return candidates, None, None
    turn = current_turn()
    metadata = turn.tier_metadata if turn else None
    payload = parsed.payload
    tier = None
    user = getattr(g, "authenticated_user", None) or {}
    if metadata is not None or affinity_settings()[0]:
        candidates = _eligible_intelligence_candidates(candidates, transport, user)
    if metadata is not None:
        payload, tier = session_tiers.prepare_session_tier(
            {**payload, "session_tier": metadata},
            principal=principal,
            revision=hashlib.sha256(
                json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            candidates=candidates,
            store=current_app.extensions.get("session_tier_store"),
        )
        if tier is not None:
            candidates = select_candidates(
                {**policy, "candidates": candidates},
                parsed,
                transport.config,
                session_tier=tier,
            )
    scope = None
    if not parsed.explicit:
        scope = make_scope(
            principal=[user.get("tenant_id"), user.get("id") or principal],
            session=metadata.get("session", "prefix")
            if isinstance(metadata, dict)
            else "prefix",
            role=[
                user.get("role") or ("admin" if user.get("is_admin") else "user"),
                metadata.get("lane", "default")
                if isinstance(metadata, dict)
                else "default",
            ],
            payload=payload,
            revision=policy,
            route="auto:intelligence",
        )
    if scope is not None:
        order = scope.order_candidates(
            [c["model"] for c in candidates],
            {c["model"]: c.get("quality_tier", 0) for c in candidates},
        )
        indexed = {c["model"]: c for c in candidates}
        candidates = [indexed[model] for model in order]
    return candidates, tier, scope


def _eligible_intelligence_candidates(candidates, transport, user):
    from services import key_controls
    from services.model_cooldown import ModelCooldownCapacity, ModelCooldownExhausted

    eligible = []
    for candidate in candidates:
        if not key_controls.model_allowed(user, candidate["model"]):
            continue
        try:
            if transport.credentials(candidate):
                eligible.append(candidate)
        except (ModelCooldownCapacity, ModelCooldownExhausted):
            continue
    return eligible


def _finish_turn(turn, response):
    response = finalize_canary_response(turn, response)
    complete = (
        completed_response(response)
        if response.mimetype != "text/event-stream"
        else False
    )
    _settle_deadline(response)
    finalizers, turn.finalizers = turn.finalizers, []
    for finish in finalizers:
        finish(complete)
    from services.context_pages import expose_managed_pages
    return expose_managed_pages(response, turn, complete=complete)


def managed_pipeline(dispatch):
    """Place validation outside protocol preparation and classified finalization."""
    from routes.tool_repair import with_managed_output_validation

    @wraps(dispatch)
    def prepared(app, auth, metrics, proxy, payload, *args, **kwargs):
        source = current_turn().source
        from services.context_pages import ContextPageError
        try:
            payload = _prepare(payload, source)
        except ContextPageError as error:
            from error_handlers import APIError
            raise APIError("Context paging could not be completed.", error.status, {"error": error.code}) from error
        except TranslationError as error:
            from routes.protocol_bridge import translation_api_error

            raise translation_api_error(error) from error
        response = dispatch(app, auth, metrics, proxy, payload, *args, **kwargs)
        if getattr(g, "context_canary_scope", None) is not None:
            response = finalize_canary_response(current_turn(), app.make_response(response))
        return response

    validated = with_managed_output_validation(prepared)

    @wraps(dispatch)
    def wrapped(app, auth, metrics, proxy, payload, *args, **kwargs):
        from routes.protocol_bridge import ENDPOINT_PROTOCOLS

        endpoint = kwargs.get("endpoint") or (args[0] if args else None)
        source = ENDPOINT_PROTOCOLS.get(endpoint, CHAT)
        outer = current_turn()
        if outer is not None:
            return validated(app, auth, metrics, proxy, payload, *args, **kwargs)
        turn = ManagedTurn(source)
        token = _turn.set(turn)
        try:
            check_deadline()
            response = app.make_response(
                validated(app, auth, metrics, proxy, payload, *args, **kwargs)
            )
            check_deadline()
            response = _finish_turn(turn, response)
            if request.path == "/intelligence/v1/chat/completions":
                from middleware.idempotency import finish_managed_response

                response = finish_managed_response(
                    response, complete=completed_response(response)
                )
            return response
        except BaseException:
            _settle_deadline()
            for finish in turn.finalizers:
                finish(False)
            raise
        finally:
            _turn.reset(token)

    return wrapped


def with_managed_idempotency(view):
    """Complete the claim outside the cache wrapper, including no-provider hits."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        from middleware.idempotency import dispatch_with_idempotency

        if getattr(g, "managed_idempotency_claim", None) is None:
            return view(*args, **kwargs)
        payload = request.get_json(silent=True) or {}
        if payload.get("model") == "auto:intelligence" or "routing" in payload:
            from middleware.idempotency import finish_managed_response

            response = current_app.make_response(view(*args, **kwargs))
            return finish_managed_response(
                response, complete=completed_response(response)
            )
        return dispatch_with_idempotency(
            lambda: view(*args, **kwargs), completed=completed_response
        )

    return wrapped


def finish_intelligence_response(response):
    from middleware.idempotency import finish_managed_response

    if current_turn() is not None:
        return response
    return finish_managed_response(response, complete=completed_response(response))


def _settle_deadline(response=None):
    """Preserve an uncertain handoff for the existing accounting finalizer."""
    owner = getattr(g, "gateway_cancellation", None)
    context = getattr(g, "usage_context", None)
    if owner is not None and owner.lost and context is not None:
        from services.reservation_store import enabled

        if enabled():
            context.ambiguous = True
    if current_deadline() is None:
        return
    if owner is None:
        return
    usage = None
    if (
        response is not None
        and not response.is_streamed
        and response.mimetype == "application/json"
    ):
        from services.usage_types import UsageObservation

        try:
            usage = UsageObservation.from_body(json.loads(response.get_data()))
        except (ValueError, RecursionError):
            pass
    information = [
        settlement_information(upstream, usage) for upstream in owner.contexts
    ]
    if context is not None and any(item["ambiguous"] for item in information):
        context.ambiguous = True


def check_managed_candidate(model):
    from routes.cascade_deadline import check_candidate

    check_deadline()
    check_candidate(model)


def bounded_managed_timeout(timeout):
    from routes.cascade_deadline import bounded_timeout as cascade_timeout
    from services.generation_deadline import bounded_timeout

    deadline = check_deadline()
    if timeout is None and deadline is not None:
        timeout = (deadline.remaining() / 2, deadline.remaining() / 2)
    return bounded_timeout(cascade_timeout(timeout))


def cache_response_allowed(response):
    if getattr(g, "context_canary_scope", None) is not None:
        return False
    from services.shared_generation_cache import shared_enabled

    from services.semantic_generation_cache import settings as semantic_settings
    from services.context_pages import paging_enabled
    from services.canary_traffic import enabled as canary_enabled
    if (
        not semantic_settings().enabled
        and not paging_enabled()
        and not canary_enabled()
        and getattr(g, "prompt_injection_action", None) is None
        and not shared_enabled()
        and current_deadline() is None
        and getattr(g, "managed_idempotency_claim", None) is None
    ):
        return True
    return completed_response(response)


def preserve_validation_accounting(response, envelope):
    """Keep measured provider spend even when generated content fails its schema."""
    from services import request_accounting, reservation_store
    from services.usage_types import UsageObservation

    if reservation_store.enabled() and UsageObservation.from_body(envelope) is not None:
        _settle_deadline(response)
        request_accounting.finish(response)
