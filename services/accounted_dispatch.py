"""Admission and usage accounting for gateway-owned subrequests."""

import json
import time

from flask import g, request

from error_handlers import APIError
from services import key_controls, request_accounting, telemetry_export
from services.budget_service import BudgetService, budgeted
from services.rate_limit_service import RateLimitService

_ROUTING_FIELDS = ("multillm_model", "multillm_provider", "multillm_route_decision")


def release_outer_accounting() -> None:
    """Subrequests replace the aggregate row and its reservation."""
    context = getattr(g, "usage_context", None)
    if isinstance(context, request_accounting.UsageContext):
        BudgetService.settle(context.reservation)
        g.usage_context = None


def accounted_dispatch(payload: dict, dispatch, *, kind: str, skip_rate: bool = False):
    user = getattr(g, "authenticated_user", None) or {}
    model = payload["model"]
    if not key_controls.model_allowed(user, model):
        raise APIError("This API key is not allowed to use the subrequest model", 403,
                       payload={"error": "model_not_allowed"})
    input_tokens = RateLimitService.estimate_input_tokens(payload)
    output_tokens = RateLimitService.requested_output_tokens(payload) or (700 if kind == "chat" else 0)
    units = payload.get("n", 1) if kind == "images" else 1
    context = request_accounting.UsageContext(
        kind=kind, models=[model], provider=None, user=user, started=time.perf_counter(), start_ns=time.time_ns(),
        input_tokens=input_tokens, output_tokens=output_tokens, units=units,
        trace=telemetry_export.trace_context(request.headers.get("traceparent")))
    request_id = getattr(g, "request_id", None)
    context.request_id = (request_id if isinstance(request_id, str)
                          and request_accounting.REQUEST_ID.fullmatch(request_id) else None)
    context.path = "/v1/chat/completions" if kind == "chat" else "/v1/images/generations"
    if budgeted(user):
        decision = BudgetService.check_and_reserve(
            user, request_accounting.estimate_cost([model], input_tokens, output_tokens, units))
        if not decision.allowed:
            raise APIError(decision.message, decision.status_code, payload={"error": decision.error})
        context.reservation = decision.reservation
    routing = {name: getattr(g, name, None) for name in _ROUTING_FIELDS}
    for name in _ROUTING_FIELDS:
        setattr(g, name, None)
    response = None
    try:
        if not skip_rate:
            decision = RateLimitService.enforce_request(
                provider=model.split(":", 1)[0], user=user, payload_bytes=json.dumps(payload).encode(),
                payload_json=payload, remote_addr=request.remote_addr)
            if not decision.allowed:
                raise APIError(decision.message, decision.status_code, payload={"error": decision.error})
        response = dispatch(payload)
        body = request_accounting._json_body(response)
        context.selected = (response.headers.get("X-MultiLLM-Auto-Selected-Model") or response.headers.get("X-MultiLLM-Model")
                            or getattr(g, "multillm_model", None) or request_accounting._reported_model(body))
        if getattr(g, "cascade_deadline", None) is not None and context.selected:
            response.headers.setdefault("X-MultiLLM-Model", context.selected)
        if response.is_streamed:
            # Reuse terminal-usage sniffing and close-time settlement for final tiers.
            outer = getattr(g, "usage_context", None)
            try:
                g.usage_context = context
                if context.selected:
                    g.multillm_model = context.selected
                response = request_accounting.finish(response)
            finally:
                g.usage_context = outer
        else:
            request_accounting._record(context, response.status_code, request_accounting._usage_from(body),
                                       request_accounting._image_count(body) if kind == "images" else None)
        return response
    except Exception as error:
        if response is not None:
            response.close()
        request_accounting._record(context, getattr(error, "status_code", 502), None, None)
        raise
    finally:
        for name, value in routing.items():
            setattr(g, name, value)
