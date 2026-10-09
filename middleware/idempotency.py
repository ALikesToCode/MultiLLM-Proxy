"""Named post-authentication idempotency hook and explicit managed dispatch boundary."""
from __future__ import annotations

import logging

from flask import Response, current_app, g, request

from services.idempotency_store import (IdempotencyStore, decode_response, encode_response,
                                        idempotency_enabled, request_fingerprint, unavailable)
from services.intelligence_contract import GatewayError

logger = logging.getLogger(__name__)


def _error_response(error):
    from routes.intelligence import error_response
    return error_response(error)


def _settle(claim, state):
    callback = current_app.extensions.get("managed_idempotency_settlement")
    if callback is not None:
        try:
            callback(claim, state)
        except Exception:
            logger.warning("Managed idempotency settlement collaborator unavailable")


def _status_response(claim):
    if claim.status == "completed":
        response = decode_response(claim.response)
        _settle(claim, "replayed")
        return response
    if claim.status == "pending":
        raise GatewayError("request_in_progress", "The same managed request is still in progress.", 409, retry_after="1")
    if claim.status == "conflict":
        raise GatewayError("idempotency_key_conflict", "The key is already bound to a different request or policy revision.", 422)
    if claim.status == "unknown":
        raise GatewayError("outcome_unknown", "The earlier request may have generated output; it will not be submitted again.", 409)
    return None


def begin_managed_request(payload, revision):
    """Claim once, after auth/policy and before admission or provider work."""
    if not idempotency_enabled() or request.headers.get("Idempotency-Key") is None:
        return None
    if payload.get("stream"):
        raise GatewayError("idempotency_stream_unsupported", "Streaming managed responses do not support idempotency replay.")
    existing = getattr(g, "managed_idempotency_claim", None)
    if existing is not None:
        return None
    from services.retention_policy import request_policy
    retention = request_policy()
    principal = (getattr(g, "authenticated_user", None) or {}).get("username")
    scope, digest = request_fingerprint(principal, request.method, request.path,
                                        request.headers["Idempotency-Key"], payload,
                                        {"policy": revision, "retention": retention.revision, "mode": retention.mode,
                                         "tool_repair": request.headers.get("X-MultiLLM-Tool-Repair", "")})
    store = current_app.extensions.get("managed_idempotency_store")
    if store is None:
        # A keyed enabled request cannot silently run without the registrar.
        raise unavailable()
    claim = store.claim(scope, digest)
    response = _status_response(claim)
    if response is not None:
        return response
    g.managed_idempotency_claim = claim
    g.managed_idempotency_retention = retention
    g.managed_idempotency_handed_off = False
    g.managed_idempotency_finalized = False
    return None


def idempotency_request_hook():
    """Static request-identity collaborator registered before admission."""
    if not idempotency_enabled() or request.method != "POST" or request.headers.get("Idempotency-Key") is None:
        return None
    dedicated = request.path == "/intelligence/v1/chat/completions"
    if not dedicated and request.path != "/v1/chat/completions":
        return None
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return None
    model = payload.get("model", "")
    intelligence = dedicated or model == "auto:intelligence" or "routing" in payload
    managed = intelligence or isinstance(model, str) and model.startswith(("auto:", "cascade:"))
    if not managed:
        return None
    payload = dict(payload)
    if dedicated:
        payload.setdefault("model", "auto:intelligence")
    try:
        if intelligence:
            from routes.intelligence import load_policy
            from services.intelligence_contract import ChatRequest
            policy = load_policy()
            if len(request.get_data(cache=True)) > policy["max_request_bytes"]:
                raise GatewayError("request_too_large", "The intelligence request exceeds the size limit.", 413)
            try:
                ChatRequest.parse(payload, policy)
            except (ValueError, TypeError, AttributeError, OverflowError):
                raise GatewayError("invalid_routing_request", "The request does not satisfy the version-one chat and routing contract.") from None
            g.managed_idempotency_policy = policy
            revision = policy
        else:
            resolver = current_app.extensions.get("managed_idempotency_policy_revision")
            if resolver is None:
                raise unavailable()
            revision = resolver(payload)
            if revision is None:
                raise unavailable()
        return begin_managed_request(payload, revision)
    except GatewayError as error:
        return _error_response(error)
    except Exception:
        return _error_response(unavailable())


def mark_managed_handoff():
    claim = getattr(g, "managed_idempotency_claim", None)
    if claim is None:
        return
    if getattr(g, "managed_idempotency_handed_off", False):
        raise unavailable()
    # Record the dispatch boundary durably before any provider side effect.
    g.managed_idempotency_handed_off = True
    if not current_app.extensions["managed_idempotency_store"].transition(claim, "handoff"):
        raise unavailable()


def finish_managed_response(response, *, complete=False):
    """The caller supplies positive completion proof; errors never become replays."""
    claim = getattr(g, "managed_idempotency_claim", None)
    if claim is None or getattr(g, "managed_idempotency_finalized", False):
        return response
    g.managed_idempotency_finalized = True
    store = current_app.extensions["managed_idempotency_store"]
    retention = g.managed_idempotency_retention
    document = encode_response(response) if complete and retention.allows_content else None
    try:
        if document is not None and store.transition(claim, "complete", response=document):
            _settle(claim, "completed")
            return response
        store.transition(claim, "unknown")
    except GatewayError:
        # A lost completion write cannot grant replay permission. Best-effort
        # ambiguity marking leaves the original pending claim blocked on failure.
        try:
            store.transition(claim, "unknown")
        except GatewayError:
            logger.warning("Managed idempotency finalization unavailable; request remains blocked")
    _settle(claim, "unknown")
    return response


def dispatch_with_idempotency(dispatch, *, completed=None):
    """Inject a managed dispatcher and its completion proof after policy eligibility."""
    try:
        mark_managed_handoff()
    except GatewayError as error:
        return _error_response(error)
    try:
        response = current_app.make_response(dispatch())
    except BaseException:
        finish_managed_response(Response(status=503))
        raise
    proof = completed(response) if completed is not None else False
    return finish_managed_response(response, complete=proof)


def register_idempotency(app, *, store=None, policy_revision=None, settlement=None):
    """Mount through the Flask registrar after retention/secret policy, before admission.

    policy_revision supplies the resolved auto/cascade policy. settlement is an
    explicitly injected usage collaborator and must never authorize generation.
    """
    app.extensions["managed_idempotency_store"] = store or IdempotencyStore()
    if policy_revision is not None:
        app.extensions["managed_idempotency_policy_revision"] = policy_revision
    if settlement is not None:
        app.extensions["managed_idempotency_settlement"] = settlement
    app.extensions.setdefault("gateway_after_authentication", []).append(idempotency_request_hook)

    @app.after_request
    def finalize_managed_failure(response):
        # Success is finalized by the explicit dispatch wrapper, not guessed here.
        return finish_managed_response(response)

    @app.teardown_request
    def abandon_managed_request(error):
        if getattr(g, "managed_idempotency_claim", None) is not None and not getattr(g, "managed_idempotency_finalized", False):
            finish_managed_response(Response(status=503))
