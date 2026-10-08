"""Authenticated generation identity and deadline for shared Flask admission."""
import math
import time
import uuid

from flask import current_app, g, request

from services.admission_leases import AdmissionIdentity, model_group, principal_hash


def request_identity(settings=None):
    from services.request_accounting import classify
    if classify() is None:
        return None
    body = request.get_json(silent=True) if request.is_json else {}
    body = body if isinstance(body, dict) else {}
    provider = None if request.path.startswith("/v1/") else (
        (request.view_args or {}).get("api_provider") or request.path.strip("/").split("/", 1)[0])
    if provider in {"intelligence", "optimize"}:
        provider = None
    group = model_group(body.get("model"), provider)
    # A principal limit always applies, including to models absent from the map.
    if settings is not None and settings.principal == 0 and not settings.limited(group):
        return None
    requested_model = body.get("model")
    timeout_provider = provider or (
        requested_model.split(":", 1)[0] if isinstance(requested_model, str) and ":" in requested_model else "default")
    timeout = current_app.config.get("API_TIMEOUTS", {}).get(timeout_provider, (5, 60))
    seconds = sum(timeout) if isinstance(timeout, (tuple, list)) else timeout
    if group == "auto:intelligence" or request.path.startswith("/intelligence/") or "routing" in body:
        from services.intelligence_store import IntelligenceStore
        policy = IntelligenceStore.policy()
        routing = body.get("routing") or {}
        proposed = routing.get("deadline_ms") if isinstance(routing, dict) else None
        budget = min(proposed, policy["deadline_ms"]) if type(proposed) is int and proposed > 0 else policy["deadline_ms"]
        seconds = budget / 1000
    seconds = min(86400, max(0.001, seconds))
    now = time.monotonic()
    deadline = min(getattr(g, "cascade_deadline", now + seconds), now + seconds)
    g.gateway_generation_deadline = deadline
    request_id = uuid.uuid4().hex
    g.gateway_admission_request_id = request_id
    wall = time.time()
    deadline_ms = min(int(wall * 1000) + 86_400_000, math.ceil((wall + deadline - now) * 1000))
    return AdmissionIdentity(principal_hash(g.authenticated_user["username"]), group, request_id, deadline_ms)


def bounded_generation_timeout(timeout):
    from flask import has_request_context
    if not has_request_context():
        return timeout
    deadline = getattr(g, "gateway_generation_deadline", None)
    if deadline is None:
        return timeout
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        from services.admission_leases import AdmissionError
        raise AdmissionError()
    if isinstance(timeout, (tuple, list)):
        return tuple(min(value, remaining / 2) for value in timeout)
    return min(timeout, remaining / 2)
