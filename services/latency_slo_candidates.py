"""Read-only reviewed eligibility for early latency admission."""

import json
import os
import sqlite3
from contextlib import closing

from flask import current_app, g, has_request_context

from services.auto_route_service import AutoRouteService
from services.intelligence_contract import ChatRequest, GatewayError
from services.intelligence_policy import select_candidates, validate_policy
from services.judge_routing import judge_candidate_allowed
from services.key_controls import model_allowed
from services.model_precision import configured_preference
from services.sqlite_store import storage_path


def _reviewed_state():
    from services.intelligence_d1_store import using_d1, _store_request
    from services import model_override_d1

    if using_d1():
        # The policy getter may seed state; the authority's read operation never does.
        policy = validate_policy(_store_request("policy", "policy"))
        return policy, dict(model_override_d1.overrides())
    if os.environ.get("CONTROL_PLANE_DATABASE_URL", "").strip():
        return None, {}
    path = storage_path("MODEL_REGISTRY_DB_PATH", "model_registry.sqlite3")
    if not path.is_file():
        return None, {}
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as connection:
        row = connection.execute("SELECT document FROM intelligence_policy WHERE id = 1").fetchone()
        exists = connection.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'model_overrides'").fetchone()
        overrides = dict(connection.execute("SELECT model_id, status FROM model_overrides")) if exists else {}
    return (validate_policy(json.loads(row[0])) if row else None), overrides


def latency_slo_candidate_policy(payload):
    """Unknown policy, translation, precision or approved lane yields no coverage."""
    if not has_request_context() or not isinstance(payload, dict):
        return []
    from services.session_tiers import settings
    from services.managed_turn import contract_payload

    if settings().enabled and "session_tier" in payload:
        # Lane preparation claims a lease. Admission must not duplicate it or guess.
        return []
    try:
        model = payload.get("model")
        if not AutoRouteService.is_auto_route(model):
            return []
        policy, overrides = _reviewed_state()
        if policy is None or not policy["enabled"]:
            return []
        cleaned = contract_payload(payload)
        if request_protocol() != "chat":
            from services.protocol_translation import translate_request
            cleaned = translate_request(cleaned, request_protocol(), "chat")
        generic = model != "auto:intelligence"
        order = AutoRouteService.read_candidates(model) if generic else None
        if generic:
            from services.canary_traffic import enabled as canary_traffic_enabled
            from services.route_health import ordering_settings
            if ordering_settings().mode_for(model) == "health" or canary_traffic_enabled():
                # Choosing a health probe or cohort is a dispatch-time state change.
                return []
            by_model = {item["model"]: item for item in policy["candidates"]}
            # Missing reviewed evidence cannot certify the primary or its alternatives.
            if not order or any(item not in by_model for item in order):
                return []
            policy = {**policy, "candidates": [by_model[item] for item in order]}
            cleaned = {**cleaned, "model": "auto:intelligence"}
        parsed = ChatRequest.parse(cleaned, policy)
        if generic and parsed.profile != "balanced":
            return []
        if parsed.profile != "balanced" and (policy.get("precision_preference") or configured_preference()):
            return []
        user = getattr(g, "authenticated_user", {})
        policy = {**policy, "candidates": [item for item in policy["candidates"]
                   if model_allowed(user, item["model"]) and judge_candidate_allowed(item["model"])]}
        candidates = select_candidates(policy, parsed, current_app.config,
                                       model_status=lambda name: overrides.get(name, "available"),
                                       apply_latency=False)
        return [{"model": item["model"], **({"quality_tier": item["quality_tier"]}
                 if "quality_tier" in item else {})} for item in candidates]
    except (ValueError, TypeError, KeyError, AttributeError, sqlite3.Error, GatewayError):
        return []


def request_protocol():
    from flask import request
    return {"/v1/messages": "messages", "/v1/responses": "responses"}.get(request.path, "chat")


def register_latency_slo_candidates(app):
    app.extensions["latency_slo_candidate_policy"] = latency_slo_candidate_policy
