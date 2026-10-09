"""Owned files, batch lifecycle and explicit asynchronous managed submission."""
from __future__ import annotations

import base64
import json
import re
import time
from functools import wraps

from flask import Response, g, jsonify, request

from error_handlers import APIError
from services import gateway_batches as batches
from services.retention_policy import request_policy, resolve_policy
from services.cost_service import CostService


def batch_error(error):
    return jsonify({"error": {"code": error.code, "message": error.message,
                             **({"line": error.line} if error.line else {})}}), error.status


def require_content():
    if not request_policy().allows_content:
        raise batches.BatchError(400, "retention_conflict", "Zero-content retention cannot persist batch files or requests.")


def spillover_hook():
    if (not batches.enabled() or not batches.flag("BATCH_SPILLOVER_ENABLED") or request.method != "POST"
            or request.path != "/v1/chat/completions" or getattr(g, "gateway_batch_execution", False)
            or request.headers.get("X-MultiLLM-Priority", "").strip().lower() != "batch"
            or "respond-async" not in {v.strip().lower() for v in request.headers.get("Prefer", "").split(",")}):
        return None
    try:
        from route_helpers import _authorize_api_scope
        refused = _authorize_api_scope("chat")
        if refused is not None:
            return refused
        require_content()
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            raise batches.BatchError(400, "invalid_batch", "Send a JSON request with metadata.multillm_budget_usd.")
        metadata = body.get("metadata")
        batches.budget_units(metadata.get("multillm_budget_usd") if isinstance(metadata, dict) else None)
        item = {"custom_id": "request-1", "method": "POST", "url": request.path, "body": body}
        content = (json.dumps(item, ensure_ascii=False) + "\n").encode()
        batches.validate_jsonl(content)
        batches.estimate_item(item)
        stored = batches.call("file_create", owner=g.authenticated_user["username"], filename="spillover.jsonl",
                              content=base64.b64encode(content).decode())
        file_id = stored.get("file", stored).get("id")
        batch = batches.create_batch({"input_file_id": file_id, "endpoint": request.path, "completion_window": "24h",
                                      "metadata": metadata}, g.authenticated_user, **batches.request_identity())
        response = jsonify(batch)
        response.status_code = 202
        response.headers["Location"] = f"/v1/batches/{batch['id']}"
        return response
    except batches.BatchError as error:
        return batch_error(error)


def register_gateway_batch_routes(app) -> None:
    from route_helpers import api_authenticate_only
    if app.extensions.get("gateway_batches_registered"):
        return
    app.extensions["gateway_batches_registered"] = True
    def gate_disabled_routes():
        batch_path = request.path == "/internal/gateway/batch-item" or re.fullmatch(
            r"/v1/(?:files(?:/[^/]+(?:/content)?)?|batches(?:/[^/]+(?:/cancel)?)?)", request.path)
        if batch_path and not batches.enabled():
            return jsonify({"error": {"code": "not_found", "message": "Not found."}}), 404
        return None
    # Gate before the application's authentication redirect and CSRF middleware.
    # This touches only the newly registered endpoints.
    app.before_request_funcs.setdefault(None, []).insert(0, gate_disabled_routes)
    from services.gateway_extensions import register_authenticated_hook
    register_authenticated_hook(app, spillover_hook)

    def guarded(view):
        authenticated = api_authenticate_only(view)
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not batches.enabled():
                return jsonify({"error": {"code": "not_found", "message": "Not found."}}), 404
            try:
                return authenticated(*args, **kwargs)
            except batches.BatchError as error:
                return batch_error(error)
        csrf = app.extensions.get("csrf")
        return csrf.exempt(wrapped) if csrf is not None else wrapped

    @app.route("/v1/files", methods=["GET", "POST", "OPTIONS"])
    @guarded
    def gateway_files():
        owner = g.authenticated_user["username"]
        if request.method == "GET":
            return jsonify(public_reply(batches.call("file_list", owner=owner, **pagination())))
        require_content()
        request.max_content_length = batches.MAX_FILE_BYTES + 65536
        if request.mimetype != "multipart/form-data" or request.form.get("purpose") != "batch":
            raise batches.BatchError(400, "invalid_purpose", "Upload multipart JSONL with purpose=batch.")
        files = request.files.getlist("file")
        if len(files) != 1 or set(request.files) != {"file"}:
            raise batches.BatchError(400, "invalid_file", "Upload exactly one file.")
        data = files[0].read(batches.MAX_FILE_BYTES + 1)
        items = batches.validate_jsonl(data)
        batches.require_item_retention(items, g.authenticated_user, batches.request_identity()["key_hash"])
        return jsonify(batches.call("file_create", owner=owner, filename=(files[0].filename or "input.jsonl")[:255],
                                    content=base64.b64encode(data).decode()).get("file"))

    @app.route("/v1/files/<file_id>", methods=["GET", "DELETE", "OPTIONS"])
    @guarded
    def gateway_file(file_id):
        result = batches.call("file_delete" if request.method == "DELETE" else "file_get",
                              owner=g.authenticated_user["username"], id=file_id)
        return jsonify(result.get("file", public_reply(result)))

    @app.route("/v1/files/<file_id>/content", methods=["GET", "OPTIONS"])
    @guarded
    def gateway_file_content(file_id):
        content = batches.call("file_content", owner=g.authenticated_user["username"], id=file_id)["content"]
        return Response(base64.b64decode(content, validate=True), content_type="application/jsonl",
                        headers={"Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff"})

    @app.route("/v1/batches", methods=["GET", "POST", "OPTIONS"])
    @guarded
    def gateway_batches():
        if request.method == "GET":
            return jsonify(public_reply(batches.call("batch_list", owner=g.authenticated_user["username"], **pagination())))
        require_content()
        return jsonify(batches.create_batch(request.get_json(silent=True), g.authenticated_user, **batches.request_identity()))

    @app.route("/v1/batches/<batch_id>", methods=["GET", "OPTIONS"])
    @guarded
    def gateway_batch(batch_id):
        return jsonify(batches.call("batch_get", owner=g.authenticated_user["username"], id=batch_id)["batch"])

    @app.route("/v1/batches/<batch_id>/cancel", methods=["POST", "OPTIONS"])
    @guarded
    def gateway_batch_cancel(batch_id):
        return jsonify(batches.call("batch_cancel", owner=g.authenticated_user["username"], id=batch_id)["batch"])

    @app.route("/internal/gateway/batch-item", methods=["POST"])
    def gateway_batch_item():
        if not batches.enabled():
            return jsonify({"error": {"code": "not_found"}}), 404
        try:
            return jsonify(execute_batch_item(app))
        except batches.BatchError as error:
            return batch_error(error)
    csrf = app.extensions.get("csrf")
    if csrf is not None:
        csrf.exempt(gateway_batch_item)


def public_reply(body):
    return {k: v for k, v in body.items() if k != "version"}


def pagination():
    try:
        limit = int(request.args.get("limit", "20"))
    except ValueError:
        raise batches.BatchError(400, "invalid_limit", "limit must be between 1 and 100.") from None
    if not 1 <= limit <= 100:
        raise batches.BatchError(400, "invalid_limit", "limit must be between 1 and 100.")
    return {"limit": limit, "after": request.args.get("after", "")[:128]}


def execute_batch_item(app):
    from services.media_signing import read_principal, bind_principal_tenant
    from routes.media_batches import principal_user
    from services.auth_service import AuthService
    header = request.headers.get("Authorization", "")
    if not header.startswith("BatchPrincipal "):
        raise batches.BatchError(403, "principal_rejected", "Invalid batch principal.")
    claims = read_principal(header[len("BatchPrincipal "):], "gateway_batch")
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or body.get("batch_id") != claims["s"]:
        raise batches.BatchError(403, "principal_rejected", "Batch principal does not match.")
    # A second Container call cannot reuse a claimed capability. Canonical content
    # and controls come from durable storage, never the request's item body.
    started = batches.call("item_start", owner=claims["o"], id=claims["s"], idx=body.get("idx"), lease_token=body.get("lease_token"))
    user = principal_user(AuthService, claims["o"])
    if user is None or (started["batch"]["key_prefix"] and user.get("api_key_prefix") != started["batch"]["key_prefix"]):
        return {"status_code": 403, "body": {"error": {"code": "principal_rejected"}}, "cost_units": 0, "ambiguous": False}
    try:
        tenant = bind_principal_tenant(claims, user)
    except APIError as error:
        return {"status_code": error.status_code, "body": error.payload, "cost_units": 0, "ambiguous": False}
    try:
        return run_managed_item(app, user, started["item"], started["batch"], tenant=tenant)
    except Exception:
        # The managed accounting finalizer has already kept an uncertain hold.
        return {"status_code": 502, "body": {}, "cost_units": None, "ambiguous": True}


def run_managed_item(app, user, item, batch, *, tenant=None):
    from route_helpers import _authorize_api_scope, provider_from_request_path
    from services import request_accounting
    from services.gateway_extensions import after_authentication
    from services.generation_deadline import Deadline
    from services.request_cancellation import RequestCancellation
    from services.rate_limit_service import RateLimitService
    from services.context_pages import paging_cache_bypass
    with app.app_context(), app.test_request_context(item["url"], method="POST", json=item["body"],
            environ_base={"REMOTE_ADDR": batch["client_ip"]}, headers={"CF-Connecting-IP": batch["client_ip"], "Authorization": "BatchPrincipal managed-item"}):
        g.authenticated_user = user
        from services.tenant_hierarchy import enabled as organisations_enabled
        if organisations_enabled():
            if tenant is None:
                raise batches.BatchError(503, "tenant_storage_unavailable", "The verified batch workspace is unavailable.")
            g.verified_tenant = g.tenant_context = tenant
        g.gateway_batch_execution = True
        g.multillm_content_retention = resolve_policy(key_id=str(user.get("id") or user["username"]),
                                                     key_hash=batch["key_hash"], route=item["url"])
        deadline = Deadline(time.monotonic() + 30)
        g.generation_deadline = deadline
        g.generation_deadline_initialized = True
        g.cascade_deadline = g.gateway_generation_deadline = deadline.expires_at
        g.gateway_cancellation = RequestCancellation()
        deadline.arm(g.gateway_cancellation.cancel)
        try:
            refused = app.preprocess_request()
            if refused is None:
                refused = request_accounting.check_key_controls(user)
            if refused is None:
                refused = _authorize_api_scope("chat")
            if refused is None and not request_policy().allows_content:
                refused = batch_error(batches.BatchError(400, "retention_conflict", "Zero-content retention cannot execute stored batches."))
            if refused is None:
                refused = after_authentication()
            if refused is None and paging_cache_bypass(item["body"]):
                # Page handles bind to the caller's API key, which stored work never holds.
                refused = batch_error(batches.BatchError(400, "context_paging_unsupported",
                                                         "Batch items cannot request context paging."))
            if refused is None and batches.estimate_item(item) > item["estimate_units"]:
                refused = batch_error(batches.BatchError(400, "price_changed", "Current estimated price exceeds the reserved batch hold."))
            if refused is None:
                decision = RateLimitService.enforce_request(provider=provider_from_request_path(item["url"], item["body"]),
                    user=user, payload_bytes=request.get_data(), payload_json=item["body"], remote_addr=batch["client_ip"])
                g.rate_limit = decision.metadata
                if not decision.allowed:
                    refused = (jsonify({"error": {"code": decision.error}}), decision.status_code)
            if refused is None:
                response, context = dispatch_managed_view(app)
            else:
                response, context = app.make_response(refused), None
            return item_outcome(response, context, item)
        finally:
            deadline.stop()


def dispatch_managed_view(app):
    from route_helpers import _call_accounted
    view = app.view_functions[request.endpoint].__wrapped__
    captured = []
    @wraps(view)
    def dispatch():
        captured.append(getattr(g, "usage_context", None))
        return view()
    # Skip only API-key authentication. All managed dispatch, cache, schema and
    # accounting wrappers remain; capture the context before finish clears g.
    # The registered response finalizers (admission, idempotency, hosted state,
    # PII restoration) run as they would for the route itself.
    response = app.process_response(app.make_response(_call_accounted(dispatch, (), {})))
    return response, captured[0] if captured else None


def item_outcome(response, context, item):
    from services.managed_turn import completed_envelope
    from services.usage_types import UsageObservation
    data = response.get_json(silent=True)
    if response.is_streamed or not isinstance(data, dict):
        response.close()
        return {"status_code": 502, "body": {}, "cost_units": None, "ambiguous": True}
    usage = UsageObservation.from_body(data)
    model = (context.selected if context else None) or item["body"]["model"]
    cost = CostService.estimate(model, usage.input_tokens, usage.output_tokens) if usage else None
    if context is None or context.cached:
        cost = 0
    ambiguous = bool(context and context.ambiguous) or (context is not None and cost is None)
    if response.status_code == 200 and not completed_envelope(data):
        ambiguous = True
    return {"status_code": response.status_code, "body": data, "cost_units": batches.cost_units(cost),
            "ambiguous": ambiguous, "request_id": response.headers.get("X-Request-ID")}
