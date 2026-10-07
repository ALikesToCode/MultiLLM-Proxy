"""Administrator-only evaluation controls; retained text loads only on demand."""

from functools import partial

from flask import jsonify, request

from error_handlers import APIError
from request_validation import json_object_body
from route_helpers import api_auth_required, login_required
from routes.core import require_admin_dashboard_user
from routes.unified import dispatch_unified_chat_completion
from services.auto_route_service import AutoRouteService
from services.intelligence_store import IntelligenceStore
from services.shadow_eval_contract import validate_config
from services.shadow_eval_league import league, proposal, result_counts
from services.shadow_eval_runner import start_run
from services.shadow_eval_sampling import sampling_counts
from services.shadow_eval_store import ShadowEvalStore


def current_proposal():
    policy = IntelligenceStore.policy()
    rows = league(ShadowEvalStore.results())
    return policy, proposal(policy, rows, AutoRouteService.list_routes())


def register_shadow_eval_routes(app, csrf, auth, metrics, proxy):
    dispatch = partial(dispatch_unified_chat_completion, app, auth, metrics, proxy,
                       request_headers={}, request_args={}, request_timeout=30, adaptive_context=False)

    @app.route("/admin/workbench/shadow/config", methods=["GET", "POST"])
    @login_required
    def shadow_config():
        require_admin_dashboard_user()
        current = ShadowEvalStore.config()
        if request.method == "GET":
            return jsonify(current)
        body = json_object_body()
        try:
            if set(body) != {"config", "expected"}:
                raise ValueError("Config and expected revision are required")
            validate_config(body["expected"])
            config = ShadowEvalStore.save_config(body["config"], body["expected"])
        except ValueError as error:
            raise APIError(str(error), 400) from None
        return jsonify(config)

    @app.get("/admin/workbench/shadow/league")
    @login_required
    def shadow_league():
        require_admin_dashboard_user()
        results = ShadowEvalStore.results()
        return jsonify({"league": league(results), "result_counts": result_counts(results),
                        "sampling_counts": sampling_counts()})

    @app.get("/admin/workbench/shadow/samples")
    @login_required
    def shadow_samples():
        require_admin_dashboard_user()
        return jsonify({"samples": ShadowEvalStore.samples()})

    @app.get("/admin/workbench/shadow/samples/<identifier>")
    @login_required
    def shadow_sample(identifier):
        require_admin_dashboard_user()
        try:
            sample = ShadowEvalStore.sample(identifier)
        except ValueError:
            raise APIError("Invalid sample ID", 400) from None
        if sample is None:
            raise APIError("Sample expired or unavailable", 404)
        return jsonify(sample)

    @app.post("/admin/workbench/shadow/purge")
    @login_required
    def shadow_purge():
        require_admin_dashboard_user()
        if json_object_body() != {"confirm": True}:
            raise APIError("Confirm deletion of retained samples and results", 400)
        ShadowEvalStore.purge()
        return jsonify({"purged": True})

    @app.post("/admin/workbench/shadow/propose")
    @login_required
    def shadow_propose():
        require_admin_dashboard_user()
        _, document = current_proposal()
        return jsonify(document)

    @app.post("/admin/workbench/shadow/apply")
    @login_required
    def shadow_apply():
        require_admin_dashboard_user()
        body = json_object_body()
        if set(body) != {"confirm", "revision"} or body["confirm"] is not True:
            raise APIError("Explicitly confirm the reviewed policy proposal", 400)
        policy, document = current_proposal()
        if body["revision"] != document["revision"]:
            raise APIError("Proposal changed; generate and review it again", 409)
        if not document["policy_diff"]:
            raise APIError("No models have a changed score supported by 20 comparisons", 400)
        if not ShadowEvalStore.apply(policy, document["policy"]):
            raise APIError("Policy changed or is unseeded; reload and review again", 409)
        return jsonify({"applied": True, "auto_routes_applied": False})

    @app.post("/admin/shadow-eval/run")
    @csrf.exempt
    @api_auth_required
    def shadow_run():
        from flask import g
        if not getattr(g, "authenticated_user", {}).get("is_admin"):
            raise APIError("Administrator API authentication required", 403)
        config = ShadowEvalStore.config()
        if not config["enabled"]:
            return jsonify({"started": False, "reason": "disabled"})
        return jsonify({"started": start_run(app, dispatch)}), 202
