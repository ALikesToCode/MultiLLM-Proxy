"""Administrator-only evaluation controls; retained text loads only on demand."""

from functools import partial
from types import SimpleNamespace

from flask import jsonify, request

from error_handlers import APIError
from request_validation import json_object_body
from route_helpers import api_auth_required, login_required
from routes.core import require_admin_dashboard_user
from routes.unified import dispatch_unified_chat_completion
from services.auto_route_service import AutoRouteService
from services.intelligence_store import IntelligenceStore
from services.shadow_eval_contract import validate_config
from services.shadow_eval_league import bandit_proposal, league, proposal, result_counts
from services.shadow_eval_runner import start_run
from services.shadow_eval_sampling import sampling_counts
from services.shadow_eval_store import ShadowEvalStore
from services import evaluation_noise_floor as noise_floor
from services import bandit_recommendations as bandit


def current_proposal(options=None):
    selected_mode = bandit.mode()
    if selected_mode != "off":
        route_id, task, seed = bandit.proposal_options(options)
        revision, order = bandit.read_route_revision(route_id)
        document = bandit_proposal(ShadowEvalStore.results(), SimpleNamespace(id=route_id, candidates=order),
                                   task, revision, seed=seed)
        return None, {"mode": selected_mode, **document}
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
        _, document = current_proposal(json_object_body() if bandit.mode() != "off" else None)
        return jsonify(document)

    @app.post("/admin/workbench/shadow/apply")
    @login_required
    def shadow_apply():
        require_admin_dashboard_user()
        if bandit.mode() != "off":
            raise APIError("Review route-order changes through configuration snapshot apply", 400)
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

    @app.post("/admin/workbench/shadow/bandit/nonce")
    @login_required
    def bandit_nonce():
        user = require_admin_dashboard_user()
        if bandit.mode() == "off":
            raise APIError("Not found", 404)
        body = json_object_body()
        if (set(body) != {"sample_id", "model"} or not isinstance(body["sample_id"], str)
                or not bandit.ID.fullmatch(body["sample_id"]) or not isinstance(body["model"], str)):
            raise APIError("Expected a stored sample_id and model", 400)
        bandit.recommendations.replace_results(ShadowEvalStore.results())
        try:
            nonce = bandit.recommendations.issue_nonce(bandit.observation_id(body["sample_id"], body["model"]),
                                                      bandit.config_snapshots.actor_identity(user))
        except ValueError as error:
            raise APIError(str(error), 409) from None
        return jsonify({"nonce": nonce, "expires_in_seconds": bandit.NONCE_TTL})

    @app.post("/admin/workbench/shadow/bandit/feedback")
    @login_required
    def bandit_feedback():
        user = require_admin_dashboard_user()
        if bandit.mode() == "off":
            raise APIError("Not found", 404)
        body = json_object_body()
        if set(body) != {"nonce", "quality"} or not isinstance(body["nonce"], str) or not bandit._number(body["quality"], 0, 1):
            raise APIError("Expected nonce and quality between zero and one", 400)
        bandit.recommendations.replace_results(ShadowEvalStore.results())
        try:
            bandit.recommendations.feedback(body["nonce"], body["quality"], bandit.config_snapshots.actor_identity(user))
        except ValueError as error:
            raise APIError(str(error), 409) from None
        return jsonify({"accepted": True})

    @app.post("/admin/shadow-eval/run")
    @csrf.exempt
    @api_auth_required
    def shadow_run():
        from flask import g
        if not getattr(g, "authenticated_user", {}).get("is_admin"):
            raise APIError("Administrator API authentication required", 403)
        body = request.get_json(silent=True)
        options = None
        if isinstance(body, dict) and "three_arm" in body:
            try:
                if not noise_floor.enabled():
                    raise ValueError("Three-arm evaluation is disabled")
                options = noise_floor.run_options(body)
            except ValueError as error:
                raise APIError(str(error), 400) from None
        config = ShadowEvalStore.config()
        if not config["enabled"]:
            return jsonify({"started": False, "reason": "disabled"})
        if options is not None:
            if config["max_replays_per_run"] < noise_floor.CALL_UNITS:
                raise APIError("Three-arm evaluation requires at least nine calls per run", 400)
            return jsonify({"started": start_run(app, dispatch, options=options)}), 202
        return jsonify({"started": start_run(app, dispatch)}), 202
