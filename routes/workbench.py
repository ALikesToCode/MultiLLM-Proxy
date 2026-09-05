"""Session-authenticated control plane; no browser-supplied upstream URLs or keys."""

from flask import jsonify, render_template, request

from error_handlers import APIError
from request_validation import json_object_body
from route_helpers import login_required, stream_upstream_response
from routes.core import require_admin_dashboard_user
from services.comparison_lab import SCENES, comparison_payload
from services.workbench_gateway import call_worker, worker_json
from services.connection_profiles import WorkbenchStore, validate_profile, profile_connection, routing_options
from services.workbench_gateway import worker_origin
from services.release_status import deployment_status, compatibility_probes


def register_workbench_routes(app):
    @app.after_request
    def private_workbench(response):
        if request.path.startswith(("/workbench", "/admin/workbench/")):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/workbench")
    @login_required
    def workbench():
        require_admin_dashboard_user()
        return render_template("workbench.html", scenes=SCENES)

    @app.get("/admin/workbench/catalog")
    @login_required
    def workbench_catalog():
        require_admin_dashboard_user()
        return jsonify(worker_json("/v1/roleplay/models"))

    @app.get("/admin/workbench/deployment")
    @login_required
    def workbench_deployment():
        require_admin_dashboard_user()
        try:
            worker = worker_json("/v1/roleplay/control/status")
        except APIError:
            worker = {"build_id": None, "error": "Worker metadata unavailable; check trusted origin, administrator authentication and Worker deployment"}
        status = deployment_status(worker)
        if request.args.get("probe") == "true":
            try:
                status["probes"] = compatibility_probes(worker_origin())
            except APIError:
                status["probes"] = {"error": "Configure a trusted WORKBENCH_WORKER_URL before probing"}
        return jsonify(status)

    @app.get("/admin/workbench/timeline")
    @login_required
    def workbench_timeline():
        require_admin_dashboard_user()
        return jsonify(worker_json("/v1/roleplay/control/timeline",
                                   params={"session_id": request.args.get("session_id", ""),
                                           "scope": request.args.get("scope", "roleplay")}))

    @app.post("/admin/workbench/lab/run")
    @login_required
    def workbench_lab_run():
        require_admin_dashboard_user()
        payload = comparison_payload(json_object_body())
        upstream = call_worker("/v1/roleplay", method="POST", payload=payload, stream=True)
        if not upstream.ok or upstream.is_redirect:
            status = upstream.status_code
            upstream.close()
            raise APIError(f"Comparison was rejected (HTTP {status}); no retry was started", status_code=status if status >= 400 else 502)
        response = stream_upstream_response(upstream)
        response.headers["X-Roleplay-Session-ID"] = payload["session_id"]
        response.headers["X-Roleplay-Trace-ID"] = upstream.headers.get("X-Roleplay-Trace-ID", "")
        return response

    @app.route("/admin/workbench/profiles", methods=["GET", "POST"])
    @login_required
    def workbench_profiles():
        user = require_admin_dashboard_user()
        if request.method == "GET":
            return jsonify({"profiles": WorkbenchStore.profiles(user["username"])})
        profile = validate_profile(json_object_body())
        return jsonify({"id": WorkbenchStore.save_profile(user["username"], profile)}), 201

    @app.post("/admin/workbench/profiles/preview")
    @login_required
    def workbench_profile_preview():
        require_admin_dashboard_user()
        profile = validate_profile(json_object_body())
        receipt = worker_json("/v1/roleplay/control/receipt", method="POST",
                              payload={"routing": routing_options(profile), "reasoning_effort": profile["effort"], "kind": profile["kind"]})
        return jsonify({"receipt": receipt, "connection": profile_connection(profile, worker_origin(), (receipt.get("selected") or {}).get("wireEffort"))})

    @app.route("/admin/workbench/lab/reports", methods=["GET", "POST"])
    @login_required
    def workbench_lab_reports():
        user = require_admin_dashboard_user()
        if request.method == "GET":
            return jsonify({"reports": WorkbenchStore.reports(user["username"])})
        body = json_object_body()
        if set(body) != {"measurements"}:
            raise APIError("Only comparison measurements are accepted", status_code=400)
        return jsonify({"id": WorkbenchStore.save_report(user["username"], body["measurements"])}), 201

    @app.post("/admin/workbench/memory")
    @login_required
    def workbench_memory():
        require_admin_dashboard_user()
        body = json_object_body()
        return jsonify(worker_json("/v1/roleplay/control/memory", method="POST", payload=body,
                                   params={"session_id": request.args.get("session_id", ""), "scope": request.args.get("scope", "roleplay")}))

    @app.post("/admin/workbench/branch")
    @login_required
    def workbench_branch():
        require_admin_dashboard_user()
        return jsonify(worker_json("/v1/roleplay/control/branch", method="POST", payload=json_object_body(),
                                   params={"session_id": request.args.get("session_id", ""), "scope": request.args.get("scope", "roleplay")}))

    @app.post("/admin/workbench/recovery")
    @login_required
    def workbench_recovery():
        require_admin_dashboard_user()
        body = json_object_body()
        params = {"session_id": request.args.get("session_id", ""), "scope": request.args.get("scope", "roleplay")}
        if body.get("action") == "inspect":
            return jsonify(worker_json("/v1/roleplay/control/recovery", method="POST", payload=body, params=params))
        if body.get("confirm") is not True or body.get("action") not in {"continue", "regenerate"}:
            raise APIError("Confirm the potentially billed recovery action", status_code=400)
        upstream = call_worker("/v1/roleplay/control/recovery", method="POST", payload=body, params=params, stream=True)
        if not upstream.ok or upstream.is_redirect:
            status = upstream.status_code
            upstream.close()
            raise APIError(f"Recovery was rejected (HTTP {status}); do not automatically retry", status_code=status if status >= 400 else 502)
        response = stream_upstream_response(upstream)
        response.headers["X-Roleplay-Session-ID"] = upstream.headers.get("X-Roleplay-Session-ID", "")
        return response
