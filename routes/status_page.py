"""Public status page, free provider health checks and the route health writer.

`GET /status` and `GET /status.json` need no login and reveal no keys, usage, URLs or
hostnames. On Cloudflare the Worker answers both from the D1 snapshot so a visit never
wakes the Container; these routes serve the live figures elsewhere and as a fallback.
`POST /v1/health/checks` runs the free model-list checks; the Worker's cron calls it with
the admin key, and an administrator may call it by hand.
"""

from __future__ import annotations

from flask import Response, jsonify, render_template

from route_helpers import api_authenticate_only
from services import route_health_sync
from services.health_checks import run_free_checks
from services.status_snapshot import build_public_status

PUBLIC_ENDPOINTS = frozenset({"public_status", "public_status_json"})
PUBLIC_CACHE_CONTROL = "public, max-age=30, s-maxage=60"
# Kept in step with worker/status-page.mjs, which renders the same page from D1.
STATUS_LABELS = {"up": "Up", "degraded": "Degraded", "down": "Down", "unknown": "Unknown"}
OVERALL_TEXT = {
    "up": "All automatic routes are up",
    "degraded": "Some automatic routes are degraded",
    "down": "Automatic routes are down",
    "unknown": "No recent health data",
}


def _public(response: Response) -> Response:
    response.headers["Cache-Control"] = PUBLIC_CACHE_CONTROL
    return response


def format_rate(value) -> str:
    return "–" if value is None else f"{value * 100:.1f}%"


def format_latency(value) -> str:
    if value is None:
        return "–"
    return f"{value} ms" if value < 1000 else f"{value / 1000:.1f} s"


def format_time(value) -> str:
    """ISO-8601 UTC to 'YYYY-MM-DD HH:MM UTC'."""
    return "–" if not value else f"{value[:10]} {value[11:16]} UTC"


def status_view(status: dict) -> dict:
    """Display strings for the page; the JSON document stays numeric."""
    def label(value):
        return {"status": value, "label": STATUS_LABELS.get(value, "Unknown")}

    return {
        "overall": {**label(status["overall"]), "text": OVERALL_TEXT.get(status["overall"], OVERALL_TEXT["unknown"])},
        "generated_at": status["generated_at"],
        "generated_text": format_time(status["generated_at"]),
        "routes": [{
            "id": route["id"], "kind": route["kind"], **label(route["status"]),
            "candidates": [{
                "priority": candidate["priority"], "model": candidate["model"], **label(candidate["status"]),
                "success_rate": format_rate(candidate["success_rate"]),
                "p50": format_latency(candidate["p50_latency_ms"]),
                "last_check": format_time(candidate["last_check_at"]),
            } for candidate in route["candidates"]],
        } for route in status["routes"]],
        "providers": [{
            "id": provider["id"], **label(provider["status"]),
            "success_rate": format_rate(provider["success_rate"]),
            "p50": format_latency(provider["p50_latency_ms"]),
            "last_check": format_time(provider["last_check_at"]),
        } for provider in status["providers"]],
    }


def register_status_routes(app, csrf, auth_service_cls, proxy_service_cls) -> None:
    route_health_sync.start_background()

    @app.get("/status.json")
    def public_status_json():
        response = jsonify({**build_public_status(), "source": "live"})
        response.headers["Access-Control-Allow-Origin"] = "*"
        return _public(response)

    @app.get("/status")
    def public_status():
        page = render_template("public_status.html", view=status_view(build_public_status()), source="live")
        return _public(Response(page, content_type="text/html; charset=utf-8"))

    @app.route("/v1/health/checks", methods=["POST", "OPTIONS"])
    @csrf.exempt
    @api_authenticate_only(required_scope="admin")
    def run_health_checks():
        if route_health_sync.enabled():
            # A cron request may arrive before the writer has merged the stored rows.
            route_health_sync.load()
        report = run_free_checks(app.config["API_BASE_URLS"], auth_service_cls, proxy_service_cls)
        report["stored"] = route_health_sync.flush(force_snapshot=True)
        response = jsonify(report)
        response.headers["Cache-Control"] = "no-store"
        return response
