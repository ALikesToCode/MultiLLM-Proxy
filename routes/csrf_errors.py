"""Recover rejected browser forms without replaying protected actions."""

from flask import jsonify, render_template, request
from flask_wtf.csrf import CSRFError

from error_handlers import get_request_id


def handle_csrf_error(error: CSRFError):
    message = "CSRF token missing or invalid."
    if request.is_json or "application/json" in request.headers.get("Accept", ""):
        return jsonify(
            error="csrf_failed",
            message=message,
            request_id=get_request_id(),
        ), 400
    if request.endpoint == "login":
        # Rendering generates a freshly signed token for the current session.
        # Rejected credentials are never authenticated, echoed, or replayed.
        return render_template(
            "login.html",
            csrf_recovery=True,
            error=(
                "Your sign-in form expired or lost its browser session. "
                "A fresh form is ready below. Enter your details again. "
                "If this repeats, allow cookies for this site."
            ),
        ), 400
    return render_template(
        "error.html", error=message, request_id=get_request_id()
    ), 400
