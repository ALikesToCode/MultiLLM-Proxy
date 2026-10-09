"""Authenticated checkout and raw, CSRF-exempt processor evidence."""
import json

from flask import g, jsonify, request

from route_helpers import api_authenticate_only
from services import payment_billing as payments
from services.enterprise_contract import TenantContext


def register_payment_routes(app, csrf, *, service=None, context_resolver=None):
    if app.extensions.get("payment_routes_registered"):
        return
    service = service or payments.PaymentBilling()
    app.extensions["payment_billing"] = service
    app.extensions["payment_routes_registered"] = True

    def failed(error):
        return jsonify({"error": {"code": error.code, "message": "Payment operation unavailable."}}), error.status

    def payment_gate():
        if not request.path.startswith("/v1/payments/"):
            return None
        try:
            service.config()
        except payments.PaymentError as error:
            return failed(error)
        if request.content_length is not None and request.content_length > payments.MAX_BODY:
            return failed(payments.PaymentError("invalid_payment_body", 400))
        return None

    app.before_request_funcs.setdefault(None, []).insert(0, payment_gate)

    @app.after_request
    def payment_headers(response):
        if request.path.startswith("/v1/payments/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.post("/v1/payments/checkout")
    @csrf.exempt
    @api_authenticate_only(required_scope="models")
    def payment_checkout():
        try:
            user = g.authenticated_user
            owner = str(user.get("id") or user.get("username") or "")
            context = context_resolver(user) if context_resolver else TenantContext(owner)
            if not request.is_json:
                raise payments.PaymentError("invalid_payment_checkout", 400)
            raw = request.stream.read(payments.MAX_BODY + 1)
            if len(raw) > payments.MAX_BODY:
                raise payments.PaymentError("invalid_payment_body", 400)
            try:
                body = json.loads(raw)
            except (ValueError, UnicodeError, RecursionError):
                raise payments.PaymentError("invalid_payment_checkout", 400) from None
            return jsonify(service.checkout(context, owner, body))
        except payments.PaymentError as error:
            return failed(error)
        except (ValueError, TypeError):
            return failed(payments.PaymentError("payment_permission_denied", 403))

    @app.post("/v1/payments/webhook")
    @csrf.exempt
    def payment_webhook():
        try:
            # Signature validation always precedes parsing or reading identity.
            raw = request.stream.read(payments.MAX_BODY + 1)
            return jsonify(service.webhook(raw, request.headers.get("Stripe-Signature", "")))
        except payments.PaymentError as error:
            return failed(error)
