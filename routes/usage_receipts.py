"""Authenticated reads of immutable usage receipts and reviewed public keys."""
from flask import g, jsonify

from route_helpers import api_authenticate_only
from services import usage_receipts


def register_usage_receipt_routes(app, csrf, *, store=None):
    def authority():
        if not usage_receipts.enabled():
            raise usage_receipts.ReceiptError("not_found", 404)
        return store or usage_receipts.open_store()

    def failed(error):
        return jsonify({"error": {"code": error.code, "message": "Usage receipt operation unavailable."}}), error.status

    @app.route("/v1/usage/receipts/<id>", methods=["GET", "OPTIONS"])
    @csrf.exempt
    @api_authenticate_only(required_scope="models")
    def usage_receipt(id):
        try:
            user = g.authenticated_user
            principal = str(user.get("username") or user.get("id") or "")
            receipt = authority().get(principal, id)
            if receipt is None:
                raise usage_receipts.ReceiptError("not_found", 404)
            response = jsonify(receipt)
            response.headers["Cache-Control"] = "no-store"
            return response
        except usage_receipts.ReceiptError as error:
            return failed(error)

    @app.route("/v1/usage/receipt-keys", methods=["GET", "OPTIONS"])
    @csrf.exempt
    @api_authenticate_only(required_scope="models")
    def usage_receipt_keys():
        try:
            response = jsonify({"keys": authority().keys()})
            response.headers["Cache-Control"] = "no-store"
            return response
        except usage_receipts.ReceiptError as error:
            return failed(error)
