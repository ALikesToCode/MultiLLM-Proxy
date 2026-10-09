"""Owner reads and explicit administrator CAS adjustments for gateway credits."""
import re

from flask import g, jsonify, request

from route_helpers import api_authenticate_only, login_required
from routes.config_snapshots import json_errors
from routes.core import require_admin_dashboard_user
from services import credits_ledger as ledger


def register_credits_routes(app, csrf, *, store=None):
    if app.extensions.get('credits_routes_registered'):
        return
    app.extensions['credits_routes_registered'] = True

    def disabled_credits():
        if request.path == '/v1/credits' or request.path.startswith('/admin/credits/'):
            if not ledger.enabled():
                return failed(ledger.CreditsError('not_found', 404))
        return None

    app.before_request_funcs.setdefault(None, []).insert(0, disabled_credits)

    @app.after_request
    def private_credits(result):
        if request.path == '/v1/credits' or request.path.startswith('/admin/credits/'):
            result.headers['Cache-Control'] = 'no-store'
        return result

    def authority():
        if not ledger.enabled():
            raise ledger.CreditsError('not_found', 404)
        return store if store is not None else ledger.open_store()

    def failed(error):
        return jsonify({'error': {'code': error.code, 'message': 'Credits operation unavailable.'}}), error.status, {'Cache-Control': 'no-store'}

    app.register_error_handler(ledger.CreditDenied, failed)

    def response(value, *, owner_view=False):
        result = jsonify({key: item for key, item in value.items() if not owner_view or key != 'revision'})
        result.headers['Cache-Control'] = 'no-store'
        if 'revision' in value:
            result.headers['ETag'] = '"' + str(value['revision']) + '"'
        return result

    def page(owner):
        limit = request.args.get('limit', '100')
        if not re.fullmatch(r'[0-9]{1,3}', limit):
            raise ledger.CreditsError('invalid_credits_request', 400)
        return authority().read(owner, cursor=request.args.get('cursor', '0'), limit=int(limit))

    @app.route('/v1/credits', methods=['GET', 'OPTIONS'])
    @csrf.exempt
    @api_authenticate_only(required_scope='models')
    def owner_credits():
        try:
            context = getattr(g, 'tenant_context', None)
            user = g.authenticated_user
            owner = ledger.context_owner(context) if context is not None else str(user.get('username') or user.get('id') or '')
            return response(page(owner), owner_view=True)
        except ledger.CreditsError as error:
            return failed(error)

    @app.get('/admin/credits/<owner>')
    @json_errors
    @login_required
    def admin_credits(owner):
        try:
            require_admin_dashboard_user()
            return response(page(owner))
        except ledger.CreditsError as error:
            return failed(error)

    @app.post('/admin/credits/adjust')
    @json_errors
    @login_required
    def adjust_credits():
        try:
            actor = require_admin_dashboard_user()
            match = request.headers.get('If-Match')
            if match is None:
                raise ledger.CreditsError('credits_revision_required', 428)
            if not re.fullmatch(r'"[0-9]{1,16}"', match):
                raise ledger.CreditsError('invalid_credits_request', 400)
            body = request.get_json(silent=True)
            if not isinstance(body, dict) or set(body) != {'owner', 'amount_microusd', 'operation_id', 'reason'}:
                raise ledger.CreditsError('invalid_credits_request', 400)
            entry = authority().append(body['owner'], 'adjust', body['amount_microusd'], body['operation_id'],
                                       int(match[1:-1]), reason=body['reason'], actor=str(actor.get('username') or actor.get('id') or ''))
            return response(entry)
        except ledger.CreditsError as error:
            return failed(error)
