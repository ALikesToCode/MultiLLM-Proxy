"""Registered enterprise collaborators and processor credit boundaries."""
import importlib
import hashlib
import hmac
import json
import os
import sqlite3
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from tests.unified_api_test_case import UnifiedApiTestCase

ROOT = Path(__file__).resolve().parents[1]
FLAGS = ('ORGANISATIONS_ENABLED', 'TENANT_GOVERNANCE_ENABLED', 'SAML_ENABLED', 'SCIM_ENABLED',
         'CREDITS_ENABLED', 'CREDITS_ENFORCEMENT', 'PAYMENTS_ENABLED')


def test_enforcement_parser(monkeypatch, caplog):
    ledger = importlib.import_module('services.credits_ledger')
    ledger._warned.discard('CREDITS_ENFORCEMENT')
    for raw in ('', 'off', 'funded', 'all', ' ALL '):
        assert ledger.enforcement({'CREDITS_ENABLED': 'true', 'CREDITS_ENFORCEMENT': raw}) == (raw.strip().lower() or 'off')
    for _ in range(2):
        assert ledger.enforcement({'CREDITS_ENABLED': 'true', 'CREDITS_ENFORCEMENT': 'private-invalid'}) == 'off'
    assert caplog.text.count('Invalid CREDITS_ENFORCEMENT') == 1
    assert 'private-invalid' not in caplog.text
    assert ledger.enforcement({'CREDITS_ENFORCEMENT': 'all'}) == 'off'


def test_processor_refund_and_replay(tmp_path, monkeypatch):
    ledger = importlib.import_module('services.credits_ledger')
    payments = importlib.import_module('services.credits_payments')
    contract = importlib.import_module('services.enterprise_contract')
    monkeypatch.setenv('CREDITS_ENABLED', 'true')
    monkeypatch.setenv('CREDITS_CURRENCY', 'USD')
    store = ledger.SqlCreditsLedger(tmp_path / 'credits.sqlite3', initialize=True)
    context = contract.TenantContext('alice', 'org', 'team')
    owner = ledger.context_owner(context)
    callback = payments.payment_callback(store)
    def event(kind, op, amount, revision):
        return contract.PaymentEvent(context, 'checkout', revision, op, 'stripe', op, kind, 'USD', amount, True)
    credit = event('credit', 'credit:checkout', 100, 8)
    assert callback(credit).revision == 9
    store.append(owner, 'reserve', 100, 'hold', 1, scoped_id='attempt', tariff_revision=1)
    store.append(owner, 'commit', 100, 'spend', 2, scoped_id='attempt', tariff_revision=1)
    refund = event('refund', 'refund:checkout:100', 100, 9)
    assert callback(refund).revision == 10
    assert callback(refund).revision == 10
    summary = store.read(owner)
    assert (summary['balance_microusd'], summary['held_microusd'], summary['revision']) == (-100, 0, 4)
    with pytest.raises(ledger.CreditsError, match='invalid_credits_request'):
        store.append(owner, 'adjust', -1, 'admin', 4, actor='processor:stripe', reason='refund')
    with pytest.raises(ledger.CreditsError, match='credits_insufficient'):
        store.append(owner, 'reserve', 1, 'denied', 4, scoped_id='next', tariff_revision=1)


def test_callback_retries_only_revision_mismatch(monkeypatch):
    ledger = importlib.import_module('services.credits_ledger')
    payments = importlib.import_module('services.credits_payments')
    contract = importlib.import_module('services.enterprise_contract')
    monkeypatch.setenv('CREDITS_ENABLED', 'true')
    monkeypatch.setenv('CREDITS_CURRENCY', 'USD')
    store = Mock(read=Mock(side_effect=[{'revision': 5}, {'revision': 6}]),
                 append_payment=Mock(side_effect=[ledger.CreditsError('credits_revision_mismatch', 412), {'revision': 7}]))
    event = contract.PaymentEvent(contract.TenantContext('alice'), 'checkout', 42, 'refund:checkout', 'stripe', 'event', 'refund', 'USD', 20, True)
    assert payments.payment_callback(store)(event).revision == 43
    assert [call.args[4] for call in store.append_payment.call_args_list] == [5, 6]
    assert len({call.args[3] for call in store.append_payment.call_args_list}) == 1
    store.read.side_effect = None
    store.read.return_value = {'revision': 6}
    for code in ('credits_conflict', 'credits_revision_mismatch'):
        store.reset_mock()
        store.append_payment.side_effect = ledger.CreditsError(code, 409)
        with pytest.raises(importlib.import_module('services.credits_admission').CreditAdmissionError, match='credits_unavailable'):
            payments.payment_callback(store)(event)
        assert store.append_payment.call_count == store.read.call_count == 1


def test_private_endpoint_bounds_and_version(monkeypatch):
    transport = importlib.import_module('services.intelligence_d1_store')
    state = importlib.import_module('services.control_state_d1')
    bounds = {'tenant_governance': (32768, '/v1/tenant-governance'), 'saml': (8192, '/v1/managed-state/saml'),
              'scim': (131072, '/v1/managed-state/scim'), 'credits': (16384, '/v1/managed-state/credits'),
              'payments': (65536, '/v1/managed-state/payments')}
    for name, (bound, path) in bounds.items():
        assert transport._ENDPOINTS[name] == 'http://intelligence.internal' + path
        assert transport._ENDPOINT_MAX_BYTES[name] == bound
        assert transport._RESPONSE_MAX_BYTES[transport._ENDPOINTS[name]] == bound
    call = Mock(return_value={})
    monkeypatch.setattr(transport, 'request_private_intelligence', call)
    state.call('credits', 'read', owner='alice')
    assert call.call_args.args[0] == {'version': 1, 'operation': 'read', 'owner': 'alice'}


@pytest.mark.parametrize('endpoint', ['tenant_governance', 'saml', 'scim', 'credits', 'payments'])
def test_private_transport_pins_origin_and_enforces_each_bound(monkeypatch, endpoint):
    private = importlib.import_module('services.intelligence_d1_store')
    calls = []
    def submit(target, body, stopped, deadline, results, slots, statuses, timeout):
        calls.append((target, len(body)))
        results.put_nowait((True, {'version': 1}))
        slots.release()
    monkeypatch.setattr(private, '_submit', submit)
    bound = private._ENDPOINT_MAX_BYTES[endpoint]
    overhead = len(json.dumps({'data': '', 'version': 1}, separators=(',', ':')).encode())
    assert private.request_private_intelligence({'data': 'x' * (bound - overhead)}, endpoint=endpoint) == {'version': 1}
    assert calls == [(private._ENDPOINTS[endpoint], bound)]
    for destination, size in ((endpoint, bound - overhead + 1), (private._ENDPOINTS[endpoint], 0),
                              ('https://external.invalid', 0)):
        with pytest.raises(private.GatewayError):
            private.request_private_intelligence({'data': 'x' * size}, endpoint=destination)
    assert len(calls) == 1


class RegisteredEnterpriseTest(UnifiedApiTestCase):
    def setUp(self):
        settings = patch.dict(os.environ, {**dict.fromkeys(FLAGS, ''),
            'CONFIG_REVISION_SYNC_ENABLED': 'false', 'USAGE_LEDGER_ENABLED': 'false',
            'INTELLIGENCE_STORAGE_BACKEND': '', 'AUTH_STORAGE_BACKEND': '', 'CF_ACCESS_SSO_ONLY': 'false'})
        settings.start()
        self.addCleanup(settings.stop)
        for target in ('env_loader.load_runtime_env', 'config.load_runtime_env', 'services.usage_ledger.start'):
            loader = patch(target)
            loader.start()
            self.addCleanup(loader.stop)
        network = patch('requests.sessions.Session.send', side_effect=AssertionError('No network'))
        network.start()
        self.addCleanup(network.stop)
        super().setUp()
        os.environ['USAGE_DB_PATH'] = str(Path(self.temp_dir.name) / 'usage.sqlite3')
        self.auth = self.app_module.AuthService

    def rebuild(self):
        with patch.object(self.app_module, 'load_runtime_env'):
            self.app = self.app_module.create_app()
        self.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False, IMAGE_RELAY_CATALOG_AUTO_REFRESH=False)
        self.client = self.app.test_client()

    def login(self):
        result = self.client.post('/login', data={'username': 'admin', 'api_key': 'admin-test-key'})
        assert result.status_code == 302

    def migrate(self, path, *names):
        with sqlite3.connect(path) as db:
            for name in names:
                db.executescript((ROOT / 'intelligence-migrations' / name).read_text())

    def workspace(self, role='admin'):
        self.migrate(os.environ['AUTH_DB_PATH'], '0033_tenant_hierarchy.sql')
        tenants = importlib.import_module('services.tenant_hierarchy')
        existing = self.auth._load_user_by_username('admin')
        assert existing is not None
        # The existing SQLite membership writer calls the schema-initializing account
        # lookup under its write lock. Supply the independently verified account fixture.
        store = tenants.TenantStore(principal_exists=lambda principal: principal == existing['username'])
        org = store.request('org_create', data={'name': 'Workspace'}, actor='admin')
        store.request('member_set', org_id=org['id'], principal='admin', actor='admin', revision=0,
                      data={'role': role, 'bind': True, 'binding_revision': 0})
        return store, org['id']

    def test_all_off_preserves_hooks_sessions_generation_and_never_calls_enterprise_storage(self):
        adapters = self.app.extensions['enterprise_adapters']
        assert adapters.credit is None and adapters.identity is None and adapters.payment is None
        assert [hook.__name__ for hook in self.app.extensions['gateway_after_authentication']] == \
            importlib.import_module('tests.test_wave6_registrar').ORDER
        assert 'tenant_context_hook' not in [hook.__name__ for hook in self.app.extensions['gateway_after_authentication']]
        urls = ['/auth/saml/login', '/auth/saml/callback', '/auth/saml/acs', '/auth/saml/metadata',
                '/admin/saml/links', '/scim/v2/Users', '/v1/credits', '/admin/credits/admin',
                '/admin/credits/adjust', '/v1/payments/checkout', '/v1/payments/webhook',
                '/admin/organisations/org/governance', '/v1/workspaces']
        transport = importlib.import_module('services.intelligence_d1_store')
        tenants = importlib.import_module('services.tenant_hierarchy')
        with patch.object(transport, 'request_private_intelligence', side_effect=AssertionError('Disabled storage')), \
                patch.object(tenants.TenantStore, 'request', side_effect=AssertionError('Disabled tenants')):
            for url in urls:
                assert self.client.get(url).status_code == 404, url
            with patch.object(self.app_module.ProxyService, 'make_request', return_value=self._chat_response()) as upstream:
                result = self.client.post('/v1/chat/completions', headers={'Authorization': 'Bearer admin-test-key'},
                    json={'model': 'opencode:test', 'messages': []})
                assert result.status_code == 200 and upstream.call_count == 1
            self.login()
            with self.client.session_transaction() as saved:
                assert set(saved) == {'authenticated', 'user'}
                assert set(saved['user']) == {'username', 'is_admin', 'api_key_prefix', 'scopes', 'session_id'}
            assert self.client.get('/users').status_code == 200

    def test_workspace_list_and_switch_use_registered_context(self):
        os.environ['ORGANISATIONS_ENABLED'] = 'true'
        self.rebuild()
        store, org = self.workspace()
        headers = {'Authorization': 'Bearer admin-test-key'}
        result = self.client.get('/v1/workspaces', headers=headers)
        assert result.status_code == 200 and result.json['binding']['org_id'] == org
        switched = self.client.post('/v1/workspaces/switch', headers={**headers, 'If-Match': '"1"'},
            json={'org_id': org, 'team_id': None})
        assert switched.status_code == 200 and switched.json['revision'] == 2
        store.request('org_update', org_id=org, actor='admin', revision=1, data={'status': 'deactivated'})
        assert self.client.get('/v1/credits', headers=headers).status_code == 404
        assert self.client.get('/v1/models', headers=headers).status_code == 403

    def test_governance_role_and_private_cas_through_real_routes(self):
        os.environ.update(ORGANISATIONS_ENABLED='true', TENANT_GOVERNANCE_ENABLED='true')
        self.rebuild()
        store, org = self.workspace()
        self.login()
        transport = importlib.import_module('services.intelligence_d1_store')
        state = importlib.import_module('services.control_state_d1')
        revision = 0
        def private(document, *, endpoint):
            nonlocal revision
            assert endpoint == 'tenant_governance' and document['version'] == 1 and document['rpc'] is True
            if document['operation'] == 'put':
                if document['revision'] != revision:
                    raise transport.PrivateIntelligenceError(412, 'revision_stale')
                revision += 1
            return {'version': 1, 'policy': {'revision': revision, 'models': None, 'tools': None, 'daily': 100, 'monthly': None}}
        path = '/admin/organisations/' + org + '/governance'
        with patch.object(state, 'using_d1', return_value=True), patch.object(transport, 'request_private_intelligence', side_effect=private):
            assert self.client.get(path).headers['ETag'] == '"0"'
            assert self.client.put(path, json={'daily': 100}).status_code == 428
            result = self.client.put(path, headers={'If-Match': '"0"'}, json={'daily': 100})
            assert result.status_code == 200 and result.headers['ETag'] == '"1"'
            assert self.client.put(path, headers={'If-Match': '"0"'}, json={'daily': 100}).status_code == 412
            store.request('member_set', org_id=org, principal='admin', actor='admin', revision=1, data={'status': 'deactivated'})
            assert self.client.get(path).status_code == 403

    def test_registered_governance_tools_intersect_key_and_ancestor_grants(self):
        from flask import g
        governance = importlib.import_module('services.tenant_governance')
        deferred = importlib.import_module('services.deferred_tools')
        contract = importlib.import_module('services.enterprise_contract')
        os.environ.update(TENANT_GOVERNANCE_ENABLED='true', ORGANISATIONS_ENABLED='true')
        rows = [{'principal_id': 'alice', 'tool_name': name, 'allowed': allowed, 'revision': 1,
                 'scopes': ['models']} for name, allowed in [('allowed', 1), ('ancestor_denied', 1), ('key_denied', 0)]]
        with patch.object(deferred.D1GrantReader, '__call__', return_value=rows):
            self.rebuild()
            collaborators = self.app.extensions['tenant_governance']
            store = Mock(call=Mock(return_value={'policies': [{'tools': ['allowed', 'key_denied']}, {'tools': ['*']}]}))
            governance.register_governance_collaborators(app=self.app, store=store,
                tenant_resolver=collaborators.tenant_resolver, membership_role=collaborators.membership_role)
            entries = [{'scope': 'models', 'definition': {'name': row['tool_name'], 'inputSchema': {'type': 'object'}}} for row in rows]
            with self.app.test_request_context('/mcp'):
                g.authenticated_user = {'username': 'alice', 'scopes': ['models']}
                g.tenant_context = contract.TenantContext('alice', 'org')
                service = self.app.extensions['deferred_tools']
                assert [item['name'] for item in service.list_tools(entries, g.authenticated_user)] == ['allowed']
                with pytest.raises(Exception, match='not granted'):
                    service.require_grant(entries[1], g.authenticated_user)

    def test_saml_registered_issuer_matches_password_session_and_denies_inactive_or_unlinked(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
        helpers = importlib.import_module('tests.test_saml_federation')
        key = ed25519.Ed25519PrivateKey.generate()
        signer = ('EdDSA', key, key.public_key().public_bytes(serialization.Encoding.PEM,
                                                            serialization.PublicFormat.SubjectPublicKeyInfo).decode())
        os.environ.update(helpers.settings(signer))
        self.rebuild()
        self.login()
        with self.client.session_transaction() as saved:
            expected = dict(saved)
            expected['user'] = dict(saved['user'])
        self.client = self.app.test_client()
        os.environ['INTELLIGENCE_STORAGE_BACKEND'] = 'd1'
        service = self.app.extensions['saml_federation']
        service.clock = lambda: helpers.NOW
        store = helpers.Store()
        transport = importlib.import_module('services.intelligence_d1_store')
        def private(document, *, endpoint):
            assert endpoint == 'saml'
            return store(document)
        with patch.object(transport, 'request_private_intelligence', side_effect=private):
            service.put_link({'issuer': helpers.ISSUER, 'subject': 'external:alice', 'account': 'admin'}, 'admin')
            claims = helpers.start(self.client)
            assert helpers.callback(self.client, signer, claims).status_code == 302
            with self.client.session_transaction() as saved:
                actual = dict(saved)
                actual['user'] = dict(saved['user'])
            assert set(actual) == set(expected)
            actual['user'].pop('session_id')
            expected['user'].pop('session_id')
            assert actual == expected
            assert helpers.callback(self.client, signer, claims).status_code == 400
            self.client = self.app.test_client()
            claims = helpers.start(self.client)
            claims['sub'] = 'unlinked'
            assert helpers.callback(self.client, signer, claims).status_code == 403
            with self.client.session_transaction() as saved:
                assert 'authenticated' not in saved
            claims = helpers.start(self.client)
            record = self.auth.get_user_record('admin')
            with patch.object(self.auth, 'get_user_record', return_value={**record, 'revoked_at': 'revoked'}):
                assert helpers.callback(self.client, signer, claims).status_code == 403

    def test_credits_read_and_admin_adjust_share_the_registered_ledger(self):
        os.environ['CREDITS_ENABLED'] = 'true'
        self.migrate(os.environ['USAGE_DB_PATH'], '0037_credits_ledger.sql')
        self.rebuild()
        self.login()
        result = self.client.post('/admin/credits/adjust', headers={'If-Match': '"0"'},
            json={'owner': 'admin', 'amount_microusd': 100, 'operation_id': 'allocation', 'reason': 'Reviewed'})
        assert result.status_code == 200
        result = self.client.get('/v1/credits', headers={'Authorization': 'Bearer admin-test-key'})
        assert result.status_code == 200 and result.json['balance_microusd'] == 100
        assert self.client.get('/admin/credits/admin').headers['ETag'] == '"1"'

    def test_scim_registered_d1_create_patch_deactivate_and_backend_gate(self):
        helpers = importlib.import_module('tests.test_scim_provisioning')
        scim = importlib.import_module('services.scim_provisioning')
        transport = importlib.import_module('services.intelligence_d1_store')
        os.environ.update(SCIM_ENABLED='true', SCIM_TEST_A='synthetic-scim-a',
            SCIM_TRUST_CONFIG_JSON=json.dumps({'tenants': {'org:a': {'token_ref': 'SCIM_TEST_A'}}}))
        store = helpers.Store()
        calls = []
        def private(document, *, endpoint):
            calls.append(document)
            assert endpoint == 'scim' and document['version'] == 1
            args = dict(document)
            operation = args.pop('operation')
            args.pop('version')
            if operation == 'probe':
                store.probe()
                result = {}
            elif operation == 'account':
                result = {'account': store.account(args['username'])}
            elif operation == 'list':
                rows, total = store.list(args['org_id'], args['kind'], args['attribute'], args['value'], args['start'], args['count'])
                result = {'resources': rows, 'total': total}
            elif operation == 'get':
                result = {'resource': store.get(args['org_id'], args['kind'], args['id'])}
            else:
                resource, created = store.put(args.pop('org_id'), args.pop('kind'), **args)
                result = {'resource': resource, 'created': created}
            return {'version': 1, **result}
        with patch.object(transport, 'request_private_intelligence', side_effect=private):
            self.rebuild()
            assert helpers.user(self.client).status_code == 503
            assert calls == []
            os.environ.update(AUTH_STORAGE_BACKEND='d1', INTELLIGENCE_STORAGE_BACKEND='d1',
                              CONFIG_REVISION_SYNC_ENABLED='true')
            with patch.object(self.auth, '_load_user_by_username', side_effect=store.account):
                created = helpers.user(self.client)
                assert created.status_code == 201
                path = 'Users/' + created.json['id']
                changed = helpers.call(self.client, 'PATCH', path, {'schemas': [scim.PATCH_SCHEMA],
                    'Operations': [{'op': 'replace', 'path': 'displayName', 'value': 'Alice'}]},
                    **{'If-Match': created.headers['ETag']})
                assert changed.status_code == 200 and changed.json['displayName'] == 'Alice'
                os.environ['ORGANISATIONS_ENABLED'] = 'true'
                tenant_store = Mock(request=Mock(return_value={'id': 'org:a', 'status': 'active'}))
                self.app.extensions['tenant_store'] = tenant_store
                group = {'schemas': [scim.GROUP_SCHEMA], 'displayName': 'Team',
                         'members': [{'value': created.json['id']}]}
                assert helpers.call(self.client, 'POST', 'Groups', group).status_code == 201
                tenant_store.request.assert_called_with('org_get', org_id='org:a')
                assert helpers.call(self.client, 'DELETE', path).status_code == 204
                assert store.accounts['alice']['revoked_at']
                assert helpers.call(self.client, 'GET', path).json['active'] is False
                group['displayName'] = 'Other team'
                assert helpers.call(self.client, 'POST', 'Groups', group).status_code == 400
                assert len(store.accounts) == 1
                assert all('api_key' not in str(row.get('resource', {})) for row in calls)

    def test_payment_checkout_alone_is_mounted_and_credit_failure_stays_pending(self):
        self.payment_setup(workspace=False)
        checkout = self.checkout()
        raw = self.paid(checkout)
        result = self.deliver(raw)
        assert result.status_code == 503 and result.json['error']['code'] == 'payment_credit_unavailable'
        with sqlite3.connect(os.environ['USAGE_DB_PATH']) as db:
            assert db.execute('SELECT status FROM payment_events').fetchone()[0] == 'pending_credit'

    def payment_setup(self, *, workspace=True):
        helpers = importlib.import_module('tests.test_payment_billing')
        os.environ.update(helpers.ENV)
        if workspace:
            os.environ.update(ORGANISATIONS_ENABLED='true', CREDITS_ENABLED='true', TENANT_GOVERNANCE_ENABLED='true')
        self.migrate(os.environ['USAGE_DB_PATH'], '0037_credits_ledger.sql', '0038_payment_billing.sql')
        self.rebuild()
        if workspace:
            _, self.org = self.workspace(role='billing')
        service = self.app.extensions['payment_billing']
        service.secret_resolver = lambda ref: helpers.SECRET
        service.clock = lambda: helpers.NOW
        def http(url, *, headers, body):
            from urllib.parse import parse_qs
            fields = parse_qs(body)
            return {'id': 'cs_' + fields['client_reference_id'][0], 'object': 'checkout.session',
                    'url': 'https://checkout.stripe.com/c/test', 'amount_total': 50, 'currency': 'usd', 'livemode': False}
        service.http = http

    def checkout(self):
        body = importlib.import_module('tests.test_payment_billing').BODY
        result = self.client.post('/v1/payments/checkout', headers={'Authorization': 'Bearer admin-test-key'}, json=body)
        assert result.status_code == 200, result.json
        return result.json

    def paid(self, checkout):
        return json.dumps({'id': 'evt_paid', 'object': 'event', 'type': 'checkout.session.completed', 'livemode': False,
            'data': {'object': {'id': 'cs_' + checkout['checkout_id'], 'client_reference_id': checkout['checkout_id'],
                'metadata': {'checkout_id': checkout['checkout_id']}, 'payment_status': 'paid', 'amount_total': 50,
                'currency': 'usd', 'livemode': False, 'payment_intent': 'pi_test'}}}, indent=2).encode() + b'\n'

    def deliver(self, raw):
        helpers = importlib.import_module('tests.test_payment_billing')
        signature = hmac.new(helpers.SECRET.encode(), str(helpers.NOW).encode() + b'.' + raw, hashlib.sha256).hexdigest()
        return self.client.post('/v1/payments/webhook', data=raw, content_type='application/json',
                                headers={'Stripe-Signature': f't={helpers.NOW},v1={signature}'})

    def test_workspace_checkout_signed_credit_refund_and_replay_have_one_owner_and_exact_bytes(self):
        self.payment_setup()
        checkout = self.checkout()
        helpers = importlib.import_module('tests.test_payment_billing')
        payments = importlib.import_module('services.payment_billing')
        ledger = importlib.import_module('services.credits_ledger')
        contract = importlib.import_module('services.enterprise_contract')
        owner = ledger.context_owner(contract.TenantContext('admin', self.org))
        raw = self.paid(checkout)
        original = payments.verify_signature
        with patch.object(payments, 'verify_signature', wraps=original) as verify:
            assert self.deliver(raw).status_code == 200
            assert verify.call_args.args[0] == raw
            assert self.deliver(raw).status_code == 200
        result = self.client.get('/v1/credits', headers={'Authorization': 'Bearer admin-test-key'})
        assert result.status_code == 200 and result.json['balance_microusd'] == 500000
        assert ledger.open_store().read('admin')['balance_microusd'] == 0
        store = ledger.open_store()
        store.append(owner, 'reserve', 500000, 'hold', 1, scoped_id='attempt', tariff_revision=1)
        store.append(owner, 'commit', 500000, 'spent', 2, scoped_id='attempt', tariff_revision=1)
        refund = json.dumps({'id': 'evt_refund', 'object': 'event', 'type': 'charge.refunded', 'livemode': False,
            'data': {'object': {'id': 'ch_test', 'payment_intent': 'pi_test', 'amount': 50, 'amount_refunded': 50,
                               'currency': 'usd', 'livemode': False}}}).encode()
        assert self.deliver(refund).status_code == 200
        assert self.deliver(refund).status_code == 200
        assert store.read(owner)['balance_microusd'] == -500000
        assert store.read(owner)['revision'] == 4
        self.login()
        with patch.object(self.auth, 'get_current_user', return_value={'username': 'processor:stripe', 'is_admin': True}):
            denied = self.client.post('/admin/credits/adjust', headers={'If-Match': '"4"'},
                json={'owner': owner, 'amount_microusd': -1, 'operation_id': 'spoof', 'reason': 'refund'})
            assert denied.status_code == 400

    def test_all_flags_signed_webhook_keeps_cached_bytes_and_bypasses_key_freshness(self):
        from flask import request
        self.payment_setup()
        checkout = self.checkout()
        raw = self.paid(checkout)
        flags = importlib.import_module('tests.test_wave5_registrar').FLAGS
        values = {name: 'block' if name == 'PROMPT_INJECTION_MODE' else
                  'shadow' if name == 'BANDIT_MODE' else 'true' for name in flags}
        os.environ.update(values)
        os.environ.update(importlib.import_module('tests.test_wave6_registrar').FLAGS)
        os.environ.update({name: 'all' if name == 'CREDITS_ENFORCEMENT' else 'true' for name in FLAGS})
        registrar = importlib.import_module('services.gateway_extensions')
        sync = Mock(settings=Mock(enabled=True), security_ready=Mock(return_value=False))
        with patch.object(registrar, 'supported_settings', side_effect=lambda settings: settings), \
                patch.object(registrar, 'configure_sync', return_value=sync):
            self.rebuild()
        helpers = importlib.import_module('tests.test_payment_billing')
        service = self.app.extensions['payment_billing']
        service.secret_resolver = lambda ref: helpers.SECRET
        service.clock = lambda: helpers.NOW
        def cache_json():
            if request.endpoint == 'payment_webhook':
                assert request.get_json()['id'] == 'evt_paid'
        self.app.before_request_funcs[None].insert(0, cache_json)
        payments = importlib.import_module('services.payment_billing')
        with patch.object(payments, 'verify_signature', wraps=payments.verify_signature) as verify:
            result = self.deliver(raw)
            assert result.status_code == 200, result.json
            assert verify.call_args.args[0] == raw
        sync.security_ready.assert_not_called()


@pytest.mark.parametrize("composed_first", [False, True])
def test_preview_preserves_composed_enterprise_adapters(composed_first):
    from flask import Flask
    routes = importlib.import_module("routes.enterprise_preview")
    contracts = importlib.import_module("services.enterprise_contract")
    app = Flask(__name__)
    composed = contracts.register_enterprise_adapters(tenant=lambda operation: operation.context)
    def compose():
        app.extensions["enterprise_adapters"] = composed
    if composed_first:
        compose()
    routes.register_enterprise_preview_routes(app)
    if not composed_first:
        compose()
    assert app.extensions["enterprise_adapters"] is composed
