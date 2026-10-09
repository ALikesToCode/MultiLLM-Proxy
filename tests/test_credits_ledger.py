"""Local ledger, registered HTTP routes and immutable authority contracts."""
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from services import credits_ledger as ledger
from services.enterprise_contract import AuthorityOperation, TenantContext, AuthorityDenied, call_authority


def vectors():
    text = (Path(__file__).resolve().parents[1] / 'docs/credits-ledger.md').read_text()
    return json.loads(text.split('```json\n', 1)[1].split('```', 1)[0])


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv('CREDITS_ENABLED', 'true')
    monkeypatch.setenv('CREDITS_CURRENCY', 'USD')
    return ledger.SqlCreditsLedger(tmp_path / 'credits.sqlite3', initialize=True)


def append(store, kind, amount, op, revision, **fields):
    return store.append('alice', kind, amount, op, revision, **fields)


def test_shared_vectors(store):
    for vector in vectors():
        if 'invalid_amount' in vector:
            with pytest.raises(ledger.CreditsError) as error:
                append(store, 'credit', vector['invalid_amount'], 'bad', 0)
            assert error.value.status == 400
            continue
        values = vector['request']
        apply = store.append_payment if vector.get('operation') == 'payment_append' else store.append
        if vector.get('error'):
            with pytest.raises(ledger.CreditsError) as error:
                apply(**values)
            assert error.value.code == vector['error']
        else:
            result = apply(**values)
            assert result['revision'] == vector['revision']
        if 'summary' in vector:
            summary = store.read(values['owner'])
            assert {key: summary[key] for key in vector['summary']} == vector['summary']
    summary = store.read('alice')
    assert (summary['balance_microusd'], summary['held_microusd'], summary['available_microusd']) == (75, 0, 75)


def test_concurrent_reserves_and_overflow(store):
    append(store, 'credit', 100, 'fund', 0)
    def reserve(op):
        try:
            return append(store, 'reserve', 80, op, 1, scoped_id=op, tariff_revision=1)
        except ledger.CreditsError as error:
            return error.code
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(reserve, ['hedge', 'shadow']))
    assert sum(isinstance(result, dict) for result in results) == 1
    assert store.read('alice')['available_microusd'] == 20
    with pytest.raises(ledger.CreditsError):
        append(store, 'credit', ledger.MAX_AMOUNT, 'overflow', 2)
    assert store.read('alice')['revision'] == 2


def test_unknown_hold_and_each_attempt_charge(store):
    append(store, 'credit', 100, 'fund', 0)
    authority = ledger.register_credit_authority(store, tariff=lambda op, phase: None if phase == 'reconcile' else 7)
    adapters = ledger.register_enterprise_credit(authority)
    def op(rev, name, amount, attempt='hedge'):
        return AuthorityOperation(TenantContext('alice'), attempt, rev, name, amount)
    call_authority(adapters, 'credit', 'reserve', op(1, 'hold1', 50))
    call_authority(adapters, 'credit', 'reconcile', op(2, 'unknown1', 0))
    assert store.read('alice')['held_microusd'] == 50
    call_authority(adapters, 'credit', 'commit', op(3, 'charge1', 20))
    call_authority(adapters, 'credit', 'reserve', op(4, 'hold2', 40, 'batch'))
    call_authority(adapters, 'credit', 'commit', op(5, 'charge2', 30, 'batch'))
    assert store.read('alice')['balance_microusd'] == 50
    denied = ledger.register_credit_authority(store, tariff=lambda *_: None)
    with pytest.raises(AuthorityDenied, match='credits_unpriced'):
        denied.reserve(op(6, 'unpriced', 0, 'new'))


def test_compensation_is_linked_and_original_unchanged(store):
    original = append(store, 'credit', 100, 'fund', 0)
    append(store, 'adjust', -20, 'debit', 1, reason='reviewed', actor='admin')
    append(store, 'compensate', 20, 'correction', 2, reference='debit', reason='correction', actor='admin')
    assert store.read('alice')['balance_microusd'] == 100
    assert store.read('alice')['entries'][0] == original
    with pytest.raises(ledger.CreditsError):
        append(store, 'compensate', 20, 'double', 3, reference='debit', reason='correction', actor='admin')
    assert store.read('bob')['entries'] == []
    assert store.read('alice', limit=1)['next_cursor'] == '1'
    assert store.read('alice', cursor='1', limit=1)['entries'][0]['operation_id'] == 'debit'


def test_missing_schema_and_default_off(tmp_path, caplog):
    missing = ledger.SqlCreditsLedger(tmp_path / 'missing.sqlite3')
    with pytest.raises(ledger.CreditsError, match='credits_unavailable'):
        missing.append('alice', 'credit', 1, 'fund', 0)
    assert not missing.path.exists()
    for flag in ['', 'false', '0', 'bad']:
        assert not ledger.enabled({'CREDITS_ENABLED': flag})
    assert ledger.enabled({'CREDITS_ENABLED': 'true', 'CREDITS_CURRENCY': ''})
    for _ in range(2):
        assert not ledger.enabled({'CREDITS_ENABLED': 'true', 'CREDITS_CURRENCY': 'EUR'})
    assert caplog.text.count('Invalid CREDITS_CURRENCY') == 1


def test_migration_preserves_old_rows_and_missing_columns_fail_closed(tmp_path):
    path = tmp_path / 'old.sqlite3'
    migration = (Path(__file__).resolve().parents[1] / 'intelligence-migrations' / ledger.MIGRATION).read_text()
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE old_usage (cost INTEGER)')
        db.execute('INSERT INTO old_usage VALUES (NULL)')
        db.executescript(migration)
        db.executescript(migration)
        assert db.execute('SELECT cost FROM old_usage').fetchone() == (None,)
    broken = tmp_path / 'broken.sqlite3'
    with sqlite3.connect(broken) as db:
        db.execute('CREATE TABLE credits_balances (owner TEXT PRIMARY KEY, balance_microusd INTEGER, held_microusd INTEGER, revision INTEGER)')
        db.execute('CREATE TABLE credits_entries (owner TEXT)')
        db.execute('CREATE TABLE credits_audit (owner TEXT)')
    store = ledger.SqlCreditsLedger(broken)
    for action in (lambda: store.read('alice'), lambda: append(store, 'credit', 1, 'fund', 0)):
        with pytest.raises(ledger.CreditsError, match='credits_unavailable'):
            action()
    with sqlite3.connect(broken) as db:
        assert db.execute('SELECT count(*) FROM credits_balances').fetchone()[0] == 0


def test_spend_above_estimate_closes_only_its_hold(store):
    append(store, 'credit', 100, 'fund', 0)
    append(store, 'reserve', 30, 'hedge', 1, scoped_id='hedge', tariff_revision=1)
    append(store, 'reserve', 60, 'shadow', 2, scoped_id='shadow', tariff_revision=1)
    append(store, 'commit', 41, 'charge', 3, scoped_id='hedge', tariff_revision=1)
    summary = store.read('alice')
    assert (summary['balance_microusd'], summary['held_microusd'], summary['available_microusd']) == (59, 60, -1)
    append(store, 'reserve', 0, 'unknown', 4, scoped_id='shadow', unknown=True)
    assert store.read('alice')['held_microusd'] == 60
    append(store, 'release', 60, 'release', 5, scoped_id='shadow')
    with pytest.raises(ledger.CreditsError, match='credits_conflict'):
        append(store, 'commit', 1, 'late', 6, scoped_id='shadow', tariff_revision=1)
    assert store.read('alice')['balance_microusd'] == 59


@pytest.mark.parametrize('recovery', ['credit', 'adjust'])
def test_commit_overrun_blocks_new_spend_until_funded(store, recovery):
    append(store, 'credit', 100, 'fund', 0)
    authority = ledger.register_credit_authority(store, tariff=lambda *_: 1)
    def op(revision, name, amount, attempt='attempt'):
        return AuthorityOperation(TenantContext('alice'), attempt, revision, name, amount)
    authority.reserve(op(1, 'hold', 60))
    with pytest.raises(ledger.CreditDenied, match='credits_revision_mismatch') as error:
        authority.commit(op(1, 'charge', 150))
    assert error.value.status == 412
    charged = authority.commit(op(2, 'charge', 150))
    assert authority.commit(op(2, 'charge', 150)) == charged
    summary = store.read('alice')
    assert (summary['balance_microusd'], summary['held_microusd'], summary['available_microusd']) == (-50, 0, -50)
    assert summary['revision'] == 3
    assert ledger.D1CreditsLedger(lambda _: dict(version=1, summary=summary)).read('alice') == summary
    for amount in (0, 1):
        with pytest.raises(ledger.CreditDenied, match='credits_insufficient'):
            authority.reserve(op(3, f'denied{amount}', amount, f'new{amount}'))
    with pytest.raises(ledger.CreditsError, match='credits_insufficient'):
        append(store, 'adjust', -1, 'debit', 3, actor='admin', reason='reviewed')
    with pytest.raises(ledger.CreditDenied, match='credits_conflict'):
        authority.commit(op(3, 'late', 1))
    with pytest.raises(ledger.CreditDenied, match='credits_conflict'):
        authority.commit(op(2, 'charge', 151))
    extra = dict(actor='admin', reason='reviewed') if recovery == 'adjust' else {}
    append(store, recovery, 25, 'partial', 3, **extra)
    assert store.read('alice')['available_microusd'] == -25
    append(store, recovery, 25, 'zero', 4, **extra)
    with pytest.raises(ledger.CreditDenied, match='credits_insufficient'):
        authority.reserve(op(5, 'zero-denied', 0, 'zero-attempt'))
    append(store, recovery, 50, 'recovered', 5, **extra)
    assert store.read('alice')['available_microusd'] == 50
    authority.reserve(op(6, 'next', 1, 'next'))
    assert store.read('alice')['available_microusd'] == 49


@pytest.mark.parametrize('balance,held', [(-ledger.MAX_AMOUNT, 0), (-50, 10), (ledger.MAX_AMOUNT, 0)])
def test_private_summary_accepts_signed_balances(store, balance, held):
    summary = dict(currency='USD', balance_microusd=balance, held_microusd=held,
                   available_microusd=balance-held, revision=0, entries=[], next_cursor=None)
    assert ledger.D1CreditsLedger(lambda _: dict(version=1, summary=summary)).read('alice') == summary
    invalid = [dict(held_microusd=-1), dict(revision=-1), dict(balance_microusd=-ledger.MAX_AMOUNT-1),
               dict(available_microusd=-ledger.MAX_AMOUNT-1), dict(balance_microusd=True)]
    for change in invalid:
        with pytest.raises(ledger.CreditsError, match='credits_unavailable'):
            ledger.D1CreditsLedger(lambda _: dict(version=1, summary={**summary, **change})).read('alice')


def test_duplicate_concurrency_pagination_and_content_free_audit(store):
    def fund(_):
        return append(store, 'adjust', 100, 'fund', 0, actor='admin', reason='Reviewed allocation')
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(fund, range(2)))
    assert results[0] == results[1]
    for revision in range(1, 102):
        append(store, 'adjust', 1, f'grant{revision}', revision, actor='admin', reason='Reviewed allocation')
    page = store.read('alice')
    assert len(page['entries']) == 100
    assert page['next_cursor'] == '100'
    assert len(store.read('alice', cursor='100')['entries']) == 2
    with sqlite3.connect(store.path) as db:
        assert [field[1] for field in db.execute('PRAGMA table_info(credits_audit)')] == ['owner', 'operation_id', 'revision', 'actor', 'kind']
        assert db.execute('SELECT count(*) FROM credits_audit').fetchone()[0] == 102
        balance, held = db.execute('SELECT SUM(balance_delta),SUM(held_delta) FROM credits_entries').fetchone()
    assert (balance, held) == (page['balance_microusd'], page['held_microusd'])
    for kwargs in ({'limit': 101}, {'limit': True}, {'cursor': '-1'}, {'cursor': '1.5'}):
        with pytest.raises(ledger.CreditsError):
            store.read('alice', **kwargs)


def test_tenant_namespace_and_d1_outage_have_no_local_fallback(store):
    context = TenantContext('alice', org_id='org', team_id='team')
    owner = ledger.context_owner(context)
    store.append(owner, 'credit', 100, 'fund', 0)
    assert store.read('alice')['balance_microusd'] == 0
    assert owner != ledger.context_owner(TenantContext('alice', org_id='other', team_id='team'))
    d1 = ledger.D1CreditsLedger(lambda _: (_ for _ in ()).throw(OSError('private transport unavailable')))
    with pytest.raises(ledger.CreditsError, match='credits_unavailable'):
        d1.read('alice')
    assert store.read('alice')['balance_microusd'] == 0


def test_private_transport_validates_response_and_preserves_errors(store):
    entry = append(store, 'credit', 100, 'fund', 0)
    response = dict(version=1, entry=entry)
    d1 = ledger.D1CreditsLedger(lambda _: response)
    assert d1.append('alice', 'credit', 100, 'fund', 0) == entry
    for altered in ({**entry, 'amount_microusd': True}, {**entry, 'operation_id': 'foreign'},
                    {**entry, 'revision': 2}, {**entry, 'prompt': 'private'}, {**entry, 'balance_delta': 99}):
        with pytest.raises(ledger.CreditsError) as error:
            ledger.D1CreditsLedger(lambda _: dict(version=1, entry=altered)).append('alice', 'credit', 100, 'fund', 0)
        assert error.value.code == 'credits_unavailable' and error.value.status == 503
    summary = store.read('alice')
    assert ledger.D1CreditsLedger(lambda _: dict(version=1, summary=summary)).read('alice') == summary
    for altered in ({**summary, 'available_microusd': 101}, {**summary, 'next_cursor': 'bogus'}, {**summary, 'prompt': 'private'}):
        with pytest.raises(ledger.CreditsError, match='credits_unavailable'):
            ledger.D1CreditsLedger(lambda _: dict(version=1, summary=altered)).read('alice')
    with pytest.raises(ledger.CreditsError) as error:
        ledger.D1CreditsLedger(lambda _: dict(version=1, error={'code': 'credits_revision_mismatch'})).read('alice')
    assert error.value.status == 412


def test_disabled_authority_never_prices_or_changes_storage(store, monkeypatch):
    def forbidden(*args):
        pytest.fail('disabled tariff evaluated')
    authority = ledger.register_credit_authority(store, tariff=forbidden)
    monkeypatch.setenv('CREDITS_ENABLED', '')
    with pytest.raises(AuthorityDenied, match='credits_disabled'):
        authority.reserve(AuthorityOperation(TenantContext('alice'), 'attempt', 0, 'disabled', 0))
    assert store.read('alice')['revision'] == 0


def test_registered_authority_denial_stops_provider_before_handoff(tmp_path, monkeypatch):
    from flask import Flask
    from types import SimpleNamespace
    from routes import credits
    monkeypatch.setenv('CREDITS_ENABLED', 'true')
    monkeypatch.setenv('CREDITS_CURRENCY', 'USD')
    store = ledger.SqlCreditsLedger(tmp_path / 'missing.sqlite3')
    authority = ledger.register_credit_authority(store, tariff=lambda *_: 1)
    app = Flask('credits-admission')
    credits.register_credits_routes(app, SimpleNamespace(exempt=lambda fn: fn), store=store)
    provider_calls = []
    def generation():
        authority.reserve(AuthorityOperation(TenantContext('alice'), 'attempt', 0, 'hold', 1))
        provider_calls.append('called')
        return 'provider result'
    app.add_url_rule('/generation', 'generation', generation)
    response = app.test_client().get('/generation')
    assert response.status_code == 503 and response.json['error']['code'] == 'credits_unavailable'
    assert provider_calls == [] and not store.path.exists()


def test_registered_real_auth_scope_and_missing_schema(store, tmp_path, monkeypatch):
    from flask import Flask
    from types import SimpleNamespace
    from routes import credits
    helpers = credits.api_authenticate_only.__globals__
    def authenticate(key, address):
        if key == 'models-test':
            return {'username': 'alice', 'scopes': ['models']}
        if key == 'chat-test':
            return {'username': 'alice', 'scopes': ['chat']}
        return None
    monkeypatch.setattr(helpers['AuthService'], 'verify_api_key', authenticate)
    monkeypatch.setattr(helpers['request_accounting'], 'check_key_controls', lambda user: None)
    monkeypatch.setattr(helpers['request_accounting'], 'begin', lambda: None)
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'synthetic-test-secret'
    credits.register_credits_routes(app, SimpleNamespace(exempt=lambda fn: fn), store=store)
    client = app.test_client()
    append(store, 'credit', 100, 'fund', 0)
    assert client.get('/v1/credits', headers={'Authorization': 'Bearer chat-test'}).status_code == 403
    assert client.get('/v1/credits').status_code == 401
    assert client.get('/v1/credits?owner=bob', headers={'Authorization': 'Bearer models-test'}).json['balance_microusd'] == 100
    assert client.get('/v1/credits?limit=101', headers={'Authorization': 'Bearer models-test'}).status_code == 400
    assert client.get('/v1/credits?cursor=-1', headers={'Authorization': 'Bearer models-test'}).status_code == 400
    missing = ledger.SqlCreditsLedger(tmp_path / 'absent.sqlite3')
    other = Flask('missing-credits')
    other.config['SECRET_KEY'] = 'synthetic-test-secret'
    credits.register_credits_routes(other, SimpleNamespace(exempt=lambda fn: fn), store=missing)
    response = other.test_client().get('/v1/credits', headers={'Authorization': 'Bearer models-test'})
    assert response.status_code == 503 and response.json['error']['code'] == 'credits_unavailable'
    assert not missing.path.exists()


def test_real_admin_session_csrf_audit_and_disabled_response_bytes(store, monkeypatch):
    from flask import Flask
    from flask_wtf.csrf import CSRFProtect, generate_csrf
    from routes import credits
    session_authority = credits.login_required.__globals__['AuthService']
    admin_authority = credits.require_admin_dashboard_user.__globals__['AuthService']
    signed_in = {'value': False}
    user = {'username': 'member', 'is_admin': False}
    monkeypatch.setattr(session_authority, 'is_authenticated', lambda: signed_in['value'])
    monkeypatch.setattr(admin_authority, 'get_current_user', lambda: user)
    app = Flask('credits-admin-security')
    app.config.update(SECRET_KEY='synthetic-test-secret', TESTING=True)
    app.add_url_rule('/login', 'login', lambda: 'login')
    app.add_url_rule('/csrf-token', 'token', lambda: {'csrf_token': generate_csrf()})
    app.add_url_rule('/existing', 'existing', lambda: ('unchanged', 201, {'X-Existing': 'value'}))
    csrf = CSRFProtect(app)
    credits.register_credits_routes(app, csrf, store=store)
    client = app.test_client()
    assert client.get('/admin/credits/alice').status_code == 302
    signed_in['value'] = True
    assert client.get('/admin/credits/alice').status_code == 403
    token = client.get('/csrf-token').json['csrf_token']
    body = dict(owner='alice', amount_microusd=100, operation_id='fund', reason='Reviewed allocation')
    assert client.post('/admin/credits/adjust', json=body, headers={'If-Match': '"0"', 'X-CSRFToken': token}).status_code == 403
    user.update(username='admin', is_admin=True)
    assert client.post('/admin/credits/adjust', json=body, headers={'If-Match': '"0"'}).status_code == 400
    result = client.post('/admin/credits/adjust', json=body, headers={'If-Match': '"0"', 'X-CSRFToken': token})
    assert result.status_code == 200 and result.headers['ETag'] == '"1"'
    assert client.post('/admin/credits/adjust', json=body, headers={'If-Match': '"0"', 'X-CSRFToken': token}).json == result.json
    with sqlite3.connect(store.path) as db:
        assert db.execute('SELECT actor FROM credits_audit').fetchone() == ('admin',)
    before = client.get('/existing')
    monkeypatch.setenv('CREDITS_ENABLED', '')
    after = client.get('/existing')
    assert (after.data, after.status_code, dict(after.headers)) == (before.data, before.status_code, dict(before.headers))
    assert client.post('/admin/credits/adjust', json=body).status_code == 404
    assert store.read('alice')['balance_microusd'] == 100


def test_registered_routes_auth_cas_and_no_store(store, monkeypatch):
    from flask import Flask, g
    from flask_wtf.csrf import CSRFProtect
    from routes import credits
    import route_helpers
    # Decorator collaborators are injected before route registration.
    def auth(required_scope):
        assert required_scope == 'models'
        def decorate(fn):
            def wrapped(*args, **kwargs):
                from flask import request
                if request.headers.get('Authorization') != 'Bearer synthetic':
                    return {'error': 'unauthorized'}, 401
                g.authenticated_user = {'username': 'alice'}
                return fn(*args, **kwargs)
            wrapped.__name__ = fn.__name__
            return wrapped
        return decorate
    monkeypatch.setattr(credits, 'api_authenticate_only', auth)
    monkeypatch.setattr(credits, 'login_required', lambda fn: fn)
    monkeypatch.setattr(credits, 'require_admin_dashboard_user', lambda: {'username': 'admin'})
    monkeypatch.setattr(route_helpers, 'login_required', lambda fn: fn)
    monkeypatch.setenv('CREDITS_ENABLED', 'false')
    monkeypatch.setenv('CREDITS_CURRENCY', 'USD')
    app = Flask(__name__)
    app.config.update(SECRET_KEY='synthetic-test-secret', TESTING=True)
    csrf = CSRFProtect(app)
    credits.register_credits_routes(app, csrf, store=store)
    client = app.test_client()
    assert client.get('/v1/credits').status_code == 404
    assert client.post('/admin/credits/adjust', json={}).status_code == 404
    monkeypatch.setenv('CREDITS_ENABLED', 'true')
    assert client.get('/v1/credits').status_code == 401
    response = client.get('/v1/credits?owner=bob', headers={'Authorization': 'Bearer synthetic'})
    assert response.json['entries'] == []
    assert response.headers['Cache-Control'] == 'no-store'
    assert client.post('/admin/credits/adjust', json={}).status_code == 400
    app.config['WTF_CSRF_ENABLED'] = False
    body = dict(owner='alice', amount_microusd=100, operation_id='grant', reason='reviewed')
    assert client.post('/admin/credits/adjust', json=body).status_code == 428
    assert client.post('/admin/credits/adjust', json=body, headers={'If-Match': '"1"'}).status_code == 412
    assert client.post('/admin/credits/adjust', json=body, headers={'If-Match': '"0"'}).status_code == 200
    assert client.get('/admin/credits/alice').headers['ETag'] == '"1"'
    monkeypatch.setattr(credits, 'require_admin_dashboard_user', lambda: (_ for _ in ()).throw(ledger.CreditsError('admin_required', 403)))
    assert client.get('/admin/credits/alice').status_code == 403
