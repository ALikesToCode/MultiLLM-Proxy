"""Immutable integer credits and revision-bound, fail-closed spending authority."""
from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import threading
from contextlib import closing
from pathlib import Path
from typing import Mapping

from services.enterprise_contract import (AuthorityDenied, AuthorityOperation, AuthorityResult,
                                          TenantContext, register_enterprise_adapters)
from services.sqlite_store import storage_path

MAX_AMOUNT = 10**15
MIGRATION = '0037_credits_ledger.sql'
TABLES = ('credits_balances', 'credits_entries', 'credits_audit')
_warned: set[str] = set()
_warn_lock = threading.Lock()
logger = logging.getLogger(__name__)


class CreditsError(Exception):
    def __init__(self, code='credits_unavailable', status=503):
        super().__init__(code)
        self.code, self.status = code, status


class CreditDenied(AuthorityDenied):
    """Bounded error metadata lets request admission return a JSON denial."""
    def __init__(self, code, status=503):
        super().__init__(code)
        self.code, self.status = code, status


def _warn(name):
    with _warn_lock:
        if name not in _warned:
            _warned.add(name)
            logger.warning('Invalid %s; credits disabled', name)


def enabled(env: Mapping | None = None) -> bool:
    values = os.environ if env is None else env
    raw = values.get('CREDITS_ENABLED', '')
    flag = raw.strip().lower() if isinstance(raw, str) else 'invalid'
    if flag in {'', '0', 'false', 'no', 'off'}:
        return False
    if flag not in {'1', 'true', 'yes', 'on'}:
        _warn('CREDITS_ENABLED')
        return False
    currency = values.get('CREDITS_CURRENCY', '')
    if currency == '':
        currency = 'USD'
    if currency != 'USD':
        _warn('CREDITS_CURRENCY')
        return False
    return True


def integer(value, *, nonnegative=False):
    if type(value) is not int or not (-MAX_AMOUNT <= value <= MAX_AMOUNT) or (nonnegative and value < 0):
        raise CreditsError('invalid_credits_request', 400)
    return value


def label(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_:.\-]{1,128}', value):
        raise CreditsError('invalid_credits_request', 400)
    return value


def reason_text(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 512 or any(ord(c) < 32 or ord(c) > 126 for c in value):
        raise CreditsError('invalid_credits_request', 400)
    return value


def owner_id(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 512 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise CreditsError('invalid_credits_request', 400)
    return value


def context_owner(context: TenantContext) -> str:
    if type(context) is not TenantContext:
        raise CreditsError('invalid_credits_request', 400)
    if context.org_id is None:
        return owner_id(context.principal_id)
    # JSON tuple delimiters cannot collide with legacy opaque principal IDs.
    return 'tenant:' + json.dumps([context.org_id, context.team_id, context.principal_id], separators=(',', ':'))


def request_fields(owner, kind, amount_microusd, operation_id, revision, *, scoped_id=None,
                   reference=None, tariff_revision=None, actor=None, reason=None, unknown=False):
    owner_id(owner)
    label(operation_id)
    integer(revision, nonnegative=True)
    integer(amount_microusd)
    if kind not in {'credit', 'reserve', 'commit', 'release', 'adjust', 'compensate'} or type(unknown) is not bool:
        raise CreditsError('invalid_credits_request', 400)
    for value in (scoped_id, reference, actor):
        if value is not None:
            label(value)
    if kind in {'reserve', 'commit', 'release'}:
        label(scoped_id)
        integer(amount_microusd, nonnegative=True)
    if kind in {'reserve', 'commit'} and not unknown:
        if tariff_revision is None:
            raise CreditsError('credits_unpriced', 503)
        integer(tariff_revision, nonnegative=True)
    elif tariff_revision is not None:
        integer(tariff_revision, nonnegative=True)
    if kind == 'credit':
        integer(amount_microusd, nonnegative=True)
    if kind in {'adjust', 'compensate'}:
        label(actor)
        reason_text(reason)
    elif reason is not None:
        reason_text(reason)
    if kind == 'compensate':
        label(reference)
    elif reference is not None:
        raise CreditsError('invalid_credits_request', 400)
    if unknown and (kind != 'reserve' or amount_microusd != 0):
        raise CreditsError('invalid_credits_request', 400)
    return dict(owner=owner, kind=kind, amount_microusd=amount_microusd, operation_id=operation_id,
                revision=revision, scoped_id=scoped_id, reference=reference, tariff_revision=tariff_revision,
                actor=actor, reason=reason, unknown=unknown)


def deltas(fields, entries):
    kind, amount = fields['kind'], fields['amount_microusd']
    balance_delta, held_delta = 0, 0
    if kind in {'credit', 'adjust'}:
        balance_delta = amount
    elif kind == 'compensate':
        original = next((row for row in entries if row['operation_id'] == fields['reference']), None)
        if (not original or original['kind'] not in {'credit', 'adjust', 'commit'}
                or amount != -original['balance_delta']
                or any(row['kind'] == 'compensate' and row['reference'] == fields['reference'] for row in entries)):
            raise CreditsError('credits_conflict', 409)
        balance_delta = amount
    else:
        attempt = [row for row in entries if row['scoped_id'] == fields['scoped_id']]
        hold = next((row for row in attempt if row['kind'] == 'reserve' and row['reference'] is None), None)
        terminal = any(row['kind'] in {'commit', 'release'} for row in attempt)
        if kind == 'reserve' and not fields['unknown']:
            if hold:
                raise CreditsError('credits_conflict', 409)
            held_delta = amount
        else:
            if not hold or terminal:
                raise CreditsError('credits_conflict', 409)
            fields['reference'] = hold['operation_id']
            if kind == 'commit':
                balance_delta, held_delta = -amount, -hold['amount_microusd']
            elif kind == 'release':
                if amount != hold['amount_microusd']:
                    raise CreditsError('invalid_credits_request', 400)
                held_delta = -amount
    return balance_delta, held_delta


def pagination(cursor, limit):
    if (not isinstance(cursor, str) or not re.fullmatch(r'[0-9]{1,16}', cursor)
            or int(cursor) > MAX_AMOUNT or type(limit) is not int or not 1 <= limit <= 100):
        raise CreditsError('invalid_credits_request', 400)
    return int(cursor)


def public_entry(row):
    return {key: row[key] for key in ('operation_id', 'revision', 'kind', 'amount_microusd',
                                     'balance_delta', 'held_delta', 'scoped_id', 'reference', 'tariff_revision')}


class SqlCreditsLedger:
    """SQLite transactions serialize CAS and preserve event/balance atomicity."""
    def __init__(self, path=None, *, initialize=False):
        self.path = Path(path) if path is not None else storage_path('USAGE_DB_PATH', 'usage.sqlite3')
        if initialize:
            self._run(lambda db: db.executescript((Path(__file__).resolve().parents[1] / 'intelligence-migrations' / MIGRATION).read_text()), check=False)

    def _run(self, action, *, check=True):
        try:
            if check and not self.path.is_file():
                raise CreditsError()
            target = self.path.resolve().as_uri() + '?mode=rw' if check else str(self.path)
            with closing(sqlite3.connect(target, timeout=10, uri=check)) as db, db:
                db.row_factory = sqlite3.Row
                db.execute('BEGIN IMMEDIATE')
                if check:
                    db.execute('SELECT owner,operation_id,revision,kind,amount_microusd,balance_delta,held_delta,scoped_id,reference,tariff_revision,actor,reason,document FROM credits_entries LIMIT 0')
                    db.execute('SELECT owner,operation_id,revision,actor,kind FROM credits_audit LIMIT 0')
                    db.execute('SELECT balance_microusd, held_microusd, revision FROM credits_balances LIMIT 0')
                return action(db)
        except (sqlite3.Error, OSError):
            raise CreditsError() from None

    def append(self, owner, kind, amount_microusd, operation_id, revision, **kwargs):
        fields = request_fields(owner, kind, amount_microusd, operation_id, revision, **kwargs)
        document = json.dumps(fields, sort_keys=True, ensure_ascii=False, separators=(',', ':'))
        def write(db):
            existing = db.execute('SELECT * FROM credits_entries WHERE owner=? AND operation_id=?', (owner, operation_id)).fetchone()
            if existing:
                if existing['document'] != document:
                    raise CreditsError('credits_conflict', 409)
                return public_entry(existing)
            row = db.execute('SELECT * FROM credits_balances WHERE owner=?', (owner,)).fetchone()
            balance, held, current = (row['balance_microusd'], row['held_microusd'], row['revision']) if row else (0, 0, 0)
            if current != revision:
                raise CreditsError('credits_revision_mismatch', 412)
            entries = [dict(item) for item in db.execute('SELECT * FROM credits_entries WHERE owner=? AND (scoped_id=? OR operation_id=? OR reference=?)',
                                                        (owner, fields['scoped_id'], fields['reference'], fields['reference']))]
            bd, hd = deltas(fields, entries)
            integer(balance + bd)
            integer(held + hd, nonnegative=True)
            integer(revision + 1, nonnegative=True)
            available = balance + bd - held - hd
            reservation = kind == 'reserve' and not fields['unknown']
            enforced_spend = reservation or (kind == 'adjust' and amount_microusd < 0)
            if enforced_spend and (available < 0 or (reservation and balance - held <= 0)):
                raise CreditsError('credits_insufficient', 409)
            db.execute('INSERT OR IGNORE INTO credits_balances(owner) VALUES (?)', (owner,))
            changed = db.execute('UPDATE credits_balances SET balance_microusd=?, held_microusd=?, revision=revision+1 WHERE owner=? AND revision=?',
                                 (balance + bd, held + hd, owner, revision)).rowcount
            if changed != 1:
                raise CreditsError('credits_revision_mismatch', 412)
            db.execute('''INSERT INTO credits_entries
                       (owner,operation_id,revision,kind,amount_microusd,balance_delta,held_delta,scoped_id,reference,tariff_revision,actor,reason,document)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                       (owner, operation_id, revision + 1, kind, amount_microusd, bd, hd, fields['scoped_id'], fields['reference'],
                        fields['tariff_revision'], fields['actor'], fields['reason'], document))
            if fields['actor']:
                db.execute('INSERT INTO credits_audit VALUES (?,?,?,?,?)', (owner, operation_id, revision + 1, fields['actor'], kind))
            return public_entry(db.execute('SELECT * FROM credits_entries WHERE owner=? AND operation_id=?', (owner, operation_id)).fetchone())
        return self._run(write)

    def read(self, owner, *, cursor='0', limit=100):
        owner_id(owner)
        after = pagination(cursor, limit)
        def read(db):
            row = db.execute('SELECT * FROM credits_balances WHERE owner=?', (owner,)).fetchone()
            balance, held, revision = (row['balance_microusd'], row['held_microusd'], row['revision']) if row else (0, 0, 0)
            rows = db.execute('SELECT * FROM credits_entries WHERE owner=? AND revision>? ORDER BY revision LIMIT ?', (owner, after, limit + 1)).fetchall()
            page = rows[:limit]
            return dict(currency='USD', balance_microusd=balance, held_microusd=held, available_microusd=balance-held,
                        revision=revision, entries=[public_entry(item) for item in page],
                        next_cursor=str(page[-1]['revision']) if len(rows) > limit else None)
        return self._run(read)


class D1CreditsLedger:
    """Private transport without retries or local fallback on authority failure."""
    def __init__(self, call):
        self.call = call

    def _call(self, operation, **values):
        try:
            result = self.call({'version': 1, 'operation': operation, **values})
            if not isinstance(result, dict) or type(result.get('version')) is not int or result.get('version') != 1:
                raise CreditsError()
            if 'error' in result:
                code = result['error'].get('code')
                statuses = {'credits_conflict': 409, 'credits_insufficient': 409, 'credits_revision_mismatch': 412,
                            'invalid_credits_request': 400, 'credits_unpriced': 503}
                raise CreditsError(code if code in statuses else 'credits_unavailable', statuses.get(code, 503))
            try:
                return _validate_private_result(operation, result, values)
            except CreditsError:
                raise CreditsError() from None
        except CreditsError:
            raise
        except Exception as error:
            statuses = {'credits_conflict': 409, 'credits_insufficient': 409, 'credits_revision_mismatch': 412,
                        'invalid_credits_request': 400, 'credits_unpriced': 503}
            code = getattr(error, 'code', None)
            raise CreditsError(code if code in statuses else 'credits_unavailable', statuses.get(code, 503)) from None

    def append(self, owner, kind, amount_microusd, operation_id, revision, **kwargs):
        fields = request_fields(owner, kind, amount_microusd, operation_id, revision, **kwargs)
        return self._call('append', **fields)

    def read(self, owner, *, cursor='0', limit=100):
        owner_id(owner)
        pagination(cursor, limit)
        return self._call('read', owner=owner, cursor=cursor, limit=limit)


def _validate_entry(value):
    fields = {'operation_id', 'revision', 'kind', 'amount_microusd', 'balance_delta', 'held_delta',
              'scoped_id', 'reference', 'tariff_revision'}
    if not isinstance(value, dict) or set(value) != fields:
        raise CreditsError()
    label(value['operation_id'])
    integer(value['revision'], nonnegative=True)
    for name in ('amount_microusd', 'balance_delta', 'held_delta'):
        integer(value[name])
    for name in ('scoped_id', 'reference'):
        if value[name] is not None:
            label(value[name])
    if value['tariff_revision'] is not None:
        integer(value['tariff_revision'], nonnegative=True)
    kind, amount, bd, hd = (value[name] for name in ('kind', 'amount_microusd', 'balance_delta', 'held_delta'))
    if kind in {'credit', 'adjust', 'compensate'}:
        valid = bd == amount and hd == 0 and (kind != 'credit' or amount >= 0)
    elif kind == 'reserve':
        valid = amount >= 0 and bd == 0 and hd in {0, amount} and value['scoped_id'] is not None
    elif kind in {'commit', 'release'}:
        valid = amount >= 0 and hd <= 0 and bd == (-amount if kind == 'commit' else 0) and value['reference'] is not None
    else:
        valid = False
    if not valid:
        raise CreditsError()


def _validate_private_result(operation, result, values):
    name = 'entry' if operation == 'append' else 'summary'
    if set(result) != {'version', name}:
        raise CreditsError()
    value = result[name]
    if operation == 'append':
        _validate_entry(value)
        if (any(value[key] != values[key] for key in ('operation_id', 'kind', 'amount_microusd', 'scoped_id', 'tariff_revision'))
                or value['revision'] != values['revision'] + 1):
            raise CreditsError()
        return value
    if not isinstance(value, dict) or set(value) != {'currency', 'balance_microusd', 'held_microusd', 'available_microusd', 'revision', 'entries', 'next_cursor'}:
        raise CreditsError()
    for field in ('balance_microusd', 'held_microusd', 'available_microusd', 'revision'):
        integer(value[field], nonnegative=field in {'held_microusd', 'revision'})
    if (value['currency'] != 'USD' or value['available_microusd'] != value['balance_microusd'] - value['held_microusd']
            or not isinstance(value['entries'], list) or len(value['entries']) > values['limit']):
        raise CreditsError()
    after = int(values['cursor'])
    for entry in value['entries']:
        _validate_entry(entry)
        if not after < entry['revision'] <= value['revision']:
            raise CreditsError()
        after = entry['revision']
    if value['next_cursor'] is not None and (not value['entries'] or value['next_cursor'] != str(after) or len(value['entries']) != values['limit']):
        raise CreditsError()
    return value


def open_store():
    from services import control_state_d1
    if control_state_d1.using_d1():
        def call(document):
            values = {key: value for key, value in document.items() if key not in {'version', 'operation'}}
            return control_state_d1.call('credits', document['operation'], **values)
        return D1CreditsLedger(call)
    if os.environ.get('INTELLIGENCE_STORAGE_BACKEND', '').strip():
        raise CreditsError()
    return SqlCreditsLedger()


class LedgerCreditAuthority:
    """Tariff returns its reviewed revision, or None when cost is unknown/unpriced."""
    def __init__(self, store, tariff):
        self.store, self.tariff = store, tariff

    def _apply(self, operation, phase):
        if type(operation) is not AuthorityOperation:
            raise TypeError('AuthorityOperation required')
        if not enabled():
            raise CreditDenied('credits_disabled', 404)
        try:
            tariff_revision = self.tariff(operation, phase)
            unknown = phase == 'reconcile' and tariff_revision is None
            if tariff_revision is None and not unknown:
                raise CreditDenied('credits_unpriced')
            kind = 'reserve' if phase == 'reserve' or unknown else 'commit'
            entry = self.store.append(context_owner(operation.context), kind, 0 if unknown else operation.amount,
                                      operation.operation_id, operation.revision, scoped_id=operation.scoped_id,
                                      tariff_revision=tariff_revision, unknown=unknown)
            return AuthorityResult(operation.context, operation.scoped_id, entry['revision'], operation.operation_id, True)
        except CreditsError as error:
            raise CreditDenied(error.code, error.status) from None

    def reserve(self, operation):
        return self._apply(operation, 'reserve')

    def commit(self, operation):
        return self._apply(operation, 'commit')

    def reconcile(self, operation):
        return self._apply(operation, 'reconcile')


def register_credit_authority(store, *, tariff):
    if not callable(tariff):
        raise TypeError('Explicit operator tariff required')
    return LedgerCreditAuthority(store, tariff)


def register_enterprise_credit(authority):
    return register_enterprise_adapters(credit=authority)
