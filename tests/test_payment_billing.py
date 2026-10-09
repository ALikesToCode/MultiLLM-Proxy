"""Offline checkout, signed evidence, durable claims and authenticated routes."""
import hashlib
import hmac
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs

import pytest
from flask import Flask, g

from services import payment_billing as pb
from services.enterprise_contract import AuthorityResult, TenantContext
from routes import payments

NOW = 1700000000
SECRET = "public-test-webhook-secret"
VECTOR = b'{"id":"evt_vector","object":"event","type":"unknown","livemode":false}'
SIGNATURE = hmac.new(SECRET.encode(), str(NOW).encode() + b"." + VECTOR, hashlib.sha256).hexdigest()
ROOT = Path(__file__).resolve().parents[1]
CONFIG = {"processor": "stripe", "secret_key_ref": "PAYMENT_TEST_KEY",
          "return_origins": ["https://portal.test"], "product_name": "Gateway credits"}
ENV = {"PAYMENTS_ENABLED": "true", "PAYMENT_PROCESSOR_CONFIG_JSON": json.dumps(CONFIG),
       "PAYMENT_WEBHOOK_KEY_REF": "PAYMENT_TEST_WEBHOOK"}
BODY = {"amount_microusd": 500000, "currency": "USD", "idempotency_key": "order-1",
        "return_url": "https://portal.test/paid"}


@pytest.fixture
def setup(tmp_path):
    path = tmp_path / "payments.sqlite"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE old_rows (value TEXT)")
        db.execute("INSERT INTO old_rows VALUES ('retained')")
        migration = (ROOT / "intelligence-migrations/0038_payment_billing.sql").read_text()
        db.executescript(migration)
        db.executescript(migration)
        assert db.execute("SELECT value FROM old_rows").fetchone()[0] == "retained"
    store = pb.SqlPaymentStore(path)
    calls, credited = [], []
    def http(url, *, headers, body):
        calls.append((url, headers, parse_qs(body)))
        fields = calls[-1][2]
        return {"id": "cs_" + fields["client_reference_id"][0], "object": "checkout.session",
                "url": "https://checkout.stripe.com/c/pay_test", "amount_total": int(fields["line_items[0][price_data][unit_amount]"][0]),
                "currency": "usd", "livemode": False}
    def callback(event):
        credited.append(event)
        return AuthorityResult(event.context, event.scoped_id, event.revision + 1, event.idempotency_id, True)
    service = pb.PaymentBilling(store=store, env=ENV, http=http, secret_resolver=lambda ref: SECRET,
                                callback=callback, clock=lambda: NOW)
    return SimpleNamespace(store=store, service=service, calls=calls, credited=credited, path=path)


def checkout(setup, **changes):
    return setup.service.checkout(TenantContext("alice"), "alice", {**BODY, **changes})


def event(row, kind="checkout.session.completed", **changes):
    obj = {"id": "cs_" + row["checkout_id"], "client_reference_id": row["checkout_id"],
           "metadata": {"checkout_id": row["checkout_id"]}, "payment_status": "paid",
           "amount_total": row["amount_microusd"] // 10000, "currency": "usd", "livemode": False,
           "payment_intent": "pi_test"}
    obj.update(changes.pop("object_changes", {}))
    return {"id": "evt_paid", "object": "event", "type": kind, "livemode": False,
            "data": {"object": obj}, **changes}


def deliver(service, value):
    raw = json.dumps(value, separators=(",", ":")).encode()
    signature = hmac.new(SECRET.encode(), str(NOW).encode() + b"." + raw, hashlib.sha256).hexdigest()
    return service.webhook(raw, f"t={NOW},v1={signature}")


@pytest.mark.parametrize("flag", [None, "", "false", "0", "junk"])
def test_default_off_has_no_io(flag, caplog):
    env = {**ENV, "PAYMENTS_ENABLED": flag}
    service = pb.PaymentBilling(env=env, secret_resolver=lambda _: pytest.fail("disabled secret"))
    with pytest.raises(pb.PaymentError) as caught:
        service.checkout(TenantContext("alice"), "alice", BODY)
    assert caught.value.status == 404
    with pytest.raises(pb.PaymentError):
        service.webhook(VECTOR, "")


@pytest.mark.parametrize("config", ["{", "[]", '{"processor":"other"}', json.dumps({**CONFIG, "secret_key_ref": "bad ref"}),
                                    json.dumps({**CONFIG, "return_origins": ["https://portal.test/path"]})])
def test_invalid_configuration_disables_without_values(config, caplog):
    pb._warn_once.cache_clear()
    for _ in range(2):
        assert pb.settings({**ENV, "PAYMENT_PROCESSOR_CONFIG_JSON": config}) is None
    assert len(caplog.records) == 1 and config not in caplog.text


@pytest.mark.parametrize("amount", [True, 1, 499999, 500001, 1000000001, 500000.0, "500000"])
def test_amount_contract_before_http(setup, amount):
    with pytest.raises(pb.PaymentError) as caught:
        checkout(setup, amount_microusd=amount)
    assert caught.value.status == 400 and not setup.calls


@pytest.mark.parametrize("url", ["https://portal.test.evil/", "https://portal.test@evil.test/", "http://portal.test/", "https://portal.test:444/", "https://portal.test/\n"])
def test_exact_return_origin(setup, url):
    with pytest.raises(pb.PaymentError):
        checkout(setup, return_url=url)
    assert not setup.calls


def test_checkout_fixed_schema_idempotency_velocity_and_concurrency(setup):
    with ThreadPoolExecutor(max_workers=4) as pool:
        rows = list(pool.map(lambda _: checkout(setup), range(4)))
    assert rows == [rows[0]] * 4 and len(setup.calls) == 1
    assert rows[0]["status"] == "pending" and not setup.credited
    url, headers, fields = setup.calls[0]
    assert url == "https://api.stripe.com/v1/checkout/sessions"
    assert headers["Idempotency-Key"] == rows[0]["checkout_id"]
    assert fields["metadata[checkout_id]"] == [rows[0]["checkout_id"]]
    assert fields["client_reference_id"] == [rows[0]["checkout_id"]]
    assert fields["line_items[0][price_data][unit_amount]"] == ["50"]
    with pytest.raises(pb.PaymentError) as conflict:
        checkout(setup, amount_microusd=510000)
    assert conflict.value.status == 409
    for n in range(9):
        checkout(setup, idempotency_key=f"order-{n+2}")
    with pytest.raises(pb.PaymentError) as limited:
        checkout(setup, idempotency_key="eleven")
    assert limited.value.code == "payment_velocity_limited" and limited.value.status == 429


def test_foreign_workspace_requires_explicit_permission(setup):
    with pytest.raises(pb.PaymentError) as caught:
        setup.service.checkout(TenantContext("alice", "foreign"), "alice", BODY)
    assert caught.value.status == 403 and not setup.calls
    setup.service.permission = lambda context, owner: context.org_id == "allowed" and owner == "alice"
    assert setup.service.checkout(TenantContext("alice", "allowed"), "alice", BODY)["status"] == "pending"


def test_signature_shared_vector_rotation_raw_bytes_and_time():
    assert pb.verify_signature(VECTOR, f"t={NOW},v1={'0'*64},v1={SIGNATURE}", SECRET, NOW)
    assert pb.verify_signature(VECTOR, f"t={NOW},v1={SIGNATURE}", SECRET, NOW + 300)
    for raw, header, now in [(VECTOR+b" ", f"t={NOW},v1={SIGNATURE}", NOW),
                             (VECTOR, f"t={NOW},v0={SIGNATURE}", NOW),
                             (VECTOR, f"t={NOW},t={NOW},v1={SIGNATURE}", NOW),
                             (VECTOR, f"t={NOW},v1={SIGNATURE}", NOW + 301),
                             (VECTOR, f"t={NOW},v1={SIGNATURE}", NOW - 301)]:
        assert not pb.verify_signature(raw, header, SECRET, now)


def test_invalid_signature_has_no_state_change(setup):
    with pytest.raises(pb.PaymentError) as caught:
        setup.service.webhook(VECTOR, f"t={NOW},v1={'0'*64}")
    assert caught.value.status == 400
    with sqlite3.connect(setup.path) as db:
        assert db.execute("SELECT COUNT(*) FROM payment_events").fetchone()[0] == 0


def test_verified_payment_once_across_replays_and_success_types(setup):
    row = checkout(setup)
    value = event(row)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: deliver(setup.service, value), range(4)))
    assert all(result["received"] for result in results)
    assert len(setup.credited) == 1
    assert deliver(setup.service, event(row, "checkout.session.async_payment_succeeded", id="evt_async"))["received"]
    assert len(setup.credited) == 1 and setup.credited[0].verified
    assert setup.credited[0].amount == 500000
    with pytest.raises(Exception):
        setup.credited[0].amount = 0


@pytest.mark.parametrize("change", [{"account": "foreign"}, {"livemode": True},
                                    {"object_changes": {"currency": "eur"}},
                                    {"object_changes": {"amount_total": 51}},
                                    {"object_changes": {"id": "cs_other"}}])
def test_mismatch_recorded_without_credit(setup, change):
    row = checkout(setup)
    assert deliver(setup.service, event(row, **change))["status"] == "mismatch"
    assert not setup.credited


def test_delayed_payment_failure_unknown_and_missing_callback_retry(setup):
    row = checkout(setup)
    assert deliver(setup.service, event(row, object_changes={"payment_status": "unpaid"}))["status"] == "ignored"
    assert not setup.credited
    assert deliver(setup.service, event(row, "checkout.session.async_payment_failed", id="evt_failed"))["status"] == "failed"
    assert deliver(setup.service, {"id": "evt_unknown", "type": "unknown", "object": "event"})["status"] == "ignored"
    setup.service.callback = None
    paid = event(row, "checkout.session.async_payment_succeeded", id="evt_retry")
    with pytest.raises(pb.PaymentError) as unavailable:
        deliver(setup.service, paid)
    assert unavailable.value.code == "payment_credit_unavailable"
    with sqlite3.connect(setup.path) as db:
        assert db.execute("SELECT status FROM payment_events WHERE event_id='evt_retry'").fetchone()[0] == "pending_credit"
    setup.service.callback = lambda e: AuthorityResult(e.context, e.scoped_id, e.revision + 1, e.idempotency_id, True)
    assert deliver(setup.service, paid)["status"] == "credited"


def test_refund_cumulative_delta_and_dispute_append(setup):
    row = checkout(setup)
    deliver(setup.service, event(row))
    charge = {"id": "ch_test", "payment_intent": "pi_test", "amount": 50, "amount_refunded": 20, "currency": "usd", "livemode": False}
    value = {"id": "evt_refund", "object": "event", "type": "charge.refunded", "livemode": False, "data": {"object": charge}}
    assert deliver(setup.service, value)["status"] == "refunded"
    deliver(setup.service, {**value, "id": "evt_refund_duplicate"})
    charge = {**charge, "amount_refunded": 50}
    deliver(setup.service, {**value, "id": "evt_refund_rest", "data": {"object": charge}})
    dispute = {"id": "dp_test", "charge": "ch_test", "payment_intent": "pi_test", "amount": 50, "currency": "usd", "livemode": False}
    deliver(setup.service, {**value, "id": "evt_dispute", "type": "charge.dispute.created", "data": {"object": dispute}})
    deliver(setup.service, {**value, "id": "evt_dispute_repeated", "type": "charge.dispute.created", "data": {"object": dispute}})
    assert [(e.kind, e.amount) for e in setup.credited] == [("credit", 500000), ("refund", 200000), ("refund", 300000), ("dispute", 500000)]


def test_callback_failure_keeps_stable_operation_and_no_false_success(setup):
    row = checkout(setup)
    operations = []
    def failure(e):
        operations.append(e.idempotency_id)
        raise RuntimeError("private detail")
    setup.service.callback = failure
    with pytest.raises(pb.PaymentError) as caught:
        deliver(setup.service, event(row))
    assert caught.value.code == "payment_credit_unavailable" and "private" not in str(caught.value)
    def success(e):
        operations.append(e.idempotency_id)
        return AuthorityResult(e.context, e.scoped_id, e.revision+1, e.idempotency_id, True)
    setup.service.callback = success
    deliver(setup.service, event(row))
    assert operations[0] == operations[1]


def test_refund_before_session_is_retried_and_reconciled(setup):
    row = checkout(setup)
    value = {"id": "evt_early", "object": "event", "type": "charge.refunded", "livemode": False,
             "data": {"object": {"id": "ch_test", "payment_intent": "pi_test", "amount": 50,
                       "amount_refunded": 20, "currency": "usd", "livemode": False}}}
    for _ in range(2):
        with pytest.raises(pb.PaymentError) as caught:
            deliver(setup.service, value)
        assert caught.value.code == "payment_credit_unavailable"
    assert not setup.credited
    deliver(setup.service, event(row))
    assert deliver(setup.service, value)["status"] == "refunded"
    assert [(e.kind, e.amount) for e in setup.credited] == [("credit", 500000), ("refund", 200000)]
    with sqlite3.connect(setup.path) as db:
        assert db.execute("SELECT COUNT(*) FROM payment_events WHERE event_id='evt_early'").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM payment_audit WHERE event_id='evt_early'").fetchone()[0] >= 3


def test_missing_schema_fails_before_provider(setup, tmp_path):
    setup.service.store = pb.SqlPaymentStore(tmp_path / "missing.sqlite")
    with pytest.raises(pb.PaymentError) as caught:
        checkout(setup)
    assert caught.value.status == 503 and caught.value.code == "payments_unavailable" and not setup.calls
    assert not (tmp_path / "missing.sqlite").exists()


def test_separate_instances_share_claims_and_callbacks(setup):
    row = checkout(setup)
    services = [pb.PaymentBilling(store=setup.store, env=ENV, secret_resolver=lambda _: SECRET,
                callback=setup.service.callback, clock=lambda: NOW) for _ in range(4)]
    def run(service):
        try:
            return deliver(service, event(row))
        except pb.PaymentError as error:
            assert error.code == "payment_credit_unavailable" and error.status == 503
            return None
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(run, services))
    assert len(setup.credited) == 1
    assert deliver(services[0], event(row))["status"] == "credited"


def test_processor_failure_retries_same_opaque_id_without_new_velocity(setup):
    original = setup.service.http
    attempted = []
    def failure(url, *, headers, body):
        attempted.append(headers["Idempotency-Key"])
        raise RuntimeError("private processor detail")
    setup.service.http = failure
    with pytest.raises(pb.PaymentError) as caught:
        checkout(setup)
    assert caught.value.code == "payment_processor_unavailable"
    setup.service.http = original
    row = checkout(setup)
    assert attempted == [row["checkout_id"]]
    with sqlite3.connect(setup.path) as db:
        assert db.execute("SELECT attempts FROM payment_velocity").fetchone()[0] == 1


def test_fixed_http_disallows_redirects_and_suppresses_processor_errors(monkeypatch):
    calls = []
    def post(url, **kwargs):
        calls.append((url, kwargs))
        return SimpleNamespace(status_code=302, json=lambda: pytest.fail("redirect body"))
    monkeypatch.setattr(pb.requests, "post", post)
    with pytest.raises(pb.PaymentError):
        pb.stripe_http(pb.ENDPOINT, headers={}, body="mode=payment")
    assert calls[0][1]["allow_redirects"] is False and calls[0][1]["timeout"] == (3, 10)
    with pytest.raises(pb.PaymentError):
        pb.stripe_http("https://foreign.test", headers={}, body="")
    assert len(calls) == 1


def test_d1_adapter_preserves_fixed_protocol_without_fallback():
    bodies = []
    def transport(body):
        bodies.append(body)
        return {"version": 1, "result": None}
    store = pb.D1PaymentStore(transport)
    assert store.call("find", checkout_id="pay_one", payment_intent=None) is None
    assert bodies == [{"version": 1, "operation": "find", "checkout_id": "pay_one", "payment_intent": None}]
    with pytest.raises(pb.PaymentError):
        pb.D1PaymentStore(lambda _: {"version": 1}).call("find")


def test_missing_columns_and_webhook_schema_are_503(setup):
    row = checkout(setup)
    with sqlite3.connect(setup.path) as db:
        db.execute("ALTER TABLE payment_events RENAME TO old_payment_events")
        db.execute("CREATE TABLE payment_events (event_id TEXT)")
    with pytest.raises(pb.PaymentError) as caught:
        deliver(setup.service, event(row))
    assert caught.value.code == "payments_unavailable" and not setup.credited


@pytest.mark.parametrize("obj", [{"type": []}, {"type": "checkout.session.completed", "data": []},
                                 {"type": "checkout.session.completed", "data": {"object": []}}])
def test_malformed_payload_never_crashes_or_credits(setup, obj):
    result = deliver(setup.service, {"id": "evt_malformed", "object": "event", **obj})
    assert result["status"] in {"ignored", "mismatch"} and not setup.credited


def test_velocity_utc_reset_and_owner_isolation(setup):
    for n in range(10):
        checkout(setup, idempotency_key=f"day-{n}")
    setup.service.clock = lambda: NOW+86400
    assert checkout(setup, idempotency_key="next-day")["status"] == "pending"
    setup.service.checkout(TenantContext("bob"), "bob", BODY)


def test_permission_callback_failures_do_not_grant_access(setup):
    setup.service.permission = lambda *_: "billing"
    with pytest.raises(pb.PaymentError) as caught:
        checkout(setup)
    assert caught.value.status == 403
    def unavailable(*_):
        raise RuntimeError("private permission detail")
    setup.service.permission = unavailable
    with pytest.raises(pb.PaymentError) as caught:
        checkout(setup)
    assert caught.value.status == 503 and not setup.calls


def test_registered_paths_off_auth_raw_webhook_redirect(setup, monkeypatch):
    def authenticate(**kwargs):
        def decorate(target):
            def wrapper(*args, **kw):
                if not g.get("authenticated_user"):
                    return {"error": "authentication_required"}, 401
                return target(*args, **kw)
            wrapper.__name__ = target.__name__
            return wrapper
        return decorate
    monkeypatch.setattr(payments, "api_authenticate_only", authenticate)
    app = Flask(__name__)
    @app.before_request
    def user():
        from flask import request
        if request.headers.get("Authorization") == "Bearer test":
            g.authenticated_user = {"id": "alice"}
    exempted = []
    csrf = SimpleNamespace(exempt=lambda f: exempted.append(f.__name__) or f)
    payments.register_payment_routes(app, csrf, service=setup.service)
    client = app.test_client()
    setup.service.env = {}
    assert client.post("/v1/payments/checkout").status_code == 404
    assert client.post("/v1/payments/webhook").status_code == 404
    setup.service.env = ENV
    assert client.post("/v1/payments/checkout", json=BODY).status_code == 401
    row = client.post("/v1/payments/checkout", json=BODY, headers={"Authorization": "Bearer test"}).json
    assert client.get("/v1/payments/checkout").status_code == 405
    assert client.get("/paid").status_code == 404 and not setup.credited
    assert client.post("/v1/payments/checkout", data="{", content_type="application/json",
                       headers={"Authorization": "Bearer test"}).status_code == 400
    assert client.post("/v1/payments/checkout", data="x"*(pb.MAX_BODY+1), content_type="application/json",
                       headers={"Authorization": "Bearer test"}).status_code == 400
    assert "payment_webhook" in exempted
    raw = json.dumps(event(row)).encode()
    signature = hmac.new(SECRET.encode(), str(NOW).encode()+b"."+raw, hashlib.sha256).hexdigest()
    assert client.post("/v1/payments/webhook", data=raw, headers={"Stripe-Signature": f"t={NOW},v1={signature}"}).status_code == 200
    assert len(setup.credited) == 1
