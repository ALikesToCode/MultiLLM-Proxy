"""Immutable receipt storage, canonical evidence and authenticated read routes."""
import base64
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest
from flask import Flask, g

from services import usage_receipts as receipts, usage_ledger
from routes import usage_receipts as receipt_routes

# Public RFC 8032 test material, never a deployment signing identity.
PRIVATE = "MC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g"
PUBLIC = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
RECORD = {"cost_usd": None, "cost_basis": "unknown", "extra": {
    "fraction": 0.5, "zero": 0, "text": "é", "nullable": None}}
CANONICAL = '{"event_id":"settlement-1","key_id":"test-1","previous_hash":null,"principal":"alice","record":{"cost_basis":"unknown","cost_usd":null,"extra":{"fraction":0.5,"nullable":null,"text":"é","zero":0}},"sequence":1,"version":1}'
SIGNATURE = "bj6tfJIYOfMT4NdUChDUckhAsA4PLn+ZRTkFoMgFkJ688dug9EXuyw01kUt39d17bJJ+qAP7rzhdROvEgJ9ADg=="
HASH = "500716026bf9836219938f4e6bba0cb435e940bcf6db76910f1ee9f6279ad256"


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("USAGE_RECEIPTS_ENABLED", "true")
    monkeypatch.setenv("USAGE_RECEIPTS_KEY_ID", "test-1")
    monkeypatch.setenv("USAGE_RECEIPTS_SIGNING_KEY_REF", "RECEIPT_TEST_PRIVATE")
    monkeypatch.setenv("RECEIPT_TEST_PRIVATE", PRIVATE)
    monkeypatch.setenv("CONTROL_PLANE_DATABASE_URL", "")
    monkeypatch.setenv("USAGE_LEDGER_BACKEND", "sql")
    path = tmp_path / "usage.sqlite3"
    monkeypatch.setenv("USAGE_DB_PATH", str(path))
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE old_usage (cost REAL)")
        db.execute("INSERT INTO old_usage VALUES (NULL)")
        db.executescript((Path(__file__).resolve().parents[1] / "intelligence-migrations/0032_usage_receipts.sql").read_text())
        db.executescript((Path(__file__).resolve().parents[1] / "intelligence-migrations/0032_usage_receipts.sql").read_text())
        db.execute("INSERT INTO usage_receipt_keys VALUES (?, ?, 1)", ("test-1", PUBLIC))
        assert db.execute("SELECT cost FROM old_usage").fetchone() == (None,)
    return receipts.SqlReceiptStore(path)


def test_cross_runtime_vector_and_unknown_fields(store):
    result = store.append("alice", "settlement-1", RECORD)
    assert base64.b64decode(result["canonical_bytes_base64"]) == CANONICAL.encode()
    assert result["signature_ed25519"] == SIGNATURE
    assert result["record_hash"] == HASH
    assert result["record"] == RECORD
    assert receipts.verify_chain([result], {"test-1": PUBLIC}, principal="alice")


@pytest.mark.parametrize("value", [float("nan"), float("inf"), 2**53, "\ud800", {1: None}])
def test_non_interoperable_json_rejected(value):
    with pytest.raises(receipts.ReceiptError):
        receipts.canonical_bytes(value)


def test_exact_numbers_unicode_order_and_negative_zero():
    assert receipts.canonical_bytes({"z": -0.0, "n": 0.1, "😀": 1, "\ue000": 2}) == (
        '{"n":0.1000000000000000055511151231257827021181583404541015625,"z":0,"\ue000":2,"😀":1}'.encode())


def test_concurrent_cas_duplicate_and_corrections(store):
    with ThreadPoolExecutor(max_workers=4) as pool:
        rows = list(pool.map(lambda n: store.append("alice", f"event-{n}", RECORD), range(12)))
    ordered = sorted(rows, key=lambda row: row["sequence"])
    assert [row["sequence"] for row in ordered] == list(range(1, 13))
    assert receipts.verify_chain(ordered, {"test-1": PUBLIC}, principal="alice")
    first = store.append("alice", "duplicate", RECORD)
    assert store.append("alice", "duplicate", RECORD) == first
    with pytest.raises(receipts.ReceiptError) as error:
        store.append("alice", "duplicate", {**RECORD, "cost_usd": 0.5})
    assert error.value.status == 409
    correction = store.append("alice", "correction", {**RECORD, "cost_usd": 0.5,
                                                       "corrects": first["record_hash"]})
    assert correction["previous_hash"] == first["record_hash"]
    assert store.get("alice", first["record_hash"])["record"]["cost_usd"] is None
    assert store.get("bob", first["record_hash"]) is None


def test_tamper_reorder_chain_gap_and_cross_principal_fail(store):
    a = store.append("alice", "a", RECORD)
    b = store.append("alice", "b", RECORD)
    assert not receipts.verify_chain([b, a], {"test-1": PUBLIC}, principal="alice")
    assert not receipts.verify_chain([b], {"test-1": PUBLIC}, principal="alice")
    assert not receipts.verify_chain([a, {**b, "sequence": 3}], {"test-1": PUBLIC}, principal="alice")
    assert not receipts.verify_chain([{**a, "record": {"cost_usd": 0}}], {"test-1": PUBLIC}, principal="alice")
    assert not receipts.verify_chain([{**a, "sequence": True}], {"test-1": PUBLIC}, principal="alice")
    assert not receipts.verify_chain([a], {"test-1": PUBLIC}, principal="bob")


def test_reviewed_key_history_rotation_and_unusable_key(store, monkeypatch):
    first = store.append("alice", "old", RECORD)
    with sqlite3.connect(store.path) as db:
        db.execute("INSERT INTO usage_receipt_keys VALUES ('unreviewed', ?, 0)", (PUBLIC,))
        db.execute("INSERT INTO usage_receipt_keys VALUES ('test-2', ?, 1)", (PUBLIC,))
    monkeypatch.setenv("USAGE_RECEIPTS_KEY_ID", "test-2")
    second = store.append("alice", "new", RECORD)
    keys = store.keys()
    assert [key["key_id"] for key in keys] == ["test-1", "test-2"]
    assert receipts.verify_chain([first, second], {key["key_id"]: key["public_key_base64"] for key in keys}, principal="alice")
    for value in ("", "invalid"):
        monkeypatch.setenv("RECEIPT_TEST_PRIVATE", value)
        with pytest.raises(receipts.ReceiptError) as error:
            store.append("alice", "missing", RECORD)
        assert error.value.status == 503
        assert str(error.value) == "usage_receipts_unavailable"


def test_registered_owner_routes_disabled_and_unavailable(store, monkeypatch):
    app = Flask(__name__)
    def auth(*, required_scope):
        def decorate(fn):
            def wrapped(**values):
                g.authenticated_user = {"username": "bob" if g.get("other") else "alice"}
                return fn(**values)
            wrapped.__name__ = fn.__name__
            return wrapped
        return decorate
    monkeypatch.setattr(receipt_routes, "api_authenticate_only", auth)
    receipt_routes.register_usage_receipt_routes(app, SimpleNamespace(exempt=lambda fn: fn), store=store)
    client = app.test_client()
    item = store.append("alice", "route", RECORD)
    assert client.get("/v1/usage/receipts/" + item["record_hash"]).get_json() == item
    assert client.get("/v1/usage/receipts/" + "0" * 64).status_code == 404
    assert client.get("/v1/usage/receipt-keys").get_json() == {"keys": store.keys()}
    with app.test_request_context():
        g.other = True
        assert app.view_functions["usage_receipt"](id=item["record_hash"])[1] == 404
    monkeypatch.setenv("RECEIPT_TEST_PRIVATE", "")
    assert client.get("/v1/usage/receipt-keys").status_code == 503
    monkeypatch.setenv("USAGE_RECEIPTS_ENABLED", "")
    assert client.get("/v1/usage/receipt-keys").status_code == 404


def test_registered_routes_use_real_authentication_and_scope_boundary(store, monkeypatch):
    app = Flask(__name__)
    helper_objects = receipt_routes.api_authenticate_only.__globals__
    accounting = helper_objects["request_accounting"]
    def authenticate(key, address):
        if key == "models-test":
            return {"username": "alice", "scopes": ["models"]}
        if key == "chat-test":
            return {"username": "alice", "scopes": ["chat"]}
        return None
    monkeypatch.setattr(helper_objects["AuthService"], "verify_api_key", authenticate)
    monkeypatch.setattr(accounting, "check_key_controls", lambda user: None)
    monkeypatch.setattr(accounting, "begin", lambda: None)
    monkeypatch.setattr(accounting, "finish", lambda response: response)
    monkeypatch.setitem(helper_objects, "authorize_integration_route", lambda user: None)
    receipt_routes.register_usage_receipt_routes(app, SimpleNamespace(exempt=lambda fn: fn), store=store)
    client = app.test_client()
    assert client.get("/v1/usage/receipt-keys").status_code == 401
    assert client.get("/v1/usage/receipt-keys", headers={"Authorization": "Bearer invalid-test"}).status_code == 401
    assert client.get("/v1/usage/receipt-keys", headers={"Authorization": "Bearer chat-test"}).status_code == 403
    assert client.get("/v1/usage/receipt-keys", headers={"Authorization": "Bearer models-test"}).status_code == 200


def test_off_flags_no_storage_and_one_warning(monkeypatch, caplog):
    for flag in ("", "false", "malformed", "malformed"):
        monkeypatch.setenv("USAGE_RECEIPTS_ENABLED", flag)
        receipts.record_settled_usage("alice", "event", RECORD, store=SimpleNamespace(
            append=lambda *args: pytest.fail("disabled storage")))
    assert sum("Invalid USAGE_RECEIPTS_ENABLED" in row.message for row in caplog.records) == 1


def test_default_ledger_rows_storage_and_response_unchanged(monkeypatch):
    monkeypatch.setenv("USAGE_RECEIPTS_ENABLED", "")
    monkeypatch.setenv("USAGE_LEDGER_ENABLED", "true")
    monkeypatch.setattr(receipts, "open_store", lambda: pytest.fail("disabled receipt storage"))
    ledger = usage_ledger.UsageLedger()
    batches = []
    monkeypatch.setattr(ledger, "store", lambda: SimpleNamespace(record=lambda batch, rows: batches.extend(rows)))
    monkeypatch.setattr(ledger, "_ensure_thread", lambda: None)
    record = {"principal": "alice", "cost_usd": None, "cost_basis": None}
    original = json.dumps(record, separators=(",", ":"))
    assert ledger.record(record) is True and ledger.flush_once() == 1
    assert json.dumps(batches[0], separators=(",", ":")) == original


def test_missing_tables_and_content_limits_fail_closed(tmp_path, store):
    missing = receipts.SqlReceiptStore(tmp_path / "missing.sqlite3")
    with pytest.raises(receipts.ReceiptError) as error:
        missing.append("alice", "a", RECORD)
    assert error.value.status == 503
    for record in ({"prompt": "secret"}, {"extra": {"api_key": "secret"}}, {"extra": "x" * 65536}):
        with pytest.raises(receipts.ReceiptError) as error:
            store.append("alice", "invalid", record)
        assert error.value.status == 400


def test_ledger_flush_hook_does_not_change_usage_or_fail_it(store, monkeypatch):
    ledger = usage_ledger.UsageLedger()
    batches = []
    monkeypatch.setattr(ledger, "store", lambda: SimpleNamespace(record=lambda batch, rows: batches.append((batch, rows))))
    monkeypatch.setattr(ledger, "_ensure_thread", lambda: None)
    monkeypatch.setenv("USAGE_LEDGER_ENABLED", "true")
    monkeypatch.setattr(receipts, "open_store", lambda: store)
    row = {"principal": "alice", "cost_usd": None, "cost_basis": None}
    assert ledger.record(row) and ledger.flush_once() == 1
    event_id = f"{batches[0][0]}:0"
    receipt = store.find_event("alice", event_id)
    assert receipt["record"] == {**row, "usage_basis": "unknown"}
    assert batches[0][1] == [row]
    monkeypatch.setenv("RECEIPT_TEST_PRIVATE", "")
    assert ledger.record(row) and ledger.flush_once() == 1


def test_d1_transport_is_injected_and_dedicated(store):
    calls = []
    def call(body):
        calls.append(body)
        return {"version": 1, "receipt": store.append(body["principal"], body["event_id"], body["record"])}
    d1 = receipts.D1ReceiptStore(call=call)
    assert d1.append("alice", "d1", RECORD)["sequence"] == 1
    assert calls == [{"operation": "append", "principal": "alice", "event_id": "d1", "record": RECORD}]
