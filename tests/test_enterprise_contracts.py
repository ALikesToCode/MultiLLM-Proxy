"""Immutable enterprise boundaries with synthetic authorities and no live calls."""
import importlib
import json
import sys
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from services import enterprise_contract as ec


def vectors():
    text = (Path(__file__).resolve().parents[1] / "docs/enterprise-contracts.md").read_text()
    return json.loads(text.split("```json\n", 1)[1].split("```", 1)[0])


@pytest.mark.parametrize("index", range(len(vectors())))
def test_shared_contract_vectors(index):
    vector = vectors()[index]
    constructor = getattr(ec, vector["type"])
    data = dict(vector["data"])
    if "context" in data:
        data["context"] = ec.TenantContext(**data["context"])
    if vector["valid"]:
        value = constructor(**data)
        assert value is not None
        with pytest.raises(FrozenInstanceError):
            value.principal_id = "changed"
    else:
        with pytest.raises((TypeError, ValueError)):
            constructor(**data)


def operation(**changes):
    data = dict(next(vector["data"] for vector in vectors() if vector["name"] == "operation"))
    data["context"] = ec.TenantContext(**data["context"])
    return ec.AuthorityOperation(**{**data, **changes})


def test_legacy_adapter_keeps_single_principal_and_rejects_tenants():
    op = operation()
    adapters = ec.register_enterprise_adapters()
    assert ec.resolve_tenant(adapters, op) == op.context
    with pytest.raises(ec.AuthorityDenied, match="tenant_scope_denied"):
        ec.resolve_tenant(adapters, replace(op, context=replace(op.context, org_id="org:one")))


@pytest.mark.parametrize("authority", ["quota", "credit"])
@pytest.mark.parametrize("action", ["reserve", "commit", "reconcile"])
def test_missing_authorities_deny(authority, action):
    with pytest.raises(ec.AuthorityDenied, match="authority_unavailable"):
        ec.call_authority(ec.register_enterprise_adapters(), authority, action, operation())


def test_fake_authority_preserves_scope_revision_and_operation_ids():
    op = operation()
    calls = []

    class Fake:
        def reserve(self, value):
            calls.append(value)
            return ec.AuthorityResult(value.context, value.scoped_id, value.revision + 1,
                                      value.operation_id, True)
        commit = reserve
        reconcile = reserve

    adapters = ec.register_enterprise_adapters(quota=Fake(), credit=Fake(), tenant=lambda value: value.context)
    for authority in ("quota", "credit"):
        for action in ("reserve", "commit", "reconcile"):
            assert ec.call_authority(adapters, authority, action, op).revision == 8
    assert calls == [op] * 6
    assert ec.resolve_tenant(adapters, op) == op.context


@pytest.mark.parametrize("change", [{"revision": 7}, {"operation_id": "other"},
                                   {"scoped_id": "other"}, {"context": ec.TenantContext("foreign")},
                                   {"allowed": False}])
def test_authority_cannot_return_stale_foreign_or_denied_result(change):
    op = operation()
    result = ec.AuthorityResult(op.context, op.scoped_id, 8, op.operation_id, True)
    fake = Mock()
    fake.reserve.return_value = replace(result, **change)
    with pytest.raises(ec.AuthorityDenied):
        ec.call_authority(ec.register_enterprise_adapters(credit=fake), "credit", "reserve", op)
    fake.reserve.assert_called_once_with(op)


def test_identity_and_payment_require_explicit_verified_boundaries():
    op = operation()
    assertion = ec.IdentityAssertion("issuer:one", "subject:one", "audience:one",
                                     "request:one", "nonce:one", 1000, True)
    event = ec.PaymentEvent(op.context, op.scoped_id, op.revision, op.operation_id,
                           "processor:one", "event:one", "credit", "USD", 12, True)
    adapters = ec.register_enterprise_adapters()
    with pytest.raises(ec.AuthorityDenied):
        ec.resolve_identity(adapters, assertion, op)
    with pytest.raises(ec.AuthorityDenied):
        ec.deliver_payment(adapters, event)
    identity = Mock(return_value=op.context)
    callback = Mock(return_value=ec.AuthorityResult(op.context, op.scoped_id, 8, op.operation_id, True))
    adapters = ec.register_enterprise_adapters(identity=identity, payment=callback)
    assert ec.resolve_identity(adapters, assertion, op) == op.context
    assert ec.deliver_payment(adapters, event).revision == 8
    callback.assert_called_once_with(event)
    with pytest.raises((TypeError, ValueError)):
        ec.deliver_payment(adapters, {"verified": True})
    with pytest.raises(ec.AuthorityDenied):
        ec.resolve_identity(ec.register_enterprise_adapters(identity=lambda *_: ec.TenantContext("foreign")), assertion, op)


def test_fake_credit_atomic_revision_and_idempotency():
    from concurrent.futures import ThreadPoolExecutor
    from threading import Lock
    op = operation()
    revision, writes, records = op.revision, [], {}
    lock = Lock()

    def apply(value):
        nonlocal revision
        with lock:
            if value.operation_id in records:
                if records[value.operation_id][0] != value:
                    raise ec.AuthorityDenied("operation_conflict")
                return records[value.operation_id][1]
            if value.revision != revision:
                raise ec.AuthorityDenied("revision_conflict")
            revision += 1
            result = ec.AuthorityResult(value.context, value.scoped_id, revision, value.operation_id, True)
            records[value.operation_id] = (value, result)
            writes.append(value)
            return result

    class Fake:
        reserve = staticmethod(apply)
        commit = staticmethod(apply)
        reconcile = staticmethod(apply)

    adapters = ec.register_enterprise_adapters(credit=Fake(), tenant=None)
    with pytest.raises(ec.AuthorityDenied):
        ec.resolve_tenant(adapters, op)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: ec.call_authority(adapters, "credit", "reserve", op), range(2)))
    assert results[0] == results[1] and writes == [op]
    with pytest.raises(ec.AuthorityDenied, match="operation_conflict"):
        ec.call_authority(adapters, "credit", "reserve", replace(op, amount=13))
    with pytest.raises(ec.AuthorityDenied, match="revision_conflict"):
        ec.call_authority(adapters, "credit", "commit", replace(op, operation_id="operation:two"))
    next_op = replace(op, revision=8, operation_id="operation:two")
    assert ec.call_authority(adapters, "credit", "commit", next_op).revision == 9
    assert writes == [op, next_op]


def test_adapter_failure_is_not_retried_or_converted_to_success():
    fake = Mock()
    fake.reserve.side_effect = RuntimeError("authority unavailable")
    with pytest.raises(RuntimeError, match="authority unavailable"):
        ec.call_authority(ec.register_enterprise_adapters(credit=fake), "credit", "reserve", operation())
    fake.reserve.assert_called_once()
    with pytest.raises(TypeError):
        ec.register_enterprise_adapters(tenant="plugin.module")


def test_preview_flag_defaults_and_warns_once_without_value(caplog):
    ec._warn_once.cache_clear()
    for flag in (None, "", "false", "0", "off", "no"):
        assert not ec.preview_enabled({} if flag is None else {"ENTERPRISE_PREVIEW_ENABLED": flag})
    for flag in ("true", "1", "YES", " on "):
        assert ec.preview_enabled({"ENTERPRISE_PREVIEW_ENABLED": flag})
    for _ in range(2):
        assert not ec.preview_enabled({"ENTERPRISE_PREVIEW_ENABLED": "private-invalid"})
    assert caplog.text.count("Invalid ENTERPRISE_PREVIEW_ENABLED") == 1
    assert "private-invalid" not in caplog.text


@pytest.fixture
def registered(monkeypatch, tmp_path):
    for key, value in {"FLASK_SECRET_KEY": "synthetic-enterprise-session", "JWT_SECRET": "synthetic-enterprise-jwt",
                       "ADMIN_API_KEY": "synthetic-enterprise-admin", "ENTERPRISE_PREVIEW_ENABLED": "",
                       "AUTH_DB_PATH": str(tmp_path / "auth.sqlite3"), "MODEL_REGISTRY_DB_PATH": str(tmp_path / "models.sqlite3"),
                       "RATE_LIMIT_DB_PATH": str(tmp_path / "limits.sqlite3")}.items():
        monkeypatch.setenv(key, value)
    with patch("config.load_runtime_env"), patch("env_loader.load_runtime_env"), \
            patch("services.usage_ledger.start"), patch("requests.Session.send", side_effect=AssertionError("No network")):
        module = importlib.import_module("app")
        with patch.object(module, "load_runtime_env"):
            app = module.create_app()
        app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        auth = module.AuthService
        # Other suites re-import the auth and route modules; patch the guards this route calls.
        preview = sys.modules[module.register_enterprise_preview_routes.__module__]
        for guard in (preview.login_required, preview.require_admin_dashboard_user):
            monkeypatch.setitem(guard.__globals__, "AuthService", auth)
        with patch.object(auth, "is_authenticated", return_value=True), \
                patch.object(auth, "get_current_user", return_value={"username": "operator", "is_admin": True}):
            yield app, app.test_client(), auth


def test_registered_preview_disabled_before_auth(registered):
    _, client, auth = registered
    with patch.object(auth, "is_authenticated", return_value=False), \
            patch.object(auth, "get_current_user", side_effect=AssertionError("Disabled route checked grants")):
        assert client.get("/admin/enterprise/preview").status_code == 404


def test_registered_preview_auth_and_zero_mutation(registered, monkeypatch):
    app, client, auth = registered
    monkeypatch.setenv("ENTERPRISE_PREVIEW_ENABLED", "true")
    with patch.object(auth, "is_authenticated", return_value=False):
        assert client.get("/admin/enterprise/preview", headers={"Accept": "application/json"}).status_code == 401
    with patch.object(auth, "get_current_user", return_value={"is_admin": False}):
        assert client.get("/admin/enterprise/preview").status_code == 403
    authority = Mock(side_effect=AssertionError("Preview called authority"))
    app.extensions["enterprise_adapters"] = ec.register_enterprise_adapters(tenant=authority, payment=authority)
    response = client.get("/admin/enterprise/preview", headers={"X-Org-ID": "spoofed"})
    assert response.status_code == 200
    assert response.json == ec.preview_descriptor(app.extensions["enterprise_adapters"])
    assert response.json["dry_run"] is True
    assert response.headers["Cache-Control"] == "no-store"
    authority.assert_not_called()
    assert client.post("/admin/enterprise/preview", json={}).status_code == 405


def test_registration_leaves_existing_response_bytes_and_headers_unchanged(monkeypatch):
    from flask import Flask, Response
    from routes.enterprise_preview import register_enterprise_preview_routes
    monkeypatch.setenv("ENTERPRISE_PREVIEW_ENABLED", "")
    def baseline():
        app = Flask(__name__)
        app.add_url_rule("/existing", view_func=lambda: Response(b"raw bytes", headers={"X-Existing": "same"}))
        return app
    before = baseline().test_client().get("/existing")
    app = baseline()
    register_enterprise_preview_routes(app)
    after = app.test_client().get("/existing")
    assert (after.status_code, after.data, list(after.headers)) == (before.status_code, before.data, list(before.headers))
