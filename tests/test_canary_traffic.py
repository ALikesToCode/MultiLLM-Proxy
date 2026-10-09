"""Reviewed canary routing with synthetic identity, storage and transports."""
import importlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import pytest
from flask import Flask, Response, g

MODELS = ("openai:baseline", "openai:candidate", "openai:other")
BASE_URLS = {"openai": "https://synthetic.invalid/v1"}
KEY = "synthetic-canary-key"
VECTOR = ("tenant:user", "session-42", "auto:experiment", "r1")


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    global canary, routes, service
    canary = importlib.import_module("services.canary_traffic")
    routes = importlib.import_module("routes.auto_routes")
    service = importlib.import_module("services.auto_route_service")
    for name, value in {"CANARY_TRAFFIC_ENABLED": "true", "AUTO_ROUTE_ORDERING": "priority",
                        "INTELLIGENCE_STORAGE_BACKEND": "", "CONTROL_PLANE_DATABASE_URL": "",
                        "GENERATION_DEADLINE_ENABLED": "false", "MULTILLM_STREAM_PREFLIGHT": "off",
                        "MODEL_REGISTRY_DB_PATH": str(tmp_path / "models.sqlite3")}.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(canary, "_warned", set())
    monkeypatch.setattr(canary, "_counts", {})
    routes.RouteHealth.reset()
    yield
    routes.RouteHealth.reset()


def config(**changes):
    raw = {"enabled": True, "mode": "live", "weights": {"baseline": 0, "candidate": 100},
           "salt_revision": "r1", "approved_candidates": [MODELS[1]]}
    raw.update(changes)
    return raw


def app():
    application = Flask(__name__)
    application.config.update(TESTING=True, JWT_SECRET=KEY, API_BASE_URLS=BASE_URLS)
    return application


def save(**changes):
    return service.AutoRouteService.save_route("auto:experiment", list(MODELS), BASE_URLS,
                                               canary=config(**changes))


def dispatch(application, *, payload=None, principal=True, headers=None, rejected=(), status=200):
    payload = payload or {"model": "auto:experiment", "session_id": "session-42"}
    calls = []
    validated = []
    def validate(model):
        validated.append(model)
        if model in rejected:
            raise routes.APIError("Denied by existing policy", 403)
    def send(body, model, decision):
        calls.append(model)
        return Response("provider body", status=status)
    with application.test_request_context("/v1/chat/completions", method="POST", json=payload, headers=headers):
        if principal:
            g.authenticated_user = {"tenant_id": "tenant", "id": "user"}
        response = routes.dispatch_auto_route_chat_completion(payload, validate_candidate=validate,
                                                               dispatch_candidate=send)
        telemetry = getattr(g, "multillm_canary", None)
    return response, calls, validated, telemetry


def test_shared_assignment_vector_and_concurrency():
    policy = canary.normalize_config(config(weights={"baseline": 50, "candidate": 50}), MODELS)
    def assign(_):
        return canary.assign_cohort(policy, principal=VECTOR[0], session=VECTOR[1],
                                    route_id=VECTOR[2], key=KEY)
    assert set(ThreadPoolExecutor(max_workers=8).map(assign, range(64))) == {"baseline"}


def test_weights_revision_identity_and_unambiguous_framing():
    policy = canary.normalize_config(config(weights={"baseline": 50, "candidate": 50}), MODELS)
    def cohort(principal=VECTOR[0], session=VECTOR[1], revision="r1"):
        policy2 = canary.normalize_config(config(weights=policy.weights, salt_revision=revision), MODELS)
        return canary.assign_cohort(policy2, principal=principal, session=session, route_id=VECTOR[2], key=KEY)
    assert {cohort(session=f"s{i}") for i in range(200)} == {"baseline", "candidate"}
    assert any(cohort(session=f"s{i}") != cohort(session=f"s{i}", revision="r2") for i in range(40))
    assert any(cohort(principal="tenant:other", session=f"s{i}") != cohort(session=f"s{i}") for i in range(40))
    zero = canary.normalize_config(config(weights={"baseline": 100, "candidate": 0}), MODELS)
    assert canary.assign_cohort(zero, principal="a", session="b", route_id="auto:x", key=KEY) == "baseline"


@pytest.mark.parametrize("change", [dict(enabled="true"), dict(mode="adaptive"), dict(salt_revision=""),
    dict(weights={"baseline": -1, "candidate": 101}), dict(weights={"baseline": 50.0, "candidate": 50}),
    dict(weights={"baseline": True, "candidate": 99}), dict(weights={"baseline": 40, "candidate": 40}),
    dict(approved_candidates=["openai:outside"]), dict(approved_candidates=[MODELS[1], MODELS[1]]),
    dict(approved_candidates=[]), dict(extra="ignored"), dict(salt_revision=5)])
def test_invalid_config_rejected_before_storage(change):
    with pytest.raises(ValueError):
        service.AutoRouteService.save_route("auto:experiment", list(MODELS), BASE_URLS,
                                           canary=config(**change))
    assert not Path(service.storage_path("MODEL_REGISTRY_DB_PATH", "unused")).exists()


@pytest.mark.parametrize("raw", [None, [], "canary", 0])
def test_malformed_object_rejected(raw):
    with pytest.raises(ValueError):
        canary.normalize_config(raw, MODELS)


@pytest.mark.parametrize("flag", ["", "false", "off", "0", "malformed-private-value"])
def test_disabled_exact_dispatch_headers_telemetry_and_warning(flag, monkeypatch, caplog):
    save()
    monkeypatch.setenv("CANARY_TRAFFIC_ENABLED", flag)
    application = app()
    response, calls, _, telemetry = dispatch(application)
    assert calls == [MODELS[0]] and response.data == b"provider body"
    assert canary.HEADER not in response.headers and telemetry is None
    dispatch(application)
    assert "malformed-private-value" not in caplog.text
    assert len(caplog.records) == (1 if flag == "malformed-private-value" else 0)
    assert canary.cohort_counts() == []


def test_legacy_route_keeps_storage_headers_and_telemetry_unchanged():
    service.AutoRouteService.save_route("auto:experiment", list(MODELS), BASE_URLS)
    response, calls, _, telemetry = dispatch(app())
    assert calls == [MODELS[0]] and telemetry is None and canary.HEADER not in response.headers
    with service.AutoRouteService._connect() as conn:
        assert conn.execute("SELECT name FROM sqlite_master WHERE name='canary_traffic'").fetchone() is None


def test_global_off_does_not_read_or_warn_about_stored_config(monkeypatch, caplog):
    save()
    monkeypatch.setenv("CANARY_TRAFFIC_ENABLED", "false")
    def refuse_read(*args):
        raise AssertionError("Disabled traffic must not load canary policy")
    monkeypatch.setattr(canary, "json", type("Unreadable", (), {"loads": refuse_read}))
    response, calls, _, telemetry = dispatch(app())
    assert calls == [MODELS[0]] and telemetry is None and canary.HEADER not in response.headers
    assert caplog.records == []


def test_live_reorders_shadow_dispatches_once_and_records_proposal():
    save(mode="shadow")
    response, calls, _, telemetry = dispatch(app())
    assert calls == [MODELS[0]] and response.headers[canary.HEADER] == "candidate; mode=shadow"
    assert telemetry["cohort"] == "candidate" and telemetry["mode"] == "shadow"
    assert telemetry["proposed_order"] == [MODELS[1], MODELS[0], MODELS[2]]
    save()
    response, calls, _, telemetry = dispatch(app())
    assert calls == [MODELS[1]] and response.headers[canary.HEADER] == "candidate; mode=live"
    assert telemetry["eligible_order"] == [MODELS[1], MODELS[0], MODELS[2]]
    counts = canary.cohort_counts()
    assert sum(row["count"] for row in counts) == 2
    assert "session-42" not in json.dumps(counts) and "tenant:user" not in json.dumps(counts)


def test_baseline_cohort_proposes_the_baseline_chain():
    save(mode="shadow", weights={"baseline": 100, "candidate": 0})
    response, calls, _, event = dispatch(app())
    assert calls == [MODELS[0]] and event["proposed_order"] == list(MODELS)
    assert response.headers[canary.HEADER] == "baseline; mode=shadow"


def test_permission_and_health_ordering_win(monkeypatch):
    save()
    response, calls, validated, _ = dispatch(app(), rejected=(MODELS[1],))
    assert calls == [MODELS[0]] and validated == [MODELS[1], MODELS[0]]
    seen = []
    from services.route_health import RouteOrder
    def ordered(route, candidates, **kw):
        seen.append(tuple(candidates))
        return RouteOrder((MODELS[0], MODELS[1], MODELS[2]), "health")
    monkeypatch.setattr(routes.RouteHealth, "order", ordered)
    _, calls, _, _ = dispatch(app())
    assert seen == [(MODELS[1], MODELS[0], MODELS[2])] and calls == [MODELS[0]]


@pytest.mark.parametrize("payload,principal", [({"model": "auto:experiment"}, True),
    ({"model": "auto:experiment", "session_id": "session-42", "principal": "spoof", "cohort": "candidate"}, False)])
def test_missing_identity_or_session_is_baseline(payload, principal):
    save()
    response, calls, _, _ = dispatch(app(), payload=payload, principal=principal,
        headers={"X-MultiLLM-Canary-Cohort": "candidate", "X-Principal": "spoof"})
    assert calls == [MODELS[0]] and response.headers[canary.HEADER] == "baseline; mode=live"


def test_missing_key_warns_once_and_stays_baseline(caplog):
    save()
    application = app()
    application.config.pop("JWT_SECRET")
    for _ in range(3):
        response, calls, _, _ = dispatch(application)
        assert calls == [MODELS[0]] and response.headers[canary.HEADER] == "baseline; mode=live"
    assert len(caplog.records) == 1 and KEY not in caplog.text


def test_session_sources_match_affinity_precedence():
    application = app()
    with application.test_request_context(headers={"X-OpenCode-Session": "header", "Session-Id": "second"}):
        assert canary.session_identifier({"session_id": "body"}, {"session_id": "signed"}) == "header"
    with application.test_request_context():
        assert canary.session_identifier({"metadata": {"conversation_id": "metadata"}}, {}) == "metadata"
        assert canary.session_identifier({}, {"session_id": "signed"}) == "signed"
        assert canary.session_identifier({}, {}) is None
        assert canary.authenticated_principal({"tenant_id": "tenant", "id": "user"}) == '["tenant","user"]'
        assert canary.authenticated_principal({"username": "user"}) == '[null,"user"]'
        assert canary.authenticated_principal({}) is None


@pytest.mark.parametrize("status", [400, 408, 504])
def test_no_new_retry_for_ambiguous_or_request_failures(status):
    save()
    response, calls, _, _ = dispatch(app(), status=status)
    assert response.status_code == status and calls == [MODELS[1]]


def test_refusals_keep_fallback_and_canary_header():
    save()
    response, calls, _, _ = dispatch(app(), status=429)
    assert calls == [MODELS[1], MODELS[0], MODELS[2]]
    assert response.status_code == 429 and response.headers[canary.HEADER] == "candidate; mode=live"


def test_save_roundtrip_atomic_revision_and_old_rows(tmp_path):
    service.AutoRouteService.save_route("auto:old", [MODELS[0]], BASE_URLS)
    stored = save()
    loaded = service.AutoRouteService.get_route(stored.id)
    assert loaded.canary.as_dict() == config()
    assert service.AutoRouteService.get_route("auto:old").canary.enabled is False
    with pytest.raises(routes.APIError) as error:
        service.AutoRouteService.save_route(stored.id, list(reversed(MODELS)), BASE_URLS,
            canary=config(), expected_updated_at="stale")
    assert error.value.status_code == 409
    assert service.AutoRouteService.get_route(stored.id) == loaded
    conn = sqlite3.connect(tmp_path / "migration.sqlite3")
    conn.execute("CREATE TABLE old (value TEXT)")
    conn.execute("INSERT INTO old VALUES ('old-row')")
    migration = (Path(__file__).resolve().parents[1] / "intelligence-migrations/0025_canary_traffic.sql").read_text()
    conn.executescript(migration)
    conn.executescript(migration)
    assert conn.execute("SELECT * FROM old").fetchall() == [("old-row",)]
    assert "session" not in {r[1] for r in conn.execute("PRAGMA table_info(canary_traffic)")}
    conn.close()


def test_missing_durable_table_and_unwired_operation_fail_closed(monkeypatch, caplog):
    monkeypatch.setattr(service.auto_route_d1, "using_d1", lambda: True)
    monkeypatch.setattr(service.config_revision_sync, "route_copy", lambda: None)
    monkeypatch.setattr(service.auto_route_d1, "stored_routes", lambda: {"auto:experiment": (MODELS, "r1")})
    def unavailable(*args, **kw):
        raise routes.APIError("Storage unavailable", 503)
    monkeypatch.setattr(canary, "durable_request", unavailable)
    loaded = service.AutoRouteService.get_route("auto:experiment")
    assert loaded.canary.enabled is False
    service.AutoRouteService.get_route("auto:experiment")
    assert len(caplog.records) == 1
    with pytest.raises(routes.APIError) as error:
        save()
    assert error.value.status_code == 503


def test_durable_save_and_read_use_fixed_operation_and_preserve_revision(monkeypatch):
    monkeypatch.setattr(service.auto_route_d1, "using_d1", lambda: True)
    monkeypatch.setattr(service.config_revision_sync, "route_copy", lambda: None)
    calls = []
    saved = {}
    def storage(operation, **values):
        calls.append((operation, values))
        if operation == "canary_put":
            saved.update(values)
            return {"version": 1, "stored": True}
        return {"version": 1, "routes": [{"route_id": saved["route_id"],
            "updated_at": saved["updated_at"], "canary": saved["canary"]}]}
    monkeypatch.setattr(canary, "durable_request", storage)
    monkeypatch.setattr(service.auto_route_d1, "stored_routes", lambda: {
        "auto:experiment": (tuple(saved["candidates"]), saved["updated_at"])})
    stored = service.AutoRouteService.save_route("auto:experiment", list(MODELS), BASE_URLS,
                                               canary=config(), current_revision=4)
    assert calls[0][0] == "canary_put" and calls[0][1]["current_revision"] == 4
    assert service.AutoRouteService.get_route(stored.id) == stored
    monkeypatch.setenv("CANARY_TRAFFIC_ENABLED", "false")
    previous = len(calls)
    assert not service.AutoRouteService.get_route(stored.id).canary.enabled
    assert len(calls) == previous


def test_registered_admin_save_refuses_invalid_config_with_real_400(monkeypatch):
    application = app()
    from error_handlers import init_error_handlers
    init_error_handlers(application)
    class Auth:
        @staticmethod
        def get_current_user():
            return {"is_admin": True}
    monkeypatch.setattr(routes, "refresh_model_catalogs", lambda *a: None)
    monkeypatch.setattr(routes, "_admin_payload", lambda *a: {"routes": []})
    routes.register_auto_route_admin_routes(application, lambda f: f, Auth, object)
    client = application.test_client()
    assert client.put("/admin/auto-routes", json={"route_id": "auto:experiment", "candidates": list(MODELS),
                                                "canary": config(mode="adaptive")}).status_code == 400
    assert client.put("/admin/auto-routes", json={"route_id": "auto:experiment", "candidates": list(MODELS),
                                                "canary": config()}).status_code == 200
    assert service.AutoRouteService.get_route("auto:experiment").canary.enabled


def test_storage_failure_rolls_back_both_candidates_and_configuration(monkeypatch):
    previous = save()
    def unavailable(*args):
        raise sqlite3.OperationalError("synthetic unavailable storage")
    monkeypatch.setattr(canary, "save_local_configuration", unavailable)
    with pytest.raises(sqlite3.OperationalError):
        service.AutoRouteService.save_route(previous.id, list(reversed(MODELS)), BASE_URLS,
                                           canary=config(mode="shadow"))
    assert service.AutoRouteService.get_route(previous.id) == previous


def test_explicit_route_save_without_canary_disables_previous_review():
    save()
    service.AutoRouteService.save_route("auto:experiment", list(MODELS), BASE_URLS)
    response, calls, _, telemetry = dispatch(app())
    assert calls == [MODELS[0]] and canary.HEADER not in response.headers and telemetry is None


def test_registered_admission_guard_keeps_cohort_visible_without_dispatch(monkeypatch):
    save()
    application = app()
    from error_handlers import init_error_handlers
    init_error_handlers(application)
    class Auth:
        @staticmethod
        def get_current_user():
            return {"is_admin": True}
    routes.register_auto_route_admin_routes(application, lambda f: f, Auth, object)
    calls = []
    @application.post("/synthetic-auto-dispatch")
    def generate():
        g.authenticated_user = {"id": "verified"}
        def admission(model):
            raise routes.ModelCooldownCapacity(1)
        return routes.dispatch_auto_route({"model": "auto:experiment", "session_id": "s"},
            validate_candidate=admission, dispatch_candidate=lambda *args: calls.append(args))
    response = application.test_client().post("/synthetic-auto-dispatch", json={})
    assert response.status_code == 503 and calls == []
    assert response.headers[canary.HEADER] == "candidate; mode=live"


from tests.unified_api_test_case import UnifiedApiTestCase


class RegisteredCanaryTest(UnifiedApiTestCase):
    def setUp(self):
        with patch("env_loader.load_runtime_env"), patch("config.load_runtime_env"):
            super().setUp()
        self.flag = patch.dict("os.environ", {"CANARY_TRAFFIC_ENABLED": "true",
            "INTELLIGENCE_STORAGE_BACKEND": "", "AUTO_ROUTE_ORDERING": "priority",
            "SECRET_SCAN_DEFAULT": "off", "MODEL_COOLDOWN_ENABLED": "false"})
        self.flag.start()
        self.addCleanup(self.flag.stop)

    def test_registered_admin_and_authenticated_generation_shadow_and_live(self):
        with self.client.session_transaction() as session:
            session["authenticated"] = True
            session["user"] = {"username": "admin", "is_admin": True,
                               "api_key_prefix": "mllm_admin-te", "scopes": ["admin"]}
        active_routes = importlib.import_module("routes.auto_routes")
        policy = config(approved_candidates=["mimo:mimo-v2-flash"])
        saved = {"route_id": "auto:registered-canary", "candidates": ["opencode:glm-5.2", "mimo:mimo-v2-flash"]}
        for mode, provider in [("shadow", "opencode"), ("live", "mimo")]:
            policy["mode"] = mode
            with patch.object(active_routes, "refresh_model_catalogs"), patch("requests.sessions.Session.request",
                    side_effect=AssertionError("Provider network is forbidden")):
                response = self.client.put("/admin/auto-routes", json={**saved, "canary": policy})
            self.assertEqual(response.status_code, 200)
            stored = next(row for row in response.json["routes"] if row["id"] == saved["route_id"])
            self.assertEqual(stored["canary"], policy)
            with patch.object(self.app_module.AuthService, "get_api_keys", return_value=[]), \
                 patch("requests.sessions.Session.request", side_effect=AssertionError("Provider network is forbidden")):
                # Track the actual transport collaborator through its object, after module re-imports.
                with patch.object(self.app_module.ProxyService, "make_request", return_value=self._chat_response()) as send:
                    response = self.client.post("/v1/chat/completions", headers={"Authorization": "Bearer admin-test-key",
                        "X-MultiLLM-Canary-Cohort": "baseline", "X-Principal": "spoof"},
                        json={"model": saved["route_id"], "session_id": "session-42",
                              "messages": [{"role": "user", "content": "synthetic prompt"}]})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(send.call_count, 1)
            self.assertEqual(send.call_args.kwargs["api_provider"], provider)
            self.assertEqual(response.headers["X-MultiLLM-Canary-Cohort"], f"candidate; mode={mode}")
