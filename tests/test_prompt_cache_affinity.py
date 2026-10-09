"""Outcome affinity with synthetic credentials and deterministic storage."""
import json
import importlib
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest
from flask import Flask, Response, g

from services import prompt_cache_affinity as affinity
from services import managed_dispatch
from services.credential_pool import CredentialPool
from services.upstream_outcome import classify_upstream_outcome

MODEL = "ce-gpt-plus:synthetic"
OTHER = "ce-gpt-pro:synthetic"
PAYLOAD = {"model": "auto:synthetic", "messages": [
    {"role": "system", "content": "private reusable prefix"},
    {"role": "user", "content": "private first turn"}]}


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    global affinity, managed_dispatch, CredentialPool
    affinity = importlib.import_module("services.prompt_cache_affinity")
    managed_dispatch = importlib.import_module("services.managed_dispatch")
    CredentialPool = importlib.import_module("services.credential_pool").CredentialPool
    monkeypatch.setenv("PROMPT_CACHE_AFFINITY_ENABLED", "true")
    monkeypatch.setenv("PROMPT_CACHE_AFFINITY_TTL_SECONDS", "900")
    monkeypatch.setenv("MODEL_COOLDOWN_ENABLED", "false")
    monkeypatch.setenv("SECRET_SCAN_DEFAULT", "off")
    monkeypatch.setenv("AUTH_DB_PATH", str(tmp_path / "auth.sqlite3"))
    monkeypatch.setenv("RATE_LIMIT_DB_PATH", str(tmp_path / "limits.sqlite3"))
    monkeypatch.setenv("MODEL_REGISTRY_DB_PATH", str(tmp_path / "models.sqlite3"))
    monkeypatch.setenv("CODEX_EVERYWHERE_API_KEY_GPT_PLUS", "synthetic-first")
    monkeypatch.setattr(CredentialPool, "keys", staticmethod(lambda provider: ["synthetic-first", "synthetic-second"]))
    CredentialPool.reset()
    monkeypatch.setattr(affinity, "store", affinity.PromptCacheAffinity())


def scope(**changes):
    args = dict(principal="alice", session="conversation", role="coding", payload=PAYLOAD,
                revision="revision-1", route="auto:synthetic")
    args.update(changes)
    return affinity.make_scope(**args)


def bind(s, model=MODEL, key="synthetic-second", **kwargs):
    s.record(model, key, classify_upstream_outcome(200), **kwargs)


def test_failure_never_binds_and_failure_evicts_only_matching_candidate():
    s = scope()
    s.record(MODEL, "synthetic-second", classify_upstream_outcome(503))
    assert s.preferred_model([MODEL, OTHER], {MODEL: "same", OTHER: "same"}) is None
    bind(s, OTHER)
    s.record(MODEL, "synthetic-second", classify_upstream_outcome(429))
    assert s.preferred_model([MODEL, OTHER], {MODEL: "same", OTHER: "same"}) == OTHER
    s.record(OTHER, "synthetic-second", classify_upstream_outcome(cancelled=True))
    assert s.preferred_model([MODEL, OTHER], {MODEL: "same", OTHER: "same"}) is None


def test_actual_successful_fallback_and_approved_tier_order():
    s = scope()
    bind(s, OTHER)
    assert s.order_candidates([MODEL, OTHER], {MODEL: "same", OTHER: "same"}) == [OTHER, MODEL]
    assert s.order_candidates([MODEL, OTHER], {MODEL: "primary", OTHER: "fallback"}) == [MODEL, OTHER]
    assert s.order_candidates([MODEL, OTHER], {}) == [MODEL, OTHER]
    assert s.order_candidates([MODEL], {MODEL: "same"}) == [MODEL]
    assert s.order_candidates([MODEL, OTHER], {MODEL: "same", OTHER: "same"}) == [MODEL, OTHER]


@pytest.mark.parametrize("changes", [dict(principal="bob"), dict(role="review"),
    dict(session="other"), dict(revision="revision-2"), dict(route="auto:other"),
    dict(payload={**PAYLOAD, "tools": [{"type": "function", "function": {"name": "other"}}]}),
    dict(payload={**PAYLOAD, "messages": [{"role": "user", "content": "different"}]})])
def test_principal_session_role_revision_prefix_separation(changes):
    bind(scope())
    assert scope(**changes).preferred_key(MODEL, ["synthetic-second"]) is None


def test_tool_loop_keeps_prefix_but_respects_tier():
    s = scope()
    bind(s, OTHER)
    continued = {**PAYLOAD, "messages": PAYLOAD["messages"] + [
        {"role": "assistant", "tool_calls": [{"id": "call"}]},
        {"role": "tool", "content": "result", "tool_call_id": "call"}]}
    later = scope(payload=continued)
    assert later.preferred_key(OTHER, ["synthetic-second"]) == "synthetic-second"
    assert later.order_candidates([MODEL, OTHER], {MODEL: 1, OTHER: 2}) == [MODEL, OTHER]


def test_expiry_bounded_hash_only_storage(monkeypatch):
    clock = [10.0]
    storage = affinity.PromptCacheAffinity(clock=lambda: clock[0], max_entries=2)
    monkeypatch.setattr(affinity, "store", storage)
    for user in ("alice", "bob", "charlie"):
        bind(scope(principal=user))
    assert len(storage) == 2
    assert scope().preferred_key(MODEL, ["synthetic-second"]) is None
    state = repr(storage.entries())
    for secret in ("private", "synthetic-second", "alice", "conversation"):
        assert secret not in state
    clock[0] += 900
    assert scope(principal="charlie").preferred_key(MODEL, ["synthetic-second"]) is None
    assert len(storage) == 0


def test_cooldown_and_removed_key_invalidation():
    s = scope()
    bind(s)
    with affinity.activate_scope(s), affinity.candidate_scope(MODEL):
        assert CredentialPool.select("ce-gpt-plus", now=10) == "synthetic-second"
        CredentialPool.record("ce-gpt-plus", "synthetic-second", 429, now=10)
        assert CredentialPool.select("ce-gpt-plus", now=11) == "synthetic-first"
    assert s.preferred_key(MODEL, ["synthetic-second"]) is None


@pytest.mark.parametrize("flag,ttl", [("", ""), ("false", "900"), ("bad-secret", "900"),
                                        ("true", "bad-secret"), ("true", "0")])
def test_disabled_invalid_unchanged(flag, ttl, monkeypatch, caplog):
    monkeypatch.setenv("PROMPT_CACHE_AFFINITY_ENABLED", flag)
    monkeypatch.setenv("PROMPT_CACHE_AFFINITY_TTL_SECONDS", ttl)
    assert scope() is None
    assert CredentialPool.select("ce-gpt-plus") == "synthetic-first"
    assert "bad-secret" not in caplog.text


def observed_response(s, body, *, status=200, stream=False, model=MODEL):
    with affinity.activate_scope(s), affinity.candidate_scope(model):
        upstream = Response(body, status=status,
                            mimetype="text/event-stream" if stream else "application/json")
        managed_dispatch.capture_managed_attempt(upstream, model, "synthetic-second")
        return managed_dispatch.observe_managed_response(upstream, upstream, stream=stream)


def test_nonstream_success_requires_classified_completed_response():
    s = scope()
    response = observed_response(s, json.dumps({"choices": [{"message": {"content": "answer"}, "finish_reason": "stop"}]}))
    assert response.status_code == 200
    assert s.preferred_key(MODEL, ["synthetic-second"]) == "synthetic-second"


@pytest.mark.parametrize("body", ['{"error":{"message":"secret"}}', 'not json', '{}'])
def test_200_error_or_unknown_body_does_not_bind(body):
    s = scope()
    observed_response(s, body)
    assert s.preferred_key(MODEL, ["synthetic-second"]) is None


def test_stream_header_and_first_delta_never_bind_and_wire_is_unchanged():
    s = scope()
    chunks = [b'data: {"choices":[{"delta":{"content":"text"}}]}\n\n',
              b'data: {"choices":[{"finish_reason":"stop"}]}\n\n', b'data: [DONE]\n\n']
    response = observed_response(s, iter(chunks), stream=True)
    assert s.preferred_key(MODEL, ["synthetic-second"]) is None
    iterator = iter(response.response)
    assert next(iterator) == chunks[0]
    assert s.preferred_key(MODEL, ["synthetic-second"]) is None
    assert list(iterator) == chunks[1:]
    assert s.preferred_key(MODEL, ["synthetic-second"]) == "synthetic-second"


@pytest.mark.parametrize("event", [b'data: {"error":{"message":"failure"}}\n\n', b'data: {}\n\n'])
def test_error_or_incomplete_stream_evicts(event):
    s = scope()
    bind(s)
    response = observed_response(s, iter([event]), stream=True)
    assert list(response.response) == [event]
    assert s.preferred_key(MODEL, ["synthetic-second"]) is None


def test_abort_before_first_read_does_not_bind():
    s = scope()
    response = observed_response(s, iter([b'data: [DONE]\n\n']), stream=True)
    response.close()
    assert s.preferred_key(MODEL, ["synthetic-second"]) is None


def test_cancellation_after_terminal_event_is_not_success():
    from services.request_cancellation import bind_cancellation
    s = scope()
    with affinity.activate_scope(s), affinity.candidate_scope(MODEL):
        response = Response(iter([b'data: [DONE]\n\n']), mimetype="text/event-stream")
        context = bind_cancellation(response)
        managed_dispatch.capture_managed_attempt(response, MODEL, "synthetic-second")
        managed_dispatch.observe_managed_response(response, response, stream=True)
    iterator = iter(response.response)
    assert next(iterator) == b'data: [DONE]\n\n'
    context.cancel()
    assert list(iterator) == []
    assert s.preferred_key(MODEL, ["synthetic-second"]) is None


def test_disabled_observation_keeps_response_and_iterator_identity(monkeypatch):
    monkeypatch.setenv("PROMPT_CACHE_AFFINITY_ENABLED", "false")
    source = iter([b'data: [DONE]\n\n'])
    response = Response(source, mimetype="text/event-stream")
    assert managed_dispatch.capture_managed_attempt(response, MODEL, "synthetic-second") is response
    assert managed_dispatch.observe_managed_response(response, response, stream=True) is response
    assert response.response is source
    assert not hasattr(response, "multillm_affinity_observer")


def test_ttl_change_and_warning_once(monkeypatch, caplog):
    s = scope()
    bind(s)
    monkeypatch.setenv("PROMPT_CACHE_AFFINITY_TTL_SECONDS", "10")
    assert s.preferred_key(MODEL, ["synthetic-second"]) is None
    assert scope().preferred_key(MODEL, ["synthetic-second"]) is None
    affinity._warned.clear()
    monkeypatch.setenv("PROMPT_CACHE_AFFINITY_ENABLED", "invalid-private-value")
    for _ in range(3):
        assert affinity.settings()[0] is False
    assert len(caplog.records) == 1
    assert "invalid-private-value" not in caplog.text


def test_concurrent_outcomes_are_bounded(monkeypatch):
    storage = affinity.PromptCacheAffinity(max_entries=8)
    monkeypatch.setattr(affinity, "store", storage)
    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(lambda i: bind(scope(principal=str(i))), range(100)))
    assert len(storage) == 8


def test_authenticated_auto_scope_excludes_explicit_raw_and_unauthenticated(monkeypatch):
    from services.auto_route_service import AutoRouteService, AutoRoute
    monkeypatch.setattr(AutoRouteService, "get_route", lambda model: AutoRoute("auto:synthetic", (MODEL, OTHER), "revision-1"))
    app = Flask(__name__)
    with app.test_request_context("/v1/chat/completions", method="POST", headers={"Session-Id": "test"}):
        assert affinity.request_scope(PAYLOAD, app.config) is None
        g.authenticated_user = {"username": "alice", "role": "coding"}
        assert affinity.request_scope(PAYLOAD, app.config) is not None
        assert affinity.request_scope({**PAYLOAD, "model": MODEL}, app.config) is None
    with app.test_request_context("/proxy/provider", method="POST"):
        g.authenticated_user = {"username": "alice"}
        assert affinity.request_scope(PAYLOAD, app.config) is None


def test_cache_cost_evidence_preserves_unknowns_and_labels_estimates(monkeypatch):
    from services.prompt_cache_cost import CacheObservation
    monkeypatch.setenv("MODEL_PRICING_USD_PER_MILLION", json.dumps({MODEL: {"input": 2, "cache_read": 0.2, "output": 4}}))
    monkeypatch.setenv("PROMPT_CACHE_PRICE_METADATA_JSON", "")
    measured = CacheObservation.from_body({"usage": {"prompt_tokens": 100, "completion_tokens": 5,
                                                    "prompt_tokens_details": {"cached_tokens": 80}}})
    assert affinity.cache_cost_evidence(MODEL, measured) == (80, 16.0, 160.0)
    bind(scope(), usage=measured)
    entry = affinity.store.entries()[0][1]
    assert entry.cache_read_tokens == 80
    assert entry.estimated_rebuild_cost_microusd == 160.0
    assert affinity.cache_cost_evidence(MODEL, None) == (None, None, None)
    monkeypatch.setenv("MODEL_PRICING_USD_PER_MILLION", "{}")
    assert affinity.cache_cost_evidence(MODEL, measured) == (80, None, None)


def test_model_scoped_cooldown_cannot_be_overridden(monkeypatch):
    from services.model_cooldown import model_cooldown, ModelCooldownExhausted
    monkeypatch.setenv("MODEL_COOLDOWN_ENABLED", "true")
    monkeypatch.setenv("MODEL_COOLDOWN_MAX_SECONDS", "3600")
    model_cooldown.reset()
    s = scope()
    bind(s)
    with affinity.activate_scope(s), affinity.candidate_scope(MODEL):
        CredentialPool.record("ce-gpt-plus", "synthetic-second", 429, model="synthetic", now=10)
        assert CredentialPool.select("ce-gpt-plus", model="synthetic", now=11) == "synthetic-first"
        CredentialPool.record("ce-gpt-plus", "synthetic-first", 429, model="synthetic", now=10)
        with pytest.raises(ModelCooldownExhausted):
            CredentialPool.select("ce-gpt-plus", model="synthetic", now=11)
    model_cooldown.reset()


def test_stream_exception_evicts_and_propagates():
    s = scope()
    bind(s)
    def broken():
        yield b'data: {"choices":[{"delta":{"content":"text"}}]}\n\n'
        raise OSError("synthetic interrupted socket")
    response = observed_response(s, broken(), stream=True)
    with pytest.raises(OSError):
        list(response.response)
    assert s.preferred_key(MODEL, ["synthetic-second"]) is None
    response.close()


@pytest.mark.parametrize("path,body", [
    ("/v1/chat/completions", {"messages": PAYLOAD["messages"]}),
    ("/v1/responses", {"input": "private first turn"}),
    ("/v1/messages", {"messages": PAYLOAD["messages"], "max_tokens": 128})])
@pytest.mark.parametrize("flag", ["false", "true"])
@pytest.mark.parametrize("fallback", [False, True])
def test_registered_managed_alias_preserves_bytes_and_prefers_completed_key(monkeypatch, path, body, flag, fallback):
    monkeypatch.setenv("PROMPT_CACHE_AFFINITY_ENABLED", flag)
    monkeypatch.setenv("ADMIN_API_KEY", "admin-test-key")
    monkeypatch.setenv("FLASK_SECRET_KEY", "test-secret")
    monkeypatch.setenv("JWT_SECRET", "jwt-test-secret")
    with patch("env_loader.load_runtime_env"), patch("config.load_runtime_env"):
        app_module = importlib.import_module("app")
    with patch.object(app_module, "load_runtime_env"), patch("config.load_runtime_env"):
        app = app_module.create_app()
    app.config.update(WTF_CSRF_ENABLED=False, IMAGE_RELAY_CATALOG_AUTO_REFRESH=False,
                      PROMPT_CACHE_ENABLED=False, NANOGPT_SPEED_ROUTING="")
    from services.auto_route_service import AutoRouteService, AutoRoute
    monkeypatch.setattr(AutoRouteService, "get_route", lambda model: AutoRoute("auto:synthetic", (MODEL, OTHER), "revision-1"))
    monkeypatch.setattr(app_module.AuthService, "verify_api_key", lambda *args: {"username": "alice", "is_admin": True})
    tokens = []
    payloads = []
    providers = []
    wire = json.dumps({"id": "synthetic", "object": "chat.completion", "model": "synthetic",
                      "choices": [{"message": {"role": "assistant", "content": "answer"}, "finish_reason": "stop"}]}).encode()
    def send(**kwargs):
        tokens.append(kwargs["headers"]["Authorization"])
        payloads.append(kwargs["data"])
        providers.append(kwargs["api_provider"])
        if fallback and kwargs["api_provider"] == "ce-gpt-plus":
            return Response(b'{"error":{"message":"rate limited"}}', status=429, mimetype="application/json")
        return Response(wire, mimetype="application/json")
    monkeypatch.setattr(app_module.ProxyService, "make_request", send)
    monkeypatch.setattr(app_module.ProxyService, "probe_nanogpt_key", lambda *args: pytest.fail("unexpected live probe"))
    from services.protocol_translation import responses as responses_translation
    monkeypatch.setattr(responses_translation, "new_id", lambda prefix: f"{prefix}_synthetic")
    CredentialPool.record("ce-gpt-plus", "synthetic-first", 429)
    client = app.test_client()
    headers = {"Authorization": "Bearer admin-test-key", "Session-Id": "conversation"}
    first = client.post(path, json={"model": "auto:synthetic", **body}, headers=headers, buffered=True)
    assert first.status_code == 200, first.data
    CredentialPool.reset()
    second = client.post(path, json={"model": "auto:synthetic", **body}, headers=headers, buffered=True)
    assert second.status_code == 200, second.data
    assert first.data == second.data
    if fallback:
        assert providers == ["ce-gpt-plus", "ce-gpt-pro"] * 2
        assert payloads[:2] == payloads[2:]
        assert tokens == ["Bearer synthetic-second", "Bearer synthetic-first", "Bearer synthetic-first", "Bearer synthetic-first"]
        if flag == "true":
            assert affinity.store.entries()[0][1].model == OTHER
    else:
        assert payloads[0] == payloads[1]
        assert tokens == ["Bearer synthetic-second", "Bearer " + ("synthetic-second" if flag == "true" else "synthetic-first")]
    assert len(affinity.store) == (1 if flag == "true" else 0)
