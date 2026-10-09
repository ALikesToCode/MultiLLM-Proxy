"""Request isolation, bounded parsing and managed dispatch with fake upstreams."""

import importlib
import json
import os
from unittest.mock import patch

import pytest
from flask import Flask, Response, g, request
from tests.unified_api_test_case import UnifiedApiTestCase


ROUTE = "/v1/chat/completions"
EMAIL = "alice@school.org"
PHONE = "+1 (415) 555-2671"
CARD = "4111 1111 1111 1111"


def modules():
    return importlib.import_module("services.pii_redaction"), importlib.import_module("services.pii_stream")


def settings(mode="required", **extra):
    return {"PII_REDACTION_ENABLED": "true", "PII_REDACTION_POLICY_JSON": json.dumps({
        "routes": [ROUTE], "detectors": ["email", "phone", "card"], "mode": mode, **extra})}


def prepare(text, env=None, **kwargs):
    redaction, _ = modules()
    return redaction.prepare_payload({"messages": [{"role": "user", "content": text}]},
        settings() if env is None else env, route=ROUTE, **kwargs)


def test_modules_are_available():
    redaction, stream = modules()
    assert callable(redaction.prepare_payload) and callable(stream.rehydrate_response)


@pytest.mark.parametrize("env", [{}, {"PII_REDACTION_ENABLED": ""},
    {"PII_REDACTION_ENABLED": "true", "PII_REDACTION_POLICY_JSON": ""}, settings(routes=[]),
    settings(keys=["other"], routes=[])])
def test_disabled_and_unscoped_payload_is_same_object(env):
    redaction, _ = modules()
    payload = {"content": EMAIL}
    prepared = redaction.prepare_payload(payload, env, route=ROUTE)
    assert prepared.payload is payload and prepared.context is None


def test_raw_never_transforms_and_key_scope_opts_in():
    result = prepare(EMAIL, settings(routes=[], keys=["key-7"]), key_scope="key-7")
    assert result.context.restore(result.payload["messages"][0]["content"]) == EMAIL
    assert prepare(EMAIL, raw=True).context is None


@pytest.mark.parametrize("value", [EMAIL, PHONE, CARD])
def test_detector_round_trip_and_request_isolation(value):
    first, second = prepare(value), prepare(value)
    token = first.payload["messages"][0]["content"]
    assert value not in token and token.startswith("__MLPII_") and len(token) == 74
    assert first.context.restore(token) == value
    assert second.context.restore(token) == token
    forged = token[:-3] + ("1" if token[-3] == "0" else "0") + "__"
    assert first.context.restore(forged) != value
    first.context.close()
    assert first.context.restore(token) == token and not first.context.values


@pytest.mark.parametrize("text", ["4111 1111 1111 1112", "123", "123456789012345678901", "bad@local", "x" * 65 + "@school.org"])
def test_false_positives_remain_unchanged(text):
    assert prepare(text).payload["messages"][0]["content"] == text


def test_secret_findings_are_never_placeholders_even_in_observe_mode(monkeypatch):
    monkeypatch.setenv("SECRET_SCAN_DEFAULT", "observe")
    text = "postgres://owner:S3cur3Password42@school.org/db " + EMAIL
    result = prepare(text)
    assert list(result.context.values.values()) == [EMAIL]
    assert result.context.restore(result.payload["messages"][0]["content"]) == text


def test_required_limits_and_best_effort_are_atomic():
    redaction, _ = modules()
    for text in ["x" * (1024 * 1024 + 1), " ".join(f"p{i}@school.org" for i in range(513))]:
        with pytest.raises(redaction.PIIRedactionError):
            prepare(text)
        result = prepare(text, settings("best_effort"))
        assert result.context is None and result.skipped and result.payload["messages"][0]["content"] == text


@pytest.mark.parametrize("env", [{"PII_REDACTION_ENABLED": "broken-value"},
    {"PII_REDACTION_ENABLED": "true", "PII_REDACTION_POLICY_JSON": "broken-value"},
    settings(detectors=["semantic"]), settings(mode="invalid")])
def test_malformed_config_off_warns_once_without_value(env, caplog):
    redaction, _ = modules()
    redaction._warned.clear()
    prepare(EMAIL, env)
    prepare(EMAIL, env)
    assert len(caplog.records) == 1 and "broken-value" not in caplog.text


def test_nonstream_restores_escaped_json_and_unknown_tokens():
    _, stream = modules()
    result = prepare(EMAIL)
    token = result.payload["messages"][0]["content"]
    unknown = "__MLPII_" + "0" * 64 + "__"
    response = Response(json.dumps({"content": "é " + token + " " + unknown}), content_type="application/json")
    stream.rehydrate_response(response, result.context)
    assert response.json == {"content": "é " + EMAIL + " " + unknown}
    assert not result.context.values and "Content-Length" not in response.headers


def stream_bytes(chunks, context):
    _, stream = modules()
    return b"".join(stream.RehydratingIterator(iter(chunks), context, event_stream=True))


def test_every_byte_split_utf8_and_json_escape():
    result = prepare(EMAIL)
    token = result.payload["messages"][0]["content"]
    data = ('data: {"choices":[{"delta":{"content":"é ' + token.replace("_", "\\u005f") +
        '\\n"}}]}\r\n\r\ndata: [DONE]\r\n\r\n').encode()
    for split in range(1, len(data)):
        result = prepare(EMAIL)
        current = result.payload["messages"][0]["content"]
        wire = data.replace(token.encode(), current.encode()) if token.encode() in data else data.replace(
            token.replace("_", "\\u005f").encode(), current.replace("_", "\\u005f").encode())
        output = stream_bytes([wire[:split], wire[split:]], result.context)
        first = json.loads(output.splitlines()[0][6:])
        assert first["choices"][0]["delta"]["content"] == "é " + EMAIL + "\n"
        assert not result.context.values


def test_placeholder_across_events_never_emits_partial_prefix():
    result = prepare(EMAIL)
    token = result.payload["messages"][0]["content"]
    chunks = [f'data: {{"choices":[{{"delta":{{"content":{json.dumps(part)}}}}}]}}\n\n'.encode()
        for part in ["hello " + token[:13], token[13:60], token[60:] + "!"]]
    output = stream_bytes(chunks, result.context)
    texts = [json.loads(line[6:])["choices"][0]["delta"]["content"] for line in output.splitlines() if line.startswith(b"data:")]
    assert texts == ["hello ", "", EMAIL + "!"]
    assert b"__MLPII_" not in output


def test_terminal_partial_parser_overflow_and_disconnect_clear_map():
    _, stream = modules()
    for wire in [b'data: {"content":"__MLPII_"}\n\ndata: [DONE]\n\n', b"data: " + b"x" * 65537]:
        result = prepare(EMAIL)
        with pytest.raises(stream.PIIStreamError):
            stream_bytes([wire], result.context)
        assert not result.context.values
    result = prepare(EMAIL)
    iterator = stream.RehydratingIterator(iter([b"data: "]), result.context, event_stream=True)
    iterator.close()
    assert not result.context.values


def test_secret_fields_are_not_reversible():
    redaction, _ = modules()
    result = redaction.prepare_payload({"password": "A1ice42@school.org", "content": EMAIL}, settings(), route=ROUTE)
    assert list(result.context.values.values()) == [EMAIL]
    assert result.payload["password"] == "A1ice42@school.org"


def test_nonstream_terminal_prefix_is_a_real_error():
    _, stream = modules()
    result = prepare(EMAIL)
    response = Response(json.dumps({"content": "__MLPII_"}), content_type="application/json")
    stream.rehydrate_response(response, result.context)
    assert response.status_code == 502 and b"__MLPII_" not in response.data
    assert not result.context.values


def test_nested_custom_text_also_withholds_terminal_prefix():
    _, stream = modules()
    result = prepare(EMAIL)
    response = Response(json.dumps({"custom": ["__MLPII_"]}), content_type="application/json")
    stream.rehydrate_response(response, result.context)
    assert response.status_code == 502 and b"__MLPII_" not in response.data


def test_stream_carry_bound_and_unknown_placeholder():
    _, stream = modules()
    result = prepare(EMAIL)
    token = result.payload["messages"][0]["content"]
    frames = [json.dumps({"choices": [{"delta": {"content": token[:65]}}] * 2}).encode()]
    with pytest.raises(stream.PIIStreamError):
        stream_bytes([b"data: " + frames[0] + b"\n\n"], result.context)
    assert not result.context.values
    result = prepare(EMAIL)
    unknown = "__MLPII_" + "0" * 64 + "__"
    assert unknown.encode() in stream_bytes([f'data: {{"content":"{unknown}"}}\n\n'.encode()], result.context)


def test_collision_failure_is_atomic(monkeypatch):
    redaction, _ = modules()
    class Digest:
        def hexdigest(self):
            return "0" * 64
    monkeypatch.setattr(redaction.hmac, "new", lambda *args: Digest())
    with pytest.raises(redaction.PIIRedactionError):
        prepare(EMAIL + " bob@school.org")
    result = prepare(EMAIL + " bob@school.org", settings("best_effort"))
    assert result.skipped and result.context is None


def test_random_secret_failure_obeys_policy(monkeypatch):
    redaction, _ = modules()
    def unavailable(size):
        raise OSError("synthetic entropy failure")
    monkeypatch.setattr(redaction.secrets, "token_bytes", unavailable)
    with pytest.raises(redaction.PIIRedactionError):
        prepare(EMAIL)
    result = prepare(EMAIL, settings("best_effort"))
    assert result.skipped and result.payload["messages"][0]["content"] == EMAIL


def test_parser_output_queue_is_bounded_and_close_drops_buffered_output():
    _, stream = modules()
    result = prepare(EMAIL)
    wire = b'data: {"content":"' + b"x" * 1000 + b'"}\n\n'
    iterator = stream.RehydratingIterator(iter([wire * 1100]), result.context, event_stream=True)
    with pytest.raises(stream.PIIStreamError):
        next(iterator)
    assert not result.context.values
    result = prepare(EMAIL)
    iterator = stream.RehydratingIterator(iter([wire * 2]), result.context, event_stream=True)
    next(iterator)
    iterator.close()
    with pytest.raises(StopIteration):
        next(iterator)


def test_restored_values_are_json_escaped():
    redaction, stream = modules()
    context = redaction.PIIContext()
    value = 'é "quoted"\\path\n'
    token = context.issue(value)
    response = Response(json.dumps({"content": token}), content_type="application/json")
    stream.rehydrate_response(response, context)
    assert response.json == {"content": value}


class RegisteredPIITests(UnifiedApiTestCase):
    def setUp(self):
        flags = {name: "false" for name in (
            "MANAGED_IDEMPOTENCY_ENABLED", "PROTOCOL_EXTRAS_ENABLED", "PROMPT_CACHE_AFFINITY_ENABLED",
            "USAGE_RESERVATIONS_ENABLED", "CONTENT_RETENTION_ENABLED", "GENERATION_CACHE_SHARED_ENABLED",
            "USAGE_LEDGER_ENABLED", "CONFIG_REVISION_SYNC_ENABLED")}
        flags.update(settings())
        flags.update(SESSION_TIER_MODE="off", SECRET_SCAN_DEFAULT="off")
        self.flags = patch.dict(os.environ, flags)
        self.flags.start()
        self.addCleanup(self.flags.stop)
        with patch("config.load_runtime_env"):
            super().setUp()
        self.app.config["OUTPUT_SCHEMA_VALIDATION_ENABLED"] = False
        redaction, _ = modules()
        redaction.register_pii_redaction(self.app)
        hooks = self.app.extensions["gateway_after_authentication"]
        hooks.remove(redaction.pii_request_hook)
        hooks.insert(1, redaction.pii_request_hook)
        self.headers = {"Authorization": "Bearer admin-test-key"}

    def test_registered_unified_redacts_and_bypasses_exact_and_shared_cache(self):
        body = {"model": "mimo:mimo-v2.5", "messages": [{"role": "user", "content": EMAIL}], "temperature": 0}
        calls = []
        def provider(**kwargs):
            payload = json.loads(kwargs["data"])
            calls.append(payload)
            return self._chat_response(payload["messages"][0]["content"])
        with patch.object(self.app_module.ProxyService, "make_request", side_effect=provider):
            for shared in ("false", "true"):
                os.environ["GENERATION_CACHE_SHARED_ENABLED"] = shared
                for _ in range(2):
                    response = self.client.post(ROUTE, json=body, headers={**self.headers, "X-MultiLLM-Cache": "on"})
                    assert response.status_code == 200
                    assert response.json["choices"][0]["message"]["content"] == EMAIL
                    assert response.headers["X-MultiLLM-Cache"] == "bypass"
        assert len(calls) == 4 and EMAIL not in json.dumps(calls)

    def test_registered_required_failure_and_idempotency_do_not_dispatch(self):
        body = {"model": "mimo:mimo-v2.5", "messages": [{"role": "user", "content": EMAIL}]}
        with patch.object(self.app_module.ProxyService, "make_request", side_effect=AssertionError("unexpected dispatch")):
            error = self.client.post(ROUTE, json=body, headers={**self.headers, "Idempotency-Key": "synthetic"})
            assert error.status_code == 400 and error.json["error"]["code"] == "pii_idempotency_unsupported"
            body["messages"][0]["content"] = "x" * (1024 * 1024 + 1)
            error = self.client.post(ROUTE, json=body, headers=self.headers)
            assert error.status_code == 422 and error.json["error"]["code"] == "pii_redaction_failed"

    def test_registered_default_off_is_unchanged(self):
        os.environ["PII_REDACTION_ENABLED"] = "false"
        upstream = self._chat_response(EMAIL)
        body = {"model": "mimo:mimo-v2.5", "messages": [{"role": "user", "content": EMAIL}]}
        with patch.object(self.app_module.ProxyService, "make_request", return_value=upstream) as send:
            response = self.client.post(ROUTE, json=body, headers=self.headers)
        assert response.data == upstream.content
        assert json.loads(send.call_args.kwargs["data"])["messages"] == body["messages"]

    def test_registered_stream_restores_fragments_and_disconnect_clears_map(self):
        import io
        import requests
        contexts = []
        def provider(**kwargs):
            token = json.loads(kwargs["data"])["messages"][0]["content"]
            contexts.append(modules()[0].current_context())
            frames = [json.dumps({"choices": [{"delta": {"content": part}}]}).encode()
                for part in (token[:13], token[13:], "!")]
            wire = b"".join(b"data: " + frame + b"\n\n" for frame in frames) + b"data: [DONE]\n\n"
            upstream = requests.Response()
            upstream.status_code = 200
            upstream.headers["Content-Type"] = "text/event-stream"
            upstream.raw = io.BytesIO(wire)
            upstream.iter_content = lambda chunk_size=1, **options: iter(wire[i:i + 1] for i in range(len(wire)))
            return upstream
        body = {"model": "mimo:mimo-v2.5", "messages": [{"role": "user", "content": EMAIL}], "stream": True}
        with patch.object(self.app_module.ProxyService, "make_request", side_effect=provider):
            response = self.client.post(ROUTE, json=body, headers=self.headers)
            wire = response.get_data()
            pieces = [json.loads(line[6:])["choices"][0]["delta"]["content"] for line in wire.splitlines()
                if line.startswith(b"data: {")]
            assert "".join(pieces) == EMAIL + "!" and b"__MLPII_" not in wire
            assert contexts[-1].closed and not contexts[-1].values
            response = self.client.post(ROUTE, json=body, headers=self.headers, buffered=False)
            response.close()
            assert contexts[-1].closed and not contexts[-1].values


def test_registered_hook_dispatch_stream_and_cache_idempotency_guards(monkeypatch):
    redaction, _ = modules()
    from services.managed_dispatch import execute_managed_attempt, observe_managed_response
    from services.retention_policy import request_policy
    import requests

    for key, value in settings().items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("SECRET_SCAN_DEFAULT", "off")
    app = Flask(__name__)
    redaction.register_pii_redaction(app)
    calls = []

    @app.before_request
    def authenticated():
        g.authenticated_user = {"id": "key-7"}
        for hook in app.extensions["gateway_after_authentication"]:
            error = hook()
            if error is not None:
                return error

    @app.post(ROUTE)
    def completion():
        payload = request.get_json()
        assert not request_policy().allows_content
        token = payload["messages"][0]["content"]
        def send():
            calls.append(payload)
            upstream = requests.Response()
            upstream.status_code = 200
            return upstream
        upstream = execute_managed_attempt(send, "synthetic", "synthetic")
        body = Response(json.dumps({"choices": [{"message": {"content": token}, "finish_reason": "stop"}]}), content_type="application/json")
        return observe_managed_response(body, upstream)

    client = app.test_client()
    body = {"model": "auto:synthetic", "messages": [{"role": "user", "content": EMAIL}]}
    response = client.post(ROUTE, json=body)
    assert response.status_code == 200 and response.json["choices"][0]["message"]["content"] == EMAIL
    assert EMAIL not in json.dumps(calls)
    response = client.post(ROUTE, json=body, headers={"Idempotency-Key": "synthetic"})
    assert response.status_code == 400 and len(calls) == 1
