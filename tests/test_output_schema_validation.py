"""Explicit managed validation with synthetic dispatch and no provider access."""

import json
import importlib
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock, patch

import pytest
from flask import Flask, Response, request

from routes import tool_repair
from services import output_schema_validation as validation
from tests.unified_api_test_case import UnifiedApiTestCase

SCHEMA = {"type": "object", "properties": {"count": {"type": "integer"}}, "required": ["count"]}
OPTION = "multillm_output_validation"


@pytest.fixture(autouse=True)
def pin_flag(monkeypatch):
    monkeypatch.setenv(validation.ENV_KEY, "false")


def completion(content):
    return {"choices": [{"message": {"content": content}}]}


def payload(schema=SCHEMA, **extra):
    return {"model": "synthetic:model", OPTION: {"mode": "strict", "schema": schema}, **extra}


def client_for(answer, *, enabled="true", protocol="chat"):
    app = Flask(__name__)
    app.config.update(TESTING=True, OUTPUT_SCHEMA_VALIDATION_ENABLED=enabled)
    dispatch = Mock(return_value=answer)
    wrapped = tool_repair.with_managed_output_validation(dispatch, protocol=protocol)

    @app.post("/v1/chat/completions")
    def managed():
        return wrapped(app, None, None, None, request.get_json())

    @app.post("/raw")
    def raw():
        return dispatch(app, None, None, None, request.get_json())

    return app.test_client(), dispatch


@pytest.mark.parametrize("enabled", [False, "false", "", "bad-value", None])
def test_off_preserves_option_and_response_bytes(enabled):
    body = b'  {"vendor":"native", "choices": []}\n'
    answer = Response(body, headers={"X-Synthetic": "keep"}, content_type="application/json")
    client, dispatch = client_for(answer, enabled=enabled)
    original = payload(schema="not a schema", stream=True)
    response = client.post("/v1/chat/completions", json=original)
    assert response.data == body and response.headers["X-Synthetic"] == "keep"
    assert dispatch.call_args.args[4] == original
    assert dispatch.call_count == 1


def test_no_option_and_raw_native_are_unchanged():
    for path, body in [("/v1/chat/completions", {"model": "synthetic:model"}), ("/raw", payload(stream=True))]:
        client, dispatch = client_for(Response(b"vendor bytes", content_type="text/plain"))
        response = client.post(path, json=body)
        assert response.data == b"vendor bytes"
        assert dispatch.call_args.args[4] == body


def test_valid_response_preserves_bytes_and_strips_only_gateway_option():
    body = json.dumps(completion('{"count":2}'), indent=2).encode()
    client, dispatch = client_for(Response(body, content_type="application/json"))
    original = payload(response_format={"type": "json_object"})
    response = client.post("/v1/chat/completions", json=original)
    assert response.status_code == 200 and response.data == body
    assert dispatch.call_args.args[4] == {key: value for key, value in original.items() if key != OPTION}
    assert OPTION in original and dispatch.call_count == 1


@pytest.mark.parametrize("content,reason", [
    ("private-response-canary", "invalid_json"), ('{"count":"private-response-canary"}', "schema_mismatch"),
    ('{"count":1,"count":2}', "invalid_json"), ("NaN", "invalid_json"), ("1e999", "invalid_json"),
])
def test_invalid_content_is_redacted_and_never_reasks(content, reason):
    client, dispatch = client_for(Response(json.dumps(completion(content)), content_type="application/json"))
    response = client.post("/v1/chat/completions", json=payload())
    assert response.status_code == 502
    assert response.json["error"]["code"] == "output_schema_violation"
    assert response.json["error"]["reason"] == reason
    assert "private-response-canary" not in response.get_data(as_text=True)
    assert dispatch.call_count == 1


@pytest.mark.parametrize("option", [None, True, {}, {"mode": "repair", "schema": {}}, {"mode": "strict"},
                                    {"mode": "strict", "schema": []}, {"mode": "strict", "schema": {}, "extra": True}])
def test_bad_option_fails_before_dispatch(option):
    client, dispatch = client_for(Response("unused"))
    response = client.post("/v1/chat/completions", json={OPTION: option})
    assert response.status_code == 400
    dispatch.assert_not_called()


def test_stream_rejected_before_dispatch():
    client, dispatch = client_for(Response("unused"))
    response = client.post("/v1/chat/completions", json=payload(stream=True))
    assert response.status_code == 400
    assert response.json["error"]["code"] == "output_validation_requires_nonstream"
    dispatch.assert_not_called()


@pytest.mark.parametrize("schema", [
    {"$ref": "https://example.test/private-schema"}, {"$ref": "file:///private-schema"},
    {"$defs": {"hidden": {"$dynamicRef": "https://example.test/schema"}}},
    {"type": "unknown"}, {"description": "x" * 65536}, {"enum": list(range(5000))},
    {"pattern": "(a+)+$"}, {"patternProperties": {"(a+)+$": {}}},
    {"$defs": {"other": {"$schema": "http://json-schema.org/draft-07/schema#"}}},
    {"$schema": "http://json-schema.org/draft-03/schema#"},
    {"$ref": "#/const", "const": {"pattern": "(a+)+$"}},
    {"$ref": "#/const", "const": {"$schema": "http://json-schema.org/draft-07/schema#", "$ref": "#"}},
    {"$defs": {"scope": {"$id": "https://example.test/other", "$ref": "#/const"}}, "const": {"pattern": "(a+)+$"}},
])
def test_unsafe_schemas_fail_without_remote_retrieval(schema):
    client, dispatch = client_for(Response("unused"))
    with patch("urllib.request.urlopen") as fetch:
        response = client.post("/v1/chat/completions", json=payload(schema))
    assert response.status_code == 400
    assert "private-schema" not in response.get_data(as_text=True)
    dispatch.assert_not_called()
    fetch.assert_not_called()


def test_deep_schema_is_rejected_before_dispatch():
    schema = {}
    for _ in range(40):
        schema = {"properties": {"child": schema}}
    client, dispatch = client_for(Response("unused"))
    assert client.post("/v1/chat/completions", json=payload(schema)).status_code == 400
    dispatch.assert_not_called()


@pytest.mark.parametrize("dialect", [None, "http://json-schema.org/draft-07/schema#"])
def test_local_refs_and_literal_ref_property_work(dialect):
    schema = {"$defs": {"number": {"type": "integer"}}, "properties": {"$ref": {"$ref": "#/$defs/number"}}}
    if dialect:
        schema["$schema"] = dialect
    client, dispatch = client_for(Response(json.dumps(completion('{"$ref":2}')), content_type="application/json"))
    assert client.post("/v1/chat/completions", json=payload(schema)).status_code == 200
    assert dispatch.call_count == 1


def test_recursive_reference_hits_validation_work_bound():
    client, dispatch = client_for(Response(json.dumps(completion('{}')), content_type="application/json"))
    response = client.post("/v1/chat/completions", json=payload({"$ref": "#", "$schema": "http://json-schema.org/draft-07/schema#"}))
    assert response.status_code == 502 and response.json["error"]["reason"] == "work_limit"
    assert dispatch.call_count == 1


def test_work_steps_and_elapsed_limit(monkeypatch):
    for budget in ("MAX_VALIDATION_STEPS", "MAX_VALIDATION_SECONDS"):
        with monkeypatch.context() as scoped:
            scoped.setattr(validation, budget, 0)
            client, dispatch = client_for(Response(json.dumps(completion('{"count":2}')), content_type="application/json"))
            response = client.post("/v1/chat/completions", json=payload())
            assert response.status_code == 502 and response.json["error"]["reason"] == "work_limit"
            assert dispatch.call_count == 1


def test_error_paths_are_bounded_and_dynamic_keys_are_redacted():
    content = json.dumps({"private-field-canary": ["private-value-canary"] * 150})
    schema = {"additionalProperties": {"items": {"type": "integer"}}}
    client, _ = client_for(Response(json.dumps(completion(content)), content_type="application/json"))
    response = client.post("/v1/chat/completions", json=payload(schema))
    error = response.json["error"]
    assert response.status_code == 502 and len(error["paths"]) == 100
    assert error["paths"][0] == "/*/0"
    assert "private-field-canary" not in response.get_data(as_text=True)
    assert "private-value-canary" not in response.get_data(as_text=True)


@pytest.mark.parametrize("body,reason", [(b"x" * (1024 * 1024 + 1), "body_limit"), (b"not JSON", "invalid_response"),
                                      (b'{"choices":[]}', "invalid_response")])
def test_invalid_envelope_is_closed(body, reason):
    closed = Mock()
    answer = Response(iter([body]), content_type="application/json")
    answer.call_on_close(closed)
    client, dispatch = client_for(answer)
    response = client.post("/v1/chat/completions", json=payload())
    assert response.status_code == 502 and response.json["error"]["reason"] == reason
    closed.assert_called_once()
    assert dispatch.call_count == 1


def test_unexpected_stream_is_closed_without_consuming_it():
    consume = Mock(return_value=b"data: private-response-canary\n\n")
    closed = Mock()
    answer = Response((consume() for _ in range(1)), content_type="text/event-stream")
    answer.call_on_close(closed)
    client, _ = client_for(answer)
    assert client.post("/v1/chat/completions", json=payload()).status_code == 502
    consume.assert_not_called()
    closed.assert_called_once()


def test_upstream_error_is_unchanged():
    client, _ = client_for(Response(b"provider error", status=429, headers={"Retry-After": "7"}))
    response = client.post("/v1/chat/completions", json=payload())
    assert response.status_code == 429 and response.data == b"provider error"
    assert response.headers["Retry-After"] == "7"


@pytest.mark.parametrize("protocol,answer", [
    ("messages", {"content": [{"type": "text", "text": '{"count":2}'}]}),
    ("responses", {"output": [{"type": "message", "content": [{"type": "output_text", "text": '{"count":2}'}]}]}),
])
def test_managed_protocols_validate_without_translation(protocol, answer):
    body = json.dumps(answer, indent=2).encode()
    client, dispatch = client_for(Response(body, content_type="application/json"), protocol=protocol)
    response = client.post("/v1/chat/completions", json=payload())
    assert response.status_code == 200 and response.data == body and dispatch.call_count == 1


def test_validation_state_is_request_local():
    client, dispatch = client_for(Response(json.dumps(completion('2')), content_type="application/json"))
    assert client.post("/v1/chat/completions", json=payload({"type": "integer"})).status_code == 200
    dispatch.return_value = Response(json.dumps(completion('2')), content_type="application/json")
    assert client.post("/v1/chat/completions", json=payload({"type": "string"})).status_code == 502
    assert dispatch.call_count == 2


def test_budget_is_shared_by_all_choices(monkeypatch):
    monkeypatch.setattr(validation, "MAX_VALIDATION_STEPS", 1)
    body = {"choices": [{"message": {"content": "1"}}, {"message": {"content": "2"}}]}
    client, _ = client_for(Response(json.dumps(body), content_type="application/json"))
    response = client.post("/v1/chat/completions", json=payload({"type": "integer"}))
    assert response.status_code == 502 and response.json["error"]["reason"] == "work_limit"


@pytest.mark.parametrize("content,schema", [(json.dumps([1] * 5000), True),
                                           (json.dumps([{}] * 129), {"uniqueItems": True}),
                                           ("[" * 40 + "0" + "]" * 40, True)])
def test_output_complexity_and_quadratic_work_are_bounded(content, schema):
    client, _ = client_for(Response(json.dumps(completion(content)), content_type="application/json"))
    response = client.post("/v1/chat/completions", json=payload(schema))
    assert response.status_code == 502 and response.json["error"]["reason"] == "work_limit"


def test_valid_boolean_schema_and_literal_pattern_keys():
    for schema, content in [(True, "null"), ({"const": {"pattern": "literal"}}, '{"pattern":"literal"}')]:
        client, _ = client_for(Response(json.dumps(completion(content)), content_type="application/json"))
        assert client.post("/v1/chat/completions", json=payload(schema)).status_code == 200


def test_safe_schema_referenced_under_literal_keyword_is_budgeted():
    schema = {"$ref": "#/const", "const": {"type": "integer"}}
    client, _ = client_for(Response(json.dumps(completion('1')), content_type="application/json"))
    # const remains an assertion in the root schema, so this is a real mismatch.
    response = client.post("/v1/chat/completions", json=payload(schema))
    assert response.status_code == 502 and response.json["error"]["reason"] == "schema_mismatch"


def test_false_schema_and_missing_reference_are_real_failures():
    for schema in [False, {"$ref": "#/$defs/missing"}]:
        client, _ = client_for(Response(json.dumps(completion('{}')), content_type="application/json"))
        response = client.post("/v1/chat/completions", json=payload(schema))
        assert response.status_code == 502 and response.json["error"]["reason"] == "schema_mismatch"


def test_invalid_setting_logs_once_without_its_value(monkeypatch, caplog):
    monkeypatch.setattr(validation, "_warned_invalid_setting", False)
    for _ in range(2):
        assert not validation.enabled({validation.ENV_KEY: "private-setting-canary"})
    assert sum("validation disabled" in record.message for record in caplog.records) == 1
    assert "private-setting-canary" not in caplog.text


def test_env_setting_and_original_schema_are_preserved(monkeypatch):
    monkeypatch.setenv(validation.ENV_KEY, "true")
    schema = {"$schema": "http://json-schema.org/draft-07/schema#", "type": "integer"}
    original = payload(schema)
    prepared, contract = validation.prepare_validation(original, {})
    assert OPTION not in prepared and contract is not None
    assert original[OPTION]["schema"] == schema and "$schema" in schema


def test_validation_does_not_invoke_tool_repair():
    client, dispatch = client_for(Response(json.dumps(completion("invalid")), content_type="application/json"))
    with patch.object(tool_repair, "repair_completion") as repair, patch.object(tool_repair, "repair_mode") as mode:
        response = client.post("/v1/chat/completions", json=payload(tools=[{"type": "function"}]))
    assert response.status_code == 502 and dispatch.call_count == 1
    repair.assert_not_called()
    mode.assert_not_called()


def test_concurrent_validation_has_independent_budgets():
    def check(number):
        _, contract = validation.prepare_validation(payload({"const": number}), {validation.ENV_KEY: True})
        validation.validate_contents([str(number)], contract)
        return number
    with ThreadPoolExecutor(max_workers=4) as executor:
        assert list(executor.map(check, range(16))) == list(range(16))


class RegisteredManagedRouteTests(UnifiedApiTestCase):
    """Exercise real route registrations with the explicit integration hook attached."""

    def setUp(self):
        with patch("config.load_runtime_env"):
            super().setUp()
        self.app.config[validation.ENV_KEY] = True
        self.unified = importlib.import_module("routes.unified")
        self.repair = importlib.import_module("routes.tool_repair")
        for name in ("dispatch_unified_chat_completion", "dispatch_protocol_request"):
            original = getattr(self.unified, name)
            hook = patch.object(self.unified, name, self.repair.with_managed_output_validation(original))
            hook.start()
            self.addCleanup(hook.stop)

    def test_registered_chat_valid_invalid_and_stream(self):
        headers = {"Authorization": "Bearer admin-test-key"}
        body = payload(messages=[{"role": "user", "content": "synthetic query"}])
        body["model"] = "mimo:mimo-v2.5"
        with patch.object(self.app_module.ProxyService, "make_request", return_value=self._chat_response('{"count":2}')) as send:
            response = self.client.post("/v1/chat/completions", json=body, headers=headers)
        assert response.status_code == 200 and send.call_count == 1
        assert OPTION not in json.loads(send.call_args.kwargs["data"])
        with patch.object(self.app_module.ProxyService, "make_request", return_value=self._chat_response("private-response-canary")) as send:
            response = self.client.post("/v1/chat/completions", json=body, headers=headers)
        assert response.status_code == 502 and send.call_count == 1
        assert "private-response-canary" not in response.get_data(as_text=True)
        with patch.object(self.app_module.ProxyService, "make_request") as send:
            response = self.client.post("/v1/chat/completions", json={**body, "stream": True}, headers=headers)
        assert response.status_code == 400
        send.assert_not_called()

    def test_registered_translated_protocols_and_stream(self):
        headers = {"Authorization": "Bearer admin-test-key"}
        for path, fields in [("/v1/messages", {"messages": [{"role": "user", "content": "synthetic"}], "max_tokens": 50}),
                             ("/v1/responses", {"input": "synthetic"})]:
            body = payload(**fields)
            body["model"] = "mimo:mimo-v2.5"
            with patch.object(self.app_module.ProxyService, "make_request", return_value=self._chat_response('{"count":2}')) as send:
                response = self.client.post(path, json=body, headers=headers)
            assert response.status_code == 200 and send.call_count == 1
            assert OPTION not in json.loads(send.call_args.kwargs["data"])
            with patch.object(self.app_module.ProxyService, "make_request") as send:
                response = self.client.post(path, json={**body, "stream": True}, headers=headers)
            assert response.status_code == 400
            send.assert_not_called()

    def test_registered_native_protocols_preserve_bytes(self):
        headers = {"Authorization": "Bearer admin-test-key"}
        for path, model, fields, answer in [
            ("/v1/messages", "opencode:minimax-m3", {"messages": [{"role": "user", "content": "synthetic"}], "max_tokens": 50},
             {"content": [{"type": "text", "text": '{"count":2}'}]}),
            ("/v1/responses", "opencode:grok-4.6", {"input": "synthetic"},
             {"output": [{"type": "message", "content": [{"type": "output_text", "text": '{"count":2}'}]}]}),
        ]:
            upstream = self._chat_response()
            upstream._content = json.dumps(answer, indent=2).encode()
            body = payload(**fields)
            body["model"] = model
            with patch.object(self.app_module.ProxyService, "make_request", return_value=upstream) as send:
                response = self.client.post(path, json=body, headers=headers)
            assert response.status_code == 200 and response.data == upstream.content and send.call_count == 1
            assert OPTION not in json.loads(send.call_args.kwargs["data"])
