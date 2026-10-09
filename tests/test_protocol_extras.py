"""Source-bound metadata, conservative provider admission and managed route checks."""

import copy
import importlib
import json
from unittest.mock import patch

import pytest
from flask import Flask, Response

from services import protocol_extras as extras
from services import protocol_translation as translation
from tests.test_protocol_routes import CHAT_COMPLETION, json_upstream
from tests.unified_api_test_case import UnifiedApiTestCase


@pytest.fixture(autouse=True)
def configured(monkeypatch):
    global extras, translation
    extras = importlib.import_module("services.protocol_extras")
    translation = importlib.import_module("services.protocol_translation")
    monkeypatch.setenv("PROTOCOL_EXTRAS_ENABLED", "true")
    monkeypatch.setenv("PROMPT_CACHE_USAGE_BUCKETS_ENABLED", "false")
    requests = importlib.import_module("requests")

    def no_http(*args, **kwargs):
        raise AssertionError("unexpected external HTTP call")

    monkeypatch.setattr(requests.sessions.Session, "request", no_http)


def body(protocol="messages", fields=None):
    result = {"model": "opencode:kimi-k2.6"}
    result["input" if protocol == "responses" else "messages"] = (
        "private" if protocol == "responses" else [{"role": "user", "content": "private"}])
    result["_multillm"] = {"protocol_extras": {
        "source_protocol": protocol, "fields": fields if fields is not None else {"top_k": 7}}}
    return result


def test_round_trip_retains_only_with_source_and_provider_admission():
    request = body()
    original = copy.deepcopy(request)
    ir = extras.request_to_ir(request, "messages")
    assert ir.extras.source_protocol == "messages"
    assert "_multillm" not in ir.body
    foreign = extras.request_from_ir(ir, "responses", admitted_fields={"top_k"})
    assert "top_k" not in foreign and "_multillm" not in foreign
    restored = extras.request_from_ir(ir, "messages", admitted_fields={"top_k"})
    assert restored["top_k"] == 7
    denied = extras.request_from_ir(ir, "messages")
    assert "top_k" not in denied
    assert request == original


@pytest.mark.parametrize("protocol,fields", [
    ("responses", {"truncation": "disabled"}),
    ("chat", {"seed": 3, "logprobs": True, "top_logprobs": 2}),
])
def test_other_source_contracts(protocol, fields):
    ir = extras.request_to_ir(body(protocol, fields), protocol)
    restored = extras.request_from_ir(ir, protocol, admitted_fields=set(fields))
    assert all(restored[key] == value for key, value in fields.items())
    assert "_multillm" not in restored


def test_duplicate_native_field_is_owned_by_the_carrier():
    request = {**body("chat", {"seed": 3}), "seed": 3}
    ir = extras.request_to_ir(request, "chat")
    assert "seed" not in ir.body
    assert "seed" not in extras.request_from_ir(ir, "chat")
    assert extras.request_from_ir(ir, "chat", admitted_fields={"seed"})["seed"] == 3


def test_chat_response_field_needs_explicit_admission_after_round_trip():
    ir = extras.response_to_ir({**CHAT_COMPLETION, "system_fingerprint": "fp_1"}, "chat")
    assert "system_fingerprint" not in ir.body
    assert "system_fingerprint" not in extras.response_from_ir(ir, "chat")
    assert extras.response_from_ir(ir, "chat", admitted_fields={"system_fingerprint"})["system_fingerprint"] == "fp_1"


@pytest.mark.parametrize("fields", [
    {"container": "private"}, {"reasoning": {"encrypted_content": "private"}},
    {"thinking": {"type": "enabled"}}, {"previous_response_id": "private"},
    {"background": True}, {"tools": [{"type": "bash"}]},
    {"authorization": "private"}, {"api_key": "private"},
    {"metadata": {"api_key": "private"}}, {"top_k": {"code": "private"}},
    {"top_k": True}, {"top_k": -1},
])
def test_unsafe_or_unreviewed_fields_fail_without_echo(fields):
    with pytest.raises(translation.TranslationError) as caught:
        extras.request_to_ir(body(fields=fields), "messages")
    assert "private" not in str(caught.value)
    assert caught.value.param == "_multillm.protocol_extras"


@pytest.mark.parametrize("namespace", [
    None, [], {"unknown-private": {}}, {"protocol_extras": []},
    {"protocol_extras": {"source_protocol": "private", "fields": {}}},
    {"protocol_extras": {"source_protocol": "responses", "fields": {}}},
    {"protocol_extras": {"source_protocol": "messages", "fields": {}, "private": True}},
])
def test_namespace_rejected(namespace):
    request = body()
    request["_multillm"] = namespace
    with pytest.raises(translation.TranslationError):
        extras.request_to_ir(request, "messages")


@pytest.mark.parametrize("fields", [
    {str(index): 1 for index in range(33)}, {"top_k": "x" * 16384},
    {"top_k": float("nan")}, {"top_k": [object()]},
])
def test_field_and_serialized_byte_bounds(fields):
    with pytest.raises(translation.TranslationError):
        extras.request_to_ir(body(fields=fields), "messages")


def test_empty_namespace_and_null_fields_are_not_silently_accepted():
    assert extras.request_to_ir({**body(), "_multillm": {}}, "messages").extras is None
    with pytest.raises(translation.TranslationError):
        extras.request_to_ir(body(fields={"top_k": None}), "messages")


def test_disabled_translators_namespace_and_raw_bytes_unchanged(monkeypatch):
    request = body(fields={"container": "private"})
    monkeypatch.setenv("PROTOCOL_EXTRAS_ENABLED", "false")
    expected = translation.translate_request(request, "messages", "chat")
    for flag in ("", "false", "0", "malformed-private"):
        monkeypatch.setenv("PROTOCOL_EXTRAS_ENABLED", flag)
        assert extras.translate_managed_request(request, "messages", "chat") == expected
        assert translation.translate_request(request, "chat", "chat") == request
    app = Flask(__name__)
    with app.test_request_context():
        bridge = importlib.import_module("routes.protocol_bridge")
        raw = Response(b' {"_multillm":{"private":true}} \n', content_type="application/json")
        result = bridge.translate_downstream_response(raw, source="messages", target="messages", stream=False)
        assert result is raw
        assert result.data == b' {"_multillm":{"private":true}} \n'


def test_enabled_raw_stream_is_unchanged_and_not_consumed():
    bridge = importlib.import_module("routes.protocol_bridge")
    seen = []

    def raw_stream():
        seen.append(True)
        yield b'data: {"_multillm":{"unreviewed":true}}\n\n'

    raw = Response(raw_stream(), content_type="text/event-stream", headers={"X-Provider": "native"})
    result = bridge.translate_downstream_response(raw, source="messages", target="messages", stream=True)
    assert result is raw and not seen
    assert result.headers["X-Provider"] == "native"
    assert result.get_data() == b'data: {"_multillm":{"unreviewed":true}}\n\n'


@pytest.mark.parametrize("protocol", ["chat", "messages", "responses"])
def test_same_protocol_managed_hook_rejects_unknown_namespace(protocol):
    request = body(protocol, {})
    request["_multillm"]["unreviewed"] = True
    with pytest.raises(translation.TranslationError):
        extras.translate_managed_request(request, protocol, protocol)


def test_native_managed_body_without_extras_keeps_existing_controls():
    request = {"model": "m", "input": "private", "previous_response_id": "existing"}
    assert extras.translate_managed_request(request, "responses", "responses") == request


def test_invalid_flag_logs_once_without_value(monkeypatch, caplog):
    monkeypatch.setattr(extras, "_warned", False)
    monkeypatch.setenv("PROTOCOL_EXTRAS_ENABLED", "private-invalid")
    assert extras.enabled() is False and extras.enabled() is False
    assert len([r for r in caplog.records if "PROTOCOL_EXTRAS_ENABLED" in r.message]) == 1
    assert "private-invalid" not in caplog.text


def test_fidelity_reports_retention_and_egress_loss_without_values():
    ir = extras.request_to_ir(body(), "messages")
    retained = extras.extras_report(ir.extras, "messages", admitted_fields={"top_k"})
    foreign = extras.extras_report(ir.extras, "responses", admitted_fields={"top_k"})
    denied = extras.extras_report(ir.extras, "messages")
    assert retained["fidelity"] == "exact"
    assert foreign["fidelity"] == denied["fidelity"] == "lossy"
    assert foreign["fields"][0]["retained_in_ir"] is True
    assert foreign["fields"][0]["re_emitted"] is False
    assert "private" not in json.dumps(foreign)
    assert "7" not in json.dumps(foreign)


def test_provider_admission_rejects_required_missing_semantics():
    ir = extras.request_to_ir(body(), "messages")
    with pytest.raises(translation.TranslationError):
        extras.request_from_ir(ir, "responses", required_fields={"top_k"})
    with pytest.raises(translation.TranslationError):
        extras.request_from_ir(ir, "messages", required_fields={"top_k"})
    assert extras.request_from_ir(ir, "messages", admitted_fields={"top_k"},
                                  required_fields={"top_k"})["top_k"] == 7


@pytest.mark.parametrize("protocol,fields", [
    ("messages", {"container": "private"}),
    ("responses", {"previous_response_id": "private"}),
])
def test_lifecycle_body_controls_still_fail(protocol, fields):
    request = body(protocol, {})
    request.update(fields)
    with pytest.raises(translation.TranslationError):
        extras.request_to_ir(request, protocol)


def test_response_round_trip_preserves_native_stop_sequence_and_usage():
    native = {"id": "msg_1", "type": "message", "model": "m", "role": "assistant",
              "content": [{"type": "text", "text": "answer"}], "stop_reason": "stop_sequence",
              "stop_sequence": "END", "usage": {"input_tokens": 4, "output_tokens": 2}}
    ir = extras.response_to_ir(native, "messages")
    foreign = extras.response_from_ir(ir, "responses", admitted_fields={"stop_sequence"})
    assert "stop_sequence" not in foreign
    same = extras.response_from_ir(ir, "messages", admitted_fields={"stop_sequence"})
    assert same["stop_sequence"] == "END"
    assert same["usage"]["input_tokens"] == 4
    assert "_multillm" not in same


def test_response_namespace_is_never_trusted():
    with pytest.raises(translation.UpstreamFailure):
        extras.response_to_ir({**CHAT_COMPLETION, "_multillm": {
            "protocol_extras": {"source_protocol": "messages", "fields": {"stop_sequence": "END"}}}}, "chat")


def test_small_translator_call_sites_validate_and_strip_enabled_namespace():
    for protocol in ("messages", "responses"):
        request = body(protocol, {"top_k": 7} if protocol == "messages" else {"truncation": "disabled"})
        converted = translation.translate_request(request, protocol, "chat")
        assert "_multillm" not in converted
        request["_multillm"]["private-unknown"] = True
        with pytest.raises(translation.TranslationError):
            translation.translate_request(request, protocol, "chat")


def test_managed_report_labels_same_source_and_foreign_source():
    report = extras.managed_request_report(body(), "messages", "messages", admitted_fields={"top_k"})
    assert report["fidelity"] == "exact"
    assert report["fields"][0]["re_emitted"] is True
    report = extras.managed_request_report(body(), "messages", "responses")
    field = next(f for f in report["fields"] if f["path"] == "request.protocol_extras.top_k")
    assert field["classification"] == "lossy" and field["retained_in_ir"] is True
    assert "private" not in json.dumps(report)
    invalid = body()
    invalid["_multillm"]["private-unknown"] = True
    assert extras.managed_request_report(invalid, "messages", "messages")["fidelity"] == "unsupported"


def test_extras_do_not_override_conflicting_body_fields():
    request = {**body(), "top_k": 9}
    with pytest.raises(translation.TranslationError):
        extras.request_to_ir(request, "messages")


def test_response_bridge_reports_reviewed_extras_loss():
    bridge = importlib.import_module("routes.protocol_bridge")
    unified_bridge = importlib.import_module("routes.unified_bridge")
    app = Flask(__name__)
    native = {**CHAT_COMPLETION, "system_fingerprint": "fp_1"}
    seen = []
    with app.test_request_context(headers={"X-MultiLLM-Conversion-Report": "1"}), \
            patch.object(unified_bridge, "record_conversion", side_effect=seen.append):
        result = bridge.translate_downstream_response(
            Response(json.dumps(native), content_type="application/json"),
            source="chat", target="messages", stream=False)
        assert result.status_code == 200
        assert "system_fingerprint" not in result.json
    field = next(f for f in seen[0]["fields"] if f["path"] == "response.protocol_extras.system_fingerprint")
    assert field["retained_in_ir"] is True and field["re_emitted"] is False


def test_prompt_cache_usage_glue_still_works_when_extras_enabled(monkeypatch):
    monkeypatch.setenv("PROMPT_CACHE_USAGE_BUCKETS_ENABLED", "true")
    monkeypatch.setenv("PROMPT_CACHE_PRICE_METADATA_JSON", "")
    native = {"type": "message", "content": [], "usage": {
        "input_tokens": 4, "cache_read_input_tokens": 3,
        "cache_creation_input_tokens": 2, "output_tokens": 1}}
    ir = extras.response_to_ir(native, "messages")
    assert ir.body["usage"]["prompt_tokens"] == 9
    same = extras.response_from_ir(ir, "messages")
    assert same["usage"]["cache_read_input_tokens"] == 3
    assert same["usage"]["cache_creation_input_tokens"] == 2


class TestManagedExtrasRoutes(UnifiedApiTestCase):
    def setUp(self):
        self.loader = patch("env_loader.load_runtime_env")
        self.loader.start()
        self.addCleanup(self.loader.stop)
        with patch("config.load_runtime_env"):
            super().setUp()
        self.http_patch = patch.object(self.app_module.ProxyService, "make_request",
                                      side_effect=AssertionError("unexpected provider call"))
        self.http = self.http_patch.start()
        self.addCleanup(self.http_patch.stop)

    def test_registered_messages_rejects_namespace_before_dispatch(self):
        request = body()
        request["_multillm"]["private-unknown"] = True
        result = self.client.post("/v1/messages", json=request,
                                  headers={"Authorization": "Bearer admin-test-key"})
        assert result.status_code == 400
        assert "private-unknown" not in result.get_data(as_text=True)
        self.http.assert_not_called()

    def test_registered_messages_keeps_metadata_out_of_provider_body(self):
        self.http.side_effect = None
        self.http.return_value = json_upstream(CHAT_COMPLETION)
        result = self.client.post("/v1/messages", json=body(),
                                  headers={"Authorization": "Bearer admin-test-key",
                                           "X-MultiLLM-Conversion-Report": "1"})
        assert result.status_code == 200
        sent = json.loads(self.http.call_args.kwargs["data"])
        assert "_multillm" not in sent and "top_k" not in sent
        assert result.headers["X-MultiLLM-Conversion-Fidelity"] == "lossy"
        assert "private" not in str(result.headers)
