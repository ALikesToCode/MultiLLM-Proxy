"""Request-local disclosure guards with synthetic managed transports."""
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from flask import Flask, Response

from services import context_canary as canary

ROUTE = "/v1/chat/completions"


def env(mode="log", **policy):
    return {"CONTEXT_CANARY_MODE": mode, "CONTEXT_CANARY_POLICY_JSON":
            json.dumps(policy or {"routes": [ROUTE]})}


def prepared(mode="log", **options):
    body = {"messages": [{"role": "user", "content": "fixture"}]}
    return canary.prepare_request(body, env(mode), route=ROUTE, **options)


def wire(text):
    return ("data: " + json.dumps({"choices": [{"index": 0, "delta": {"content": text}}]},
                                ensure_ascii=False) + "\n\n").encode()


def contents(data):
    return "".join(json.loads(line[6:])["choices"][0]["delta"].get("content", "")
                   for line in data.decode().splitlines()
                   if line.startswith("data: {") and "choices" in json.loads(line[6:]))


@pytest.fixture(autouse=True)
def isolate(monkeypatch):
    monkeypatch.setattr(canary, "_warned", set())


@pytest.mark.parametrize("settings", [{}, {"CONTEXT_CANARY_MODE": ""},
                         env("off"), env("log", routes=[]), env("log", keys=["other"])])
def test_default_and_no_scope_preserve_identity(settings, caplog):
    body = {"messages": [{"content": "fixture"}]}
    item = canary.prepare_request(body, settings, route=ROUTE)
    assert item.payload is body and item.context is None
    response = Response(b' {"content":"fixture"} ')
    assert canary.finalize_response(response, item.context) is response
    assert not caplog.text


@pytest.mark.parametrize("policy", ["[]", "null", "{", '{"default":true}',
                         '{"routes":"/chat"}', '{"keys":[1]}', '{"routes":[""]}',
                         '{"routes":["/chat"],"unknown":false}'])
def test_strict_policy_warns_once_without_value(policy, caplog):
    settings = {"CONTEXT_CANARY_MODE": "log", "CONTEXT_CANARY_POLICY_JSON": policy}
    for _ in range(2):
        assert canary.resolve_policy(settings, route=ROUTE) is None
    assert len(caplog.records) == 1 and policy not in caplog.text


def test_malformed_mode_and_empty_policy(caplog):
    for _ in range(2):
        assert canary.resolve_policy(env("private-invalid"), route=ROUTE) is None
    assert len(caplog.records) == 1 and "private-invalid" not in caplog.text
    assert canary.resolve_policy({"CONTEXT_CANARY_MODE": "log", "CONTEXT_CANARY_POLICY_JSON": ""}, route=ROUTE) is None


def test_key_opt_in_raw_and_concurrent_markers():
    body = {"messages": [{"role": "user", "content": "fixture"}]}
    a = canary.prepare_request(body, env("log", keys=["key-7"]), key_scope="key-7")
    b = prepared()
    assert len(a.context.marker) == 32 and a.context.marker != b.context.marker
    assert a.payload is not body and len(body["messages"]) == 1
    assert a.payload["messages"][0]["role"] == "system"
    assert "Gateway context canary" in a.payload["messages"][0]["content"]
    assert a.context.marker in a.payload["messages"][0]["content"]
    assert a.context.scanner().feed(b.context.marker, final=True) == b.context.marker
    assert canary.prepare_request(body, env(), route=ROUTE, raw=True).payload is body


def test_all_marker_splits_log_and_bounded_carry(caplog):
    item = prepared(trace_id="trace-7")
    for split in range(33):
        scan = item.context.scanner()
        output = scan.feed("é before " + item.context.marker[:split])
        assert len(scan.carry) < 32
        output += scan.feed(item.context.marker[split:] + " after", final=True)
        assert output == "é before  after"
    assert item.context.marker not in caplog.text
    assert len(caplog.records) == 1
    assert item.context.digest in caplog.text and "trace-7" in caplog.text
    assert "fixture" not in caplog.text


def test_false_prefix_flush_and_repeated_markers():
    item = prepared()
    scan = item.context.scanner()
    assert scan.feed(item.context.marker[:20]) == ""
    assert scan.feed("!", final=True) == item.context.marker[:20] + "!"
    assert item.context.scanner().feed(item.context.marker * 4, final=True) == ""


def test_json_log_and_block_cancel_keep_ambiguous_hold():
    for mode, status in [("log", 200), ("block", 502)]:
        item = prepared(mode)
        cancel, hold = Mock(), SimpleNamespace(ambiguous=False)
        response = Response(json.dumps({"choices": [{"message": {
            "content": "before " + item.context.marker + " after"}}]}), mimetype="application/json")
        result = canary.finalize_response(response, item.context, cancel=cancel, accounting=hold)
        assert result.status_code == status
        assert item.context.marker.encode() not in result.get_data()
        if mode == "block":
            assert result.json["error"]["code"] == "context_canary_leak"
            assert hold.ambiguous and cancel.call_count == 1
        else:
            assert result.json["choices"][0]["message"]["content"] == "before  after"
            assert not hold.ambiguous and not cancel.called
        assert item.context.closed


def test_sse_every_wire_and_event_split_including_utf8():
    for split in range(1, 33):
        item = prepared()
        data = wire("é " + item.context.marker[:split]) + wire(item.context.marker[split:] + " tail") + b"data: [DONE]\n\n"
        for cut in range(1, len(data)):
            parser = canary.CanarySSEParser(item.context)
            result = parser.feed(data[:cut]) + parser.feed(data[cut:], final=True)
            assert contents(result) == "é  tail"
            assert item.context.marker.encode() not in result


def test_terminal_false_prefix_is_flushed_before_done():
    item = prepared()
    parser = canary.CanarySSEParser(item.context)
    result = parser.feed(wire(item.context.marker[:9]) + b"data: [DONE]\n\n", final=True)
    assert contents(result) == item.context.marker[:9]
    assert result.endswith(b"data: [DONE]\n\n")


def test_stream_precommit_and_late_protocol_error_close_upstream():
    for late in [False, True]:
        item = prepared("block")
        cancel, hold = Mock(), SimpleNamespace(ambiguous=False)
        chunks = ([wire("safe first")] if late else []) + [wire(item.context.marker)]
        response = Response(iter(chunks), mimetype="text/event-stream")
        result = canary.finalize_response(response, item.context, cancel=cancel, accounting=hold)
        if late:
            assert result.status_code == 200
            data = b"".join(result.response)
            assert b"safe first" in data and b'"code":"context_canary_leak"' in data
            assert b"[DONE]" not in data
        else:
            assert result.status_code == 502
            assert result.json["error"]["code"] == "context_canary_leak"
        assert hold.ambiguous and cancel.call_count == 1 and item.context.closed


def test_client_close_and_parser_bounds():
    item = prepared()
    cancel, hold = Mock(), SimpleNamespace(ambiguous=False)
    result = canary.finalize_response(Response(iter([wire("safe"), wire("next")]),
        mimetype="text/event-stream"), item.context, cancel=cancel, accounting=hold)
    result.close()
    assert item.context.closed and cancel.call_count == 1 and hold.ambiguous
    with pytest.raises(canary.ContextCanaryError):
        canary.CanarySSEParser(prepared().context).feed(b"data: " + b"x" * 65537)


def test_flask_managed_hook_contract_with_fake_dispatch():
    app = Flask(__name__)
    @app.post(ROUTE)
    def dispatch():
        item = prepared("block")
        return canary.finalize_response(Response(json.dumps({"content": item.context.marker}),
            mimetype="application/json"), item.context)
    reply = app.test_client().post(ROUTE)
    assert reply.status_code == 502 and reply.json["error"]["code"] == "context_canary_leak"


def test_terminal_delta_finishes_marker_before_flushing_prefix():
    item = prepared()
    end = ("data: " + json.dumps({"choices": [{"index": 0, "delta": {
        "content": item.context.marker[10:] + " tail"}, "finish_reason": "stop"}]}) + "\n\n").encode()
    data = canary.CanarySSEParser(item.context).feed(wire("head " + item.context.marker[:10]) + end +
        b"data: [DONE]\n\n", final=True)
    assert contents(data) == "head  tail" and item.context.marker.encode() not in data


@pytest.mark.parametrize("protocol,body,field", [("messages", {"system": "original", "messages": []}, "system"),
                         ("responses", {"instructions": "original", "input": "fixture"}, "instructions")])
def test_protocol_annotations_preserve_supplied_instructions(protocol, body, field):
    item = canary.prepare_request(body, env(), route=ROUTE, protocol=protocol)
    assert item.payload[field].endswith("\noriginal") and body[field] == "original"


def test_interleaved_choices_keep_independent_prefixes():
    item = prepared()
    def choice(index, text):
        return ("data: " + json.dumps({"choices": [{"index": index, "delta": {"content": text}}]}) + "\n\n").encode()
    data = choice(0, "head " + item.context.marker[:12]) + choice(1, "other choice") + choice(0, item.context.marker[12:] + " tail") + b"data: [DONE]\n\n"
    result = canary.CanarySSEParser(item.context).feed(data, final=True)
    values = [json.loads(line[6:])["choices"][0] for line in result.decode().splitlines() if line.startswith("data: {")]
    assert "".join(value["delta"]["content"] for value in values if value["index"] == 0) == "head  tail"
    assert "".join(value["delta"]["content"] for value in values if value["index"] == 1) == "other choice"


def test_sse_comments_and_labels_cannot_disclose_marker():
    item = prepared()
    data = ("event: " + item.context.marker + "\n: " + item.context.marker + "\n").encode() + wire("safe")
    result = canary.CanarySSEParser(item.context).feed(data, final=True)
    assert item.context.marker.encode() not in result and contents(result) == "safe"


def test_done_comments_are_scanned_and_other_choice_finish_keeps_carry():
    item = prepared()
    data = (": " + item.context.marker + "\ndata: [DONE]\n\n").encode()
    assert item.context.marker.encode() not in canary.CanarySSEParser(item.context).feed(data, final=True)
    item = prepared()
    events = [{"choices": [{"index": 1, "delta": {"content": item.context.marker[:12]}}]},
              {"choices": [{"index": 0, "delta": {"content": "safe"}, "finish_reason": "stop"}]},
              {"choices": [{"index": 1, "delta": {"content": item.context.marker[12:]}, "finish_reason": "stop"}]}]
    data = b"".join(("data: " + json.dumps(event) + "\n\n").encode() for event in events) + b"data: [DONE]\n\n"
    result = canary.CanarySSEParser(item.context).feed(data, final=True)
    values = [json.loads(line[6:])["choices"][0] for line in result.decode().splitlines() if line.startswith("data: {")]
    assert "".join(value["delta"]["content"] for value in values if value["index"] == 1) == ""
