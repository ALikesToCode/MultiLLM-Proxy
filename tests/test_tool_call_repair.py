"""Independent corpus and schema acceptance tests for deterministic tool repair."""

import copy
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from services.tool_call_repair import repair_tool_calls, validate_arguments
from services.tool_argument_parser import MAX_BYTES, tolerant_loads
from services.tool_repair_runtime import repair_completion, repair_mode
from services.tool_repair_stream import ToolCallBuffer, repair_sse

CASES = json.loads((Path(__file__).parent / "fixtures/tool_call_repair_cases.json").read_text())
TOOLS = CASES[0]["tools"]


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_corpus(case):
    original = copy.deepcopy(case["message"])
    with patch("services.tool_call_repair.safe_tool_id", return_value="call_fixture") as make_id:
        message, report = repair_tool_calls(case["message"], case["tools"], tool_choice=case["tool_choice"])
    assert message == case["expected_message"]
    assert report == case["expected_report"]
    assert case["message"] == original
    if any(error.get("reason") == "extraction_rejected" for error in report["errors"]):
        assert message is case["message"]
        make_id.assert_not_called()


@pytest.mark.parametrize("schema,value,valid", [
    ({"type":"integer"}, True, False), ({"type":"integer"}, 2.0, True),
    ({"type":["string","null"]}, None, True), ({"type":"string","nullable":True}, None, True),
    ({"enum":[1]}, True, False), ({"const":True}, 1, False),
    ({"type":"array","items":{"type":"integer"},"minItems":1,"maxItems":2}, [], False),
    ({"type":"array","items":{"type":"integer"},"minItems":1,"maxItems":2}, [1,2], True),
    ({"type":"array","items":{"type":"integer"}}, ["1"], False),
    ({"minimum":1,"maximum":2}, 3, False), ({"minimum":1,"maximum":2}, 1.5, True),
    ({"minLength":2,"maxLength":3}, "a", False), ({"maxLength":1}, "aa", False),
    ({"type":"object","additionalProperties":False}, {"extra":1}, False),
    ({"anyOf":[{"type":"integer"},{"type":"null"}]}, None, True),
    ({"oneOf":[{"type":"integer"},{"type":"number"}]}, 1, False),
    ({"oneOf":[{"type":"integer"},{"type":"string"}]}, "a", True),
    ({"$ref":"https://never-fetch.example/schema","pattern":"^no$","unknown":True}, "yes", True),
    ({"type":"number"}, float("inf"), False),
    ({"type":"integer"}, 10**400, True),
    ({"nullable":True}, "unconstrained", True),
    ({"type":[{"unsupported":True},"string"]}, "a", True),
])
def test_validator(schema, value, valid):
    assert (not validate_arguments(schema, value)) is valid


def test_off_returns_original_and_zero_report():
    for case in CASES:
        result, report = repair_tool_calls(case["message"], case["tools"], mode="off")
        assert result is case["message"]
        assert json.dumps(result) == json.dumps(case["message"])
        assert all(report[k] == 0 for k in ("checked","repaired","invalid","extracted"))


def test_bounds_and_ambiguous_coercion_fail_closed():
    message = copy.deepcopy(CASES[0]["message"])
    message["tool_calls"][0]["function"]["arguments"] = '"' + "a" * MAX_BYTES + '"'
    repaired, report = repair_tool_calls(message, TOOLS)
    assert repaired == message and report["invalid"] == 1
    assert validate_arguments({}, [[[[1]]]] * 5000)
    tools = copy.deepcopy(TOOLS)
    tools[0]["function"]["parameters"]["properties"]["q"] = {"type":["integer","array"],"items":{"type":"integer"}}
    message["tool_calls"][0]["function"]["arguments"] = '{"q":"5"}'
    assert repair_tool_calls(message, tools)[1]["invalid"] == 1
    with pytest.raises(ValueError):
        tolerant_loads("[" * 34 + "1" + "]" * 34)


def test_mode_override_and_invalid_default(monkeypatch):
    monkeypatch.setenv("TOOL_CALL_REPAIR_DEFAULT", "full")
    assert repair_mode() == "full"
    assert repair_mode({"x-multillm-tool-repair":"OFF"}) == "off"
    assert repair_mode({"X-MultiLLM-Tool-Repair":"wrong"}) == "full"
    assert repair_mode(config={"TOOL_CALL_REPAIR_DEFAULT":"wrong"}) == "repair"


def completion(message, tokens=3):
    return {"choices":[{"index":0,"message":message,"finish_reason":"tool_calls"}],
            "usage":{"prompt_tokens":tokens,"completion_tokens":tokens,"total_tokens":tokens*2}}


def test_full_reasks_once_accounts_invalid_reply_and_keeps_original():
    invalid = next(case for case in CASES if case["name"] == "missing_required")["message"]
    sent = []
    def reask(body):
        sent.append(body)
        return completion(invalid)
    original = completion(invalid)
    result, report = repair_completion(original, {"tools":TOOLS,"messages":[{"role":"user","content":"do it"}]}, mode="full", reask=reask)
    assert len(sent) == 1 and report["reasked"] == 1 and report["invalid"] == 1
    assert result["choices"] == original["choices"]
    assert result["usage"]["total_tokens"] == 12
    assert sent[0]["messages"][-2] == invalid
    assert "lookup" in sent[0]["messages"][-1]["content"] and "required" in sent[0]["messages"][-1]["content"]


def test_full_failure_is_nonfatal():
    invalid = next(case for case in CASES if case["name"] == "missing_required")["message"]
    def fail(body):
        raise RuntimeError("private-canary")
    original = completion(invalid)
    result, report = repair_completion(original, {"tools":TOOLS}, mode="full", reask=fail)
    assert result == original and report["invalid"] == report["reasked"] == 1


def test_full_multiple_choices_share_one_reask_and_preserve_valid_calls():
    invalid = next(case for case in CASES if case["name"] == "missing_required")["message"]
    valid = next(case for case in CASES if case["name"] == "valid_is_identical")["message"]
    original = completion(invalid)
    original["choices"].append({"index":1,"message":valid,"finish_reason":"tool_calls"})
    sent = []
    def reask(body):
        sent.append(body)
        return completion({"role":"assistant","tool_calls":valid["tool_calls"] * 2})
    result, report = repair_completion(original, {"tools":TOOLS,"n":2}, mode="full", reask=reask)
    assert len(sent) == 1 and sent[0]["n"] == 1
    assert report["checked"] == 2 and report["invalid"] == 0 and report["reasked"] == 1
    assert result["choices"][1] == original["choices"][1]
    assert result["choices"][0]["message"]["tool_calls"] == valid["tool_calls"]


@pytest.mark.parametrize("content", [
    '<tool_call>lookup\n{"q":"a"}</tool_call>',
    '<｜tool▁calls▁begin｜><｜tool▁call▁begin｜>function<｜tool▁sep｜>lookup\n```json\n{"q":"a"}\n```<｜tool▁call▁end｜><｜tool▁calls▁end｜>',
])
def test_native_glm_and_deepseek_text_formats(content):
    message, report = repair_tool_calls({"role":"assistant","content":content}, TOOLS)
    assert message["content"] is None
    assert message["tool_calls"][0]["function"] == {"name":"lookup","arguments":'{"q":"a"}'}
    assert report["extracted"] == report["checked"] == 1 and report["invalid"] == 0


def test_stream_request_never_extracts_or_reasks_even_with_json_response():
    original = completion({"role":"assistant","content":'<tool_call>{"name":"lookup","arguments":{}}</tool_call>'})
    with patch("builtins.print") as reask:
        result, report = repair_completion(original, {"tools":TOOLS,"stream":True}, mode="full", reask=reask)
    assert result == original and report["extracted"] == report["reasked"] == 0
    reask.assert_not_called()


def test_skipped_reask_is_not_counted():
    from services.tool_repair_runtime import SKIP_REASK
    invalid = next(case for case in CASES if case["name"] == "missing_required")["message"]
    result, report = repair_completion(completion(invalid), {"tools":TOOLS}, mode="full", reask=lambda _: SKIP_REASK)
    assert report["invalid"] == 1 and report["reasked"] == 0


@pytest.mark.parametrize("reply", [{"choices": None}, {"choices": "x"}, {"choices": [None]}, {"choices": [{}]}])
def test_malformed_reask_keeps_original(reply):
    invalid = next(case for case in CASES if case["name"] == "missing_required")["message"]
    original = completion(invalid)
    result, report = repair_completion(original, {"tools":TOOLS}, mode="full", reask=lambda _: reply)
    assert result["choices"] == original["choices"] and report["invalid"] == report["reasked"] == 1


def test_reask_cannot_substitute_another_declared_function():
    invalid = next(case for case in CASES if case["name"] == "missing_required")["message"]
    tools = [*TOOLS, {"type":"function","function":{"name":"other","parameters":{"type":"object"}}}]
    reply = completion({"role":"assistant","tool_calls":[{"id":"new","type":"function","function":{"name":"other","arguments":"{}"}}]})
    original = completion(invalid)
    result, report = repair_completion(original, {"tools":tools}, mode="full", reask=lambda _: reply)
    assert result["choices"] == original["choices"] and report["invalid"] == 1


def test_bound_errors_are_safe_for_invalid_unicode_and_large_values():
    assert validate_arguments({}, "\ud800")
    assert validate_arguments({}, "a"*(MAX_BYTES+1))


def test_stream_content_is_immediate_tool_calls_precede_finish_and_no_extraction():
    buffer = ToolCallBuffer(TOOLS)
    def chunk(delta, finish=None):
        return {"choices":[{"index":0,"delta":delta,"finish_reason":finish}]}
    content = '<tool_call>{"name":"lookup","arguments":{}}</tool_call>'
    first = chunk({"content":content,"tool_calls":[{"index":0,"id":"call_a","type":"function","function":{"name":"LOOKUP","arguments":"{q:"}}]})
    output = list(buffer.process(first))
    assert output[0]["choices"][0]["delta"] == {"content":content}
    assert list(buffer.process(chunk({"tool_calls":[{"index":0,"function":{"arguments":"'a',}"}}]}))) == []
    output = list(buffer.process(chunk({}, "tool_calls")))
    assert output[0]["choices"][0]["delta"]["tool_calls"][0]["function"] == {"name":"lookup","arguments":'{"q":"a"}'}
    assert output[1]["choices"][0]["finish_reason"] == "tool_calls"
    assert buffer.report["repaired"] == 1 and buffer.report["extracted"] == 0


def test_sse_heartbeats_usage_done_eof_and_off():
    call = {'choices':[{'index':0,'delta':{'tool_calls':[{'index':2,'id':'a','function':{'name':'lookup','arguments':'{q:"a"}'}}]}}]}
    frames = [b": keep-alive\n\n", ("data: " + json.dumps(call) + "\n\n").encode(), b"data: [DONE]\n\n"]
    output = list(repair_sse(iter(frames), ToolCallBuffer(TOOLS)))
    assert output[0] == frames[0] and output[-1] == frames[-1]
    assert '"index":2' in output[-2] and 'lookup' in output[-2]
    assert b"".join(repair_sse(iter(frames), ToolCallBuffer(TOOLS, mode="off"))) == b"".join(frames)
    assert len(list(repair_sse(iter(frames[:-1]), ToolCallBuffer(TOOLS)))) == 2


def test_stream_limits_keep_all_original_fragments():
    buffer = ToolCallBuffer(TOOLS)
    first = {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"a","function":{"name":"lookup","arguments":"{"}}]}}]}
    assert list(buffer.process(first)) == []
    oversized = {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"x"*(MAX_BYTES+1)}}]}}]}
    output = list(buffer.process(oversized))
    assert output[-1] is oversized and buffer.disabled and len(output) == 2


def test_deep_stream_metadata_falls_back_without_losing_fragments():
    metadata = {}
    for _ in range(64):
        metadata = {"nested": metadata}
    payload = {"choices":[{"delta":{"tool_calls":[{"index":0,"extra_content":metadata,"function":{"name":"lookup","arguments":"{}"}}]}}]}
    buffer = ToolCallBuffer(TOOLS)
    assert list(buffer.process(payload)) == [payload]
    assert buffer.disabled


def test_json_recursion_limit_keeps_raw_sse_frame():
    frame = b'data: ' + b'[' * 2000 + b'0' + b']' * 2000 + b'\n\n'
    assert list(repair_sse(iter([frame]), ToolCallBuffer(TOOLS))) == [frame]
