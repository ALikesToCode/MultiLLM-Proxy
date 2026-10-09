"""Offline contracts for the operator capability diagnostic."""

import copy
import io
import json
import socket
from unittest.mock import Mock

import pytest

from scripts.model_capability_probe import main
from services.capability_probes import (
    ProbeConfig, ProbeFixtures, ProbeLimits, ProbePrice, ProbeResponse,
    build_plan, receipt_is_current, run_probes, synthetic_image_data_url,
    FlaskGatewayAdapter, WorkerGatewayAdapter,
)

CONFIG = {
    "runtime": "flask", "gateway_base_url": "https://gateway.example.test",
    "provider": "fixture", "model": "fixture-model", "base_url": "https://provider.example.test/v1",
    "credential_revision": "credential-r1", "policy_revision": "policy-r1",
    "provider_header_revision": "headers-r1",
    "headers": {"OpenAI-Beta": "fixture=v1"},
    "capability_config": {"tools": True, "reasoning": {"enabled": False}},
}
FIXTURES = {"synthetic": True, "fixture_version": "fixture-v1", "tool_call": True, "json_schema": True}
PRICE = ProbePrice("0.1", "0.2")


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Network calls are forbidden")
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)


def config(**changes):
    return ProbeConfig.from_dict({**copy.deepcopy(CONFIG), **changes})


def fixtures(**changes):
    return ProbeFixtures.from_dict({**FIXTURES, **changes})


def response(capability, *, usage=True):
    message = {"role": "assistant", "content": '{"status":"ready"}'}
    finish = "stop"
    if capability == "tool_call":
        message = {"role": "assistant", "content": None, "tool_calls": [{
            "id": "call-fixture", "type": "function", "function": {
                "name": "report_status", "arguments": '{"status":"ready"}',
            },
        }]}
        finish = "tool_calls"
    if capability == "vision":
        message["content"] = "red"
    body = {"choices": [{"message": message, "finish_reason": finish}]}
    if usage:
        body["usage"] = {"prompt_tokens": 20, "completion_tokens": 8}
    return ProbeResponse(200, body)


class FakeTransport:
    def __init__(self, replies=None):
        self.calls = []
        self.replies = iter(replies) if replies is not None else None

    def __call__(self, cfg, payload, timeout):
        self.calls.append((cfg, copy.deepcopy(payload), timeout))
        if self.replies is not None:
            item = next(self.replies)
            if isinstance(item, Exception):
                raise item
            return item
        capability = "tool_call" if "tools" in payload else "json_schema" if "response_format" in payload else "vision"
        return response(capability)


def execute(transport, **kwargs):
    return run_probes(config(), fixtures(), price=PRICE, execute=True,
                      allow_generation=True, transport=transport, **kwargs)


def test_default_dry_run_never_dispatches_or_claims_observations():
    send = FakeTransport()
    receipt = run_probes(config(), fixtures(), transport=send)
    assert send.calls == []
    assert receipt["dry_run"] is True
    assert receipt["request_count"] == 0
    assert receipt["cost_usd"] == 0
    assert receipt["observations"] == []
    assert receipt["plan"]["planned_requests"] == 2
    assert receipt["plan"]["reserved_cost_usd"] is None
    assert not receipt_is_current(receipt, config(), fixtures())


@pytest.mark.parametrize("execute_flag,allow", [(True, False), (False, True)])
def test_partial_opt_in_refuses_generation(execute_flag, allow):
    send = FakeTransport()
    with pytest.raises(ValueError):
        run_probes(config(), fixtures(), price=PRICE, execute=execute_flag,
                   allow_generation=allow, transport=send)
    assert send.calls == []


def test_known_price_and_transport_required_before_generation():
    send = FakeTransport()
    with pytest.raises(ValueError):
        run_probes(config(), fixtures(), execute=True, allow_generation=True, transport=send)
    with pytest.raises(ValueError):
        execute(None)
    assert send.calls == []


@pytest.mark.parametrize("limits", [ProbeLimits(max_requests=1), ProbeLimits(max_cost_usd="0.00001")])
def test_entire_plan_fits_caps_before_first_request(limits):
    send = FakeTransport()
    with pytest.raises(ValueError):
        execute(send, limits=limits)
    assert send.calls == []


@pytest.mark.parametrize("kwargs", [
    {"max_requests": 0}, {"max_requests": 33}, {"max_output_tokens": 0},
    {"max_output_tokens": 1025}, {"max_output_tokens": True}, {"max_cost_usd": "NaN"},
    {"max_cost_usd": "Infinity"}, {"max_cost_usd": -1}, {"max_input_tokens": 0},
    {"timeout_seconds": 0}, {"timeout_seconds": 31},
])
def test_invalid_limits_rejected(kwargs):
    with pytest.raises(ValueError):
        build_plan(config(), fixtures(), limits=ProbeLimits(**kwargs), price=PRICE)


@pytest.mark.parametrize("rates", [("NaN", 1), (1, "Infinity"), (-1, 1), (None, 1), (True, 1)])
def test_invalid_or_partial_prices_rejected(rates):
    with pytest.raises(ValueError):
        build_plan(config(), fixtures(), price=ProbePrice(*rates))


def test_success_is_observed_with_bounded_exact_requests_and_receipt():
    send = FakeTransport()
    receipt = execute(send, limits=ProbeLimits(max_output_tokens=16), clock=lambda: "2026-10-09T00:00:00Z")
    assert receipt["request_count"] == 2
    assert [row["status"] for row in receipt["observations"]] == ["supported", "supported"]
    assert receipt["input_tokens"] == 40 and receipt["output_tokens"] == 16
    assert receipt["cost_usd"] == pytest.approx(0.0000072)
    assert receipt["timestamp"] == "2026-10-09T00:00:00Z"
    for cfg, payload, timeout in send.calls:
        assert payload["model"] == "fixture:fixture-model"
        assert payload["max_tokens"] == 16 and payload["stream"] is False
        assert payload["n"] == 1 and timeout == 10
    assert receipt_is_current(receipt, config(), fixtures())


@pytest.mark.parametrize("capability,bad_message", [
    ("tool_call", {"tool_calls": [{"id": "x", "type": "function", "function": {"name": "report_status", "arguments": "not-json"}}]}),
    ("tool_call", {"tool_calls": []}),
    ("tool_call", {"tool_calls": [{"function": {"name": "other", "arguments": '{}'}}]}),
    ("json_schema", {"content": "not-json"}),
    ("json_schema", {"content": '{"wrong":"private-output"}'}),
])
def test_malformed_outputs_are_inconclusive(capability, bad_message):
    fs = fixtures(tool_call=capability == "tool_call", json_schema=capability == "json_schema")
    send = FakeTransport([ProbeResponse(200, {"choices": [{"message": bad_message, "finish_reason": "stop"}]})])
    receipt = run_probes(config(), fs, price=PRICE, execute=True, allow_generation=True, transport=send)
    assert receipt["observations"][0]["status"] == "inconclusive"
    assert "private-output" not in json.dumps(receipt)


@pytest.mark.parametrize("status,body,expected", [
    (400, {"error": {"code": "unsupported_parameter", "param": "tools"}}, "unsupported"),
    (422, {"error": {"code": "unsupported_feature", "param": "response_format"}}, "unsupported"),
    (400, {"error": {"code": "unsupported_parameter", "param": "model"}}, "inconclusive"),
    (401, {"error": {"message": "private-error"}}, "inconclusive"),
    (429, {}, "inconclusive"), (500, {}, "inconclusive"), (200, [], "inconclusive"),
])
def test_only_explicit_feature_rejections_prove_unsupported(status, body, expected):
    cap = "json_schema" if status == 422 else "tool_call"
    fs = fixtures(tool_call=cap == "tool_call", json_schema=cap == "json_schema")
    receipt = run_probes(config(), fs, price=PRICE, execute=True, allow_generation=True,
                         transport=FakeTransport([ProbeResponse(status, body)]))
    assert receipt["observations"][0]["status"] == expected
    assert "private-error" not in json.dumps(receipt)


def test_unknown_usage_stays_unknown_and_reserved_cost_is_bounded():
    receipt = execute(FakeTransport([response("tool_call", usage=False), response("json_schema")]))
    assert receipt["cost_usd"] is None
    assert receipt["input_tokens"] is None and receipt["output_tokens"] is None
    assert 0 < receipt["reserved_cost_usd"] <= 0.01


@pytest.mark.parametrize("usage", [
    {"prompt_tokens": 4097, "completion_tokens": 8},
    {"prompt_tokens": 20, "completion_tokens": 65},
    {"prompt_tokens": True, "completion_tokens": 0},
    {"prompt_tokens": -1, "completion_tokens": 0},
])
def test_provider_budget_violations_or_invalid_usage_stop_further_requests(usage):
    reply = response("tool_call")
    reply.body["usage"] = usage
    send = FakeTransport([reply])
    receipt = execute(send)
    assert receipt["request_count"] == len(send.calls) == 1
    assert receipt["stop_reason"] in {"usage_exceeds_budget", "invalid_usage"}


def test_timeout_is_content_free_and_never_retried():
    send = FakeTransport([TimeoutError("private-url-and-key")])
    receipt = execute(send)
    assert len(send.calls) == 1 and receipt["request_count"] == 1
    assert receipt["observations"][0]["status"] == "inconclusive"
    assert receipt["stop_reason"] == "transport_error"
    assert receipt["cost_usd"] is None
    assert "private-url-and-key" not in json.dumps(receipt)


def test_vision_requires_provided_canonical_synthetic_fixture():
    fs = fixtures(vision={"image_data_url": synthetic_image_data_url("red"), "expected": "red"})
    send = FakeTransport()
    receipt = run_probes(config(), fs, price=PRICE, execute=True, allow_generation=True, transport=send)
    assert receipt["request_count"] == 3
    assert receipt["observations"][-1]["status"] == "supported"
    assert send.calls[-1][1]["messages"][0]["content"][1]["image_url"]["url"].startswith("data:image/png;base64,")
    assert len(execute(FakeTransport())["observations"]) == 2


@pytest.mark.parametrize("changes", [
    {"synthetic": False}, {"prompt": "private prompt"},
    {"vision": {"image_data_url": "https://external.test/image.png", "expected": "red"}},
    {"vision": {"image_data_url": "data:image/png;base64,AAAA", "expected": "red"}},
    {"vision": {"image_data_url": synthetic_image_data_url("red"), "expected": "blue"}},
])
def test_non_synthetic_or_arbitrary_fixtures_are_rejected(changes):
    with pytest.raises(ValueError):
        fixtures(**changes)


@pytest.mark.parametrize("change", [
    {"base_url": "https://other.example.test/v1"}, {"model": "other-model"},
    {"provider": "other"}, {"headers": {"OpenAI-Beta": "fixture=v2"}},
    {"credential_revision": "credential-r2"}, {"policy_revision": "policy-r2"},
    {"provider_header_revision": "headers-r2"}, {"capability_config": {"tools": False}},
    {"runtime": "worker"}, {"gateway_base_url": "https://other-gateway.example.test"},
])
def test_effective_config_changes_make_receipt_stale(change):
    receipt = execute(FakeTransport())
    assert not receipt_is_current(receipt, config(**change), fixtures())


def test_digest_is_canonical_and_snapshots_mutable_inputs():
    raw = copy.deepcopy(CONFIG)
    cfg = ProbeConfig.from_dict(raw)
    assert cfg.configuration_digest == ProbeConfig.from_dict(dict(reversed(list(raw.items())))).configuration_digest
    assert cfg.configuration_digest == config(headers={"openai-beta": "fixture=v1"}).configuration_digest
    raw["capability_config"]["tools"] = False
    raw["headers"]["OpenAI-Beta"] = "changed"
    assert cfg.configuration_digest == config().configuration_digest
    receipt = execute(FakeTransport())
    assert not receipt_is_current(receipt, config(), fixtures(fixture_version="fixture-v2"))
    assert not receipt_is_current(receipt, config(), fixtures(tool_call=False))


@pytest.mark.parametrize("changes", [
    {"base_url": "https://user:secret@provider.test"}, {"base_url": "https://provider.test?key=secret"},
    {"gateway_base_url": "http://public.test"}, {"headers": {"Authorization": "Bearer synthetic-private"}},
    {"headers": {"X-Api-Key": "synthetic-private"}}, {"capability_config": {"api_key": "synthetic-private"}},
    {"model": "auto:intelligence"}, {"provider": "free"}, {"credential_revision": ""},
])
def test_unsafe_or_ambiguous_configuration_rejected(changes):
    with pytest.raises(ValueError):
        config(**changes)


def test_receipt_contains_only_facts_and_digests_no_content_or_configuration():
    receipt = execute(FakeTransport())
    text = json.dumps(receipt)
    for value in (CONFIG["base_url"], CONFIG["gateway_base_url"], "fixture=v1", "report_status", "Return", "arguments", "private-output"):
        assert value not in text
    assert receipt["model"] == CONFIG["model"] and receipt["provider"] == CONFIG["provider"]
    assert len(receipt["configuration_digest"]) == 64
    assert receipt["policy_revision"] == CONFIG["policy_revision"]
    assert receipt["fixture_version"] == "fixture-v1"


def write_inputs(tmp_path):
    cfg_path = tmp_path / "config.json"
    fs_path = tmp_path / "fixtures.json"
    cfg_path.write_text(json.dumps(CONFIG))
    fs_path.write_text(json.dumps(FIXTURES))
    return ["--config", str(cfg_path), "--fixtures", str(fs_path)]


def test_cli_default_dry_run_without_environment_key(tmp_path):
    out, err = io.StringIO(), io.StringIO()
    send = FakeTransport()
    assert main(write_inputs(tmp_path), transport=send, environ={}, stdout=out, stderr=err) == 0
    assert not send.calls and json.loads(out.getvalue())["dry_run"] is True
    assert "Planned requests: 2" in err.getvalue()


def test_cli_prints_count_before_sending_and_uses_only_injected_environment(tmp_path):
    out, err = io.StringIO(), io.StringIO()
    base = FakeTransport()
    def send(cfg, payload, timeout):
        assert "Planned requests: 2" in err.getvalue()
        return base(cfg, payload, timeout)
    args = write_inputs(tmp_path) + ["--execute", "--allow-generation", "--input-usd-per-million", "0.1", "--output-usd-per-million", "0.2"]
    assert main(args, transport=send, environ={"MULTILLM_API_KEY": "synthetic-private"}, stdout=out, stderr=err) == 0
    assert len(base.calls) == 2
    assert "synthetic-private" not in out.getvalue() + err.getvalue()
    assert main(args, transport=send, environ={}, stdout=io.StringIO(), stderr=io.StringIO()) == 2


def test_cli_refuses_without_both_flags_or_price_and_never_writes_existing_output(tmp_path):
    args = write_inputs(tmp_path)
    send = FakeTransport()
    for tail in (["--execute"], ["--allow-generation"], ["--execute", "--allow-generation"]):
        assert main(args + tail, transport=send, environ={}, stdout=io.StringIO(), stderr=io.StringIO()) == 2
    output = tmp_path / "receipt.json"
    output.write_text("existing receipt")
    assert main(args + ["--output", str(output)], transport=send, environ={}, stdout=io.StringIO(), stderr=io.StringIO()) == 1
    assert output.read_text() == "existing receipt" and not send.calls


@pytest.mark.parametrize("adapter_type,runtime", [(FlaskGatewayAdapter, "flask"), (WorkerGatewayAdapter, "worker")])
def test_adapters_use_exact_endpoint_auth_no_redirect_or_retry(monkeypatch, adapter_type, runtime):
    conn = Mock()
    wire = Mock()
    wire.status = 200
    wire.read.return_value = json.dumps(response("json_schema").body).encode()
    conn.getresponse.return_value = wire
    factory = Mock(return_value=conn)
    monkeypatch.setattr("services.capability_probes.http.client.HTTPSConnection", factory)
    adapter = adapter_type("synthetic-private")
    result = adapter(config(runtime=runtime), {"model": "fixture:fixture-model"}, 10)
    assert result.status_code == 200
    args, kwargs = conn.request.call_args
    assert args[:2] == ("POST", "/v1/chat/completions")
    assert kwargs["headers"]["Authorization"] == "Bearer synthetic-private"
    assert kwargs["headers"]["openai-beta"] == "fixture=v1"
    assert conn.request.call_count == 1 and conn.close.call_count == 1
    wire.status = 302
    assert adapter(config(runtime=runtime), {}, 10).status_code == 302
    assert conn.request.call_count == 2


def test_adapter_response_size_is_bounded_and_connections_close(monkeypatch):
    conn = Mock()
    conn.getresponse.return_value.read.return_value = b"x" * 65537
    monkeypatch.setattr("services.capability_probes.http.client.HTTPSConnection", Mock(return_value=conn))
    with pytest.raises(ValueError):
        FlaskGatewayAdapter("synthetic-private")(config(), {}, 10)
    conn.close.assert_called_once()


def test_no_catalog_or_routing_dependencies_are_imported():
    from pathlib import Path
    source = Path("services/capability_probes.py").read_text() + Path("scripts/model_capability_probe.py").read_text()
    for module in ("provider_catalog_service", "provider_capability_discovery", "auto_route_service", "intelligence_store", "app", "config"):
        assert f"from {module} import" not in source
        assert f"from services.{module} import" not in source


@pytest.mark.parametrize("capability", ["tool_call", "json_schema"])
def test_duplicate_json_members_are_malformed_not_supported(capability):
    reply = response(capability)
    text = '{"status":"wrong","status":"ready"}'
    if capability == "tool_call":
        reply.body["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] = text
    else:
        reply.body["choices"][0]["message"]["content"] = text
    fs = fixtures(tool_call=capability == "tool_call", json_schema=capability == "json_schema")
    receipt = run_probes(config(), fs, price=PRICE, execute=True, allow_generation=True,
                         transport=FakeTransport([reply]))
    assert receipt["observations"][0]["status"] == "inconclusive"


@pytest.mark.parametrize("field,value", [("provider", "other"), ("model", "other"), ("runtime", "worker")])
def test_receipt_identifier_mismatch_is_not_current(field, value):
    receipt = execute(FakeTransport())
    receipt[field] = value
    assert not receipt_is_current(receipt, config(), fixtures())


def test_invalid_url_port_is_rejected_before_dispatch():
    with pytest.raises(ValueError):
        config(gateway_base_url="https://gateway.test:invalid")


def test_cli_entrypoint_runs_dry_without_any_key_or_network(tmp_path, monkeypatch, capsys):
    import runpy
    import sys
    monkeypatch.setattr(sys, "argv", ["model_capability_probe.py", *write_inputs(tmp_path)])
    with pytest.raises(SystemExit) as stopped:
        runpy.run_path("scripts/model_capability_probe.py", run_name="__main__")
    assert stopped.value.code == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["request_count"] == 0
    assert "Planned requests: 2" in captured.err


def test_cli_live_inconclusive_returns_one_and_new_output_contains_receipt(tmp_path):
    args = write_inputs(tmp_path) + ["--execute", "--allow-generation", "--input-usd-per-million", "0.1", "--output-usd-per-million", "0.2"]
    out, err = io.StringIO(), io.StringIO()
    send = FakeTransport([TimeoutError("private-exception")])
    assert main(args, transport=send, environ={"MULTILLM_API_KEY": "synthetic-private"}, stdout=out, stderr=err) == 1
    assert "private-exception" not in out.getvalue() + err.getvalue()
    assert json.loads(out.getvalue())["stop_reason"] == "transport_error"
    dest = tmp_path / "new-receipt.json"
    assert main(write_inputs(tmp_path) + ["--output", str(dest)], environ={}, stdout=io.StringIO(), stderr=io.StringIO()) == 0
    assert json.loads(dest.read_text())["dry_run"] is True


def test_cli_existing_output_stops_live_dispatch_and_default_files_are_unchanged(tmp_path):
    args = write_inputs(tmp_path)
    before = {p: p.read_bytes() for p in tmp_path.iterdir()}
    target = tmp_path / "existing.json"
    target.write_text("existing")
    send = FakeTransport()
    args += ["--execute", "--allow-generation", "--input-usd-per-million", "0.1", "--output-usd-per-million", "0.2", "--output", str(target)]
    assert main(args, transport=send, environ={"MULTILLM_API_KEY": "synthetic-private"}, stdout=io.StringIO(), stderr=io.StringIO()) == 1
    assert send.calls == [] and target.read_text() == "existing"
    assert all(p.read_bytes() == data for p, data in before.items())


def test_exact_decimal_cap_and_known_zero_price_are_allowed():
    plan = build_plan(config(), fixtures(), price=PRICE)
    limits = ProbeLimits(max_cost_usd=str(plan["reserved_cost_usd"]))
    assert execute(FakeTransport(), limits=limits)["request_count"] == 2
    receipt = run_probes(config(), fixtures(), price=ProbePrice(0, 0), limits=ProbeLimits(max_cost_usd=0),
                         execute=True, allow_generation=True, transport=FakeTransport())
    assert receipt["cost_usd"] == receipt["reserved_cost_usd"] == 0


@pytest.mark.parametrize("reply", [
    ProbeResponse(200, {"choices": [{"finish_reason": "length", "message": {"content": '{"status":"ready"}'}}]}),
    ProbeResponse(200, {"choices": []}), ProbeResponse(200, {"choices": [42]}),
    ProbeResponse(200, {"choices": [{"message": {"content": '{"status":"ready"}'}, "finish_reason": "stop"}],
                        "usage": {"completion_tokens": 0}}),
])
def test_truncated_malformed_and_partial_usage_are_reported_honestly(reply):
    receipt = run_probes(config(), fixtures(tool_call=False), price=PRICE, execute=True,
                         allow_generation=True, transport=FakeTransport([reply]))
    assert receipt["cost_usd"] is None
    if reply.body.get("usage"):
        assert receipt["input_tokens"] is None and receipt["output_tokens"] == 0
    else:
        assert receipt["observations"][0]["status"] == "inconclusive"


def test_small_input_allowance_refuses_before_any_call():
    send = FakeTransport()
    with pytest.raises(ValueError):
        execute(send, limits=ProbeLimits(max_input_tokens=128))
    assert send.calls == []


@pytest.mark.parametrize("value", ["1e-100000000", "1.00000000000001", "9" * 200])
def test_unbounded_monetary_precision_is_refused_before_dispatch(value):
    send = FakeTransport()
    with pytest.raises(ValueError):
        run_probes(config(), fixtures(), price=ProbePrice(value, 0), limits=ProbeLimits(max_cost_usd=0),
                   execute=True, allow_generation=True, transport=send)
    assert send.calls == []
