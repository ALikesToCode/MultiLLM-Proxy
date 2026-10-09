"""Content-free exports use fake collectors and independent delivery queues."""
import json
import threading
from types import SimpleNamespace

import pytest

from services import observability_adapters as exports, telemetry_export


def settings(*types):
    return {"OBSERVABILITY_EXPORTERS_JSON": json.dumps([
        {"type": kind, "endpoint": f"https://{kind}.example/ingest",
         "allowed_origins": [f"https://{kind}.example"], "credential_env": f"TEST_{kind.upper()}_EXPORT_CREDENTIAL"}
        for kind in types]), "TEST_LANGFUSE_EXPORT_CREDENTIAL": "public:synthetic-secret", "TEST_HELICONE_EXPORT_CREDENTIAL": "synthetic-secret"}


def record(**extra):
    return {"request_id": "req-1", "trace_id": "a" * 32, "principal": "private-user",
            "selected_model": "openai:test", "kind": "chat", "status": 200,
            "start_ns": 1_000_000_000, "end_ns": 1_010_000_000, "latency_ms": 10,
            "input_tokens": 0, "output_tokens": None, "cost_usd": None, "cost_basis": None,
            "prompt": "private-prompt", "response": "private-output", "tools": ["private-tool"],
            "headers": {"Authorization": "private-key"}, "key_prefix": "private-prefix", **extra}


def collector(calls, status=200):
    def post(url, **kwargs):
        calls.append((url, kwargs))
        return SimpleNamespace(status_code=status)
    return post


@pytest.mark.parametrize("raw", [None, "", "[]"])
def test_default_off_does_nothing(raw):
    env = {} if raw is None else {"OBSERVABILITY_EXPORTERS_JSON": raw}
    calls = []
    exporter = exports.ObservabilityExporter(env, transport=collector(calls), auto_start=False)
    assert not exporter.submit(record())
    assert exporter.export_once() == 0 and calls == []
    assert exporter.status()["accepted"] == 0


@pytest.mark.parametrize("raw", ["private-invalid", "{}", '[{"type":"unknown"}]',
    '[{"type":"helicone","endpoint":"http://collector.example","allowed_origins":["http://collector.example"],"credential_env":"TEST_KEY"}]'])
def test_malformed_disables_with_one_content_free_warning(raw, caplog, monkeypatch):
    monkeypatch.setattr(exports, "_warned", False)
    exporter = exports.ObservabilityExporter({"OBSERVABILITY_EXPORTERS_JSON": raw}, auto_start=False)
    assert not exporter.submit(record()) and not exporter.submit(record())
    assert len(caplog.records) == 1 and raw not in caplog.text


@pytest.mark.parametrize("change", [
    {"endpoint": "https://other.example/log"}, {"endpoint": "https://secret@helicone.example/log"},
    {"endpoint": "https://helicone.example/log?key=secret"}, {"endpoint": "https://helicone.example/log#secret"},
    {"credential_env": "secret-value!"}, {"credential_env": "GEMINI_API_KEY"}, {"api_key": "secret-value"},
    {"allowed_origins": ["https://helicone.example/path"]},
])
def test_destinations_and_credential_references_are_strict(change):
    env = settings("helicone")
    config = json.loads(env["OBSERVABILITY_EXPORTERS_JSON"])
    config[0].update(change)
    env["OBSERVABILITY_EXPORTERS_JSON"] = json.dumps(config)
    assert not exports.ObservabilityExporter(env, auto_start=False).submit(record())


def test_adapter_schema_nulls_content_and_safe_status():
    calls = []
    exporter = exports.ObservabilityExporter(settings("langfuse", "helicone"), transport=collector(calls), auto_start=False)
    assert exporter.submit(record()) and calls == []
    assert exporter.status()["accepted"] == 1
    assert exporter.status()["exporters"][0]["acknowledged"] == 0
    assert exporter.export_once() == 1
    langfuse = calls[0][1]["json"]["batch"][0]
    assert langfuse["type"] == "generation-create"
    assert langfuse["body"]["usage"] == {"input": 0, "output": None, "unit": "TOKENS"}
    observation = langfuse["body"]["metadata"]
    assert observation["cost"] == {"usd": None, "basis": None}
    assert observation["model"] == "openai:test" and observation["latency_ms"] == 10
    assert observation["principal"].startswith("principal:")
    helicone = calls[1][1]["json"]
    assert helicone["providerResponse"]["json"]["usage"]["completion_tokens"] is None
    assert helicone["providerRequest"]["json"] == {"model": "openai:test"}
    assert helicone["timing"] == {"startTime": {"seconds": 1, "milliseconds": 0}, "endTime": {"seconds": 1, "milliseconds": 10}}
    for _, kwargs in calls:
        assert kwargs["timeout"] == 2 and kwargs["allow_redirects"] is False
        text = json.dumps(kwargs["json"])
        for forbidden in ["private-user", "private-prompt", "private-output", "private-tool", "private-key", "private-prefix"]:
            assert forbidden not in text
    status = exporter.status()
    assert "synthetic-secret" not in json.dumps(status)
    assert all(item["acknowledged"] == 1 and item["delivery_status"] == "acknowledged" for item in status["exporters"])


def test_queue_overflow_batch_bound_dedup_and_kind_cost_isolation():
    calls = []
    exporter = exports.ObservabilityExporter(settings("langfuse"), transport=collector(calls), auto_start=False)
    for index in range(1000):
        assert exporter.submit(record(request_id=f"req-{index}"))
    assert not exporter.submit(record(request_id="overflow"))
    assert exporter.status()["dropped"] == 1 and exporter.status()["queued"] == 1000
    assert not exporter.submit(record())
    assert exporter.export_once() == 50 and len(calls[0][1]["json"]["batch"]) == 50
    for kind, cost in [("shadow", .1), ("canary", .2)]:
        assert exporter.submit(record(request_id="same", kind=kind, cost_usd=cost, cost_basis="usage"))
    while exporter.export_once():
        pass
    observations = [event["body"]["metadata"] for _, args in calls for event in args["json"]["batch"]]
    assert [(item["kind"], item["cost"]["usd"]) for item in observations[-2:]] == [("shadow", .1), ("canary", .2)]


def test_bounded_retries_independent_failure_no_secret_logs(caplog):
    calls = []
    def post(url, **kwargs):
        calls.append((url, kwargs))
        if "langfuse" in url:
            raise RuntimeError("synthetic-secret private-prompt")
        return SimpleNamespace(status_code=200)
    exporter = exports.ObservabilityExporter(settings("langfuse", "helicone"), transport=post, auto_start=False)
    exporter.submit(record())
    assert exporter.export_once() == 1
    assert len(calls) == 4
    assert exporter.status()["exporters"][0]["failed"] == 1
    assert exporter.status()["exporters"][1]["acknowledged"] == 1
    assert "synthetic-secret" not in caplog.text and "private-prompt" not in caplog.text
    assert len({args["json"]["batch"][0]["id"] for url, args in calls if "langfuse" in url}) == 1


@pytest.mark.parametrize("status", [301, 400, 401, 207])
def test_rejected_or_partial_receipts_are_not_acknowledged(status):
    calls = []
    exporter = exports.ObservabilityExporter(settings("langfuse"), transport=collector(calls, status), auto_start=False)
    exporter.submit(record()); exporter.export_once()
    assert len(calls) == 1 and exporter.status()["exporters"][0]["failed"] == 1


def test_missing_credentials_are_failures_without_transport():
    env = settings("helicone"); env["TEST_HELICONE_EXPORT_CREDENTIAL"] = ""
    calls = []
    exporter = exports.ObservabilityExporter(env, transport=collector(calls), auto_start=False)
    exporter.submit(record()); exporter.export_once()
    assert calls == [] and exporter.status()["exporters"][0]["delivery_status"] == "credential_unavailable"


def test_background_delivery_never_waits_in_submit():
    entered, release = threading.Event(), threading.Event()
    def slow(*args, **kwargs):
        entered.set(); release.wait(5)
        return SimpleNamespace(status_code=200)
    exporter = exports.ObservabilityExporter(settings("helicone"), transport=slow)
    try:
        assert exporter.submit(record())
        assert entered.wait(2)
        assert exporter.submit(record(request_id="req-2"))
        assert exporter.status()["accepted"] == 2
    finally:
        release.set()


@pytest.mark.parametrize("enabled", [False, True])
def test_otlp_payload_and_return_contract_are_unchanged(monkeypatch, enabled):
    calls = []
    env = settings("helicone") if enabled else {}
    external = exports.ObservabilityExporter(env, transport=collector([]), auto_start=False)
    monkeypatch.setattr(telemetry_export, "OBSERVABILITY_EXPORTER", external)
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://otlp.example")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_HEADERS", "")
    monkeypatch.setenv("OTEL_SERVICE_NAME", "multillm-proxy")
    monkeypatch.setattr(telemetry_export.requests, "post", collector(calls))
    monkeypatch.setattr(telemetry_export.secrets, "token_hex", lambda length: "b" * (length * 2))
    monkeypatch.setattr(telemetry_export.time, "time_ns", lambda: 2_000_000_000)
    exporter = telemetry_export.TelemetryExporter()
    monkeypatch.setattr(exporter, "_run", lambda: None)
    event = record()
    expected_span = telemetry_export.span(event)
    expected_metrics = telemetry_export.metrics([event])
    assert exporter.submit(event)
    assert exporter.export_once() == 1
    assert calls[0][1]["json"]["resourceSpans"][0]["scopeSpans"][0]["spans"] == [expected_span]
    assert calls[1][1]["json"]["resourceMetrics"][0]["scopeMetrics"][0]["metrics"] == expected_metrics
    assert external.status()["accepted"] == int(enabled)


def test_flask_exports_without_otlp_and_once_per_finalization(monkeypatch):
    external = exports.ObservabilityExporter(settings("helicone"), auto_start=False)
    monkeypatch.setattr(telemetry_export, "OBSERVABILITY_EXPORTER", external)
    for name in ["OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"]:
        monkeypatch.setenv(name, "")
    exporter = telemetry_export.TelemetryExporter()
    assert not exporter.submit(record())  # Existing return value describes the OTLP queue.
    exporter.submit(record())
    assert external.status()["accepted"] == 1 and not exporter._queue


def test_partial_langfuse_receipt_only_acknowledges_matching_successes():
    def post(url, **kwargs):
        first, second = kwargs["json"]["batch"]
        return SimpleNamespace(status_code=207, content=json.dumps({
            "successes": [{"id": first["id"]}, {"id": "foreign"}], "errors": [{"id": second["id"]}]}).encode())
    exporter = exports.ObservabilityExporter(settings("langfuse"), transport=post, auto_start=False)
    exporter.submit(record()); exporter.submit(record(request_id="req-2"))
    exporter.export_once()
    status = exporter.status()["exporters"][0]
    assert (status["acknowledged"], status["failed"], status["attempts"], status["delivery_status"]) == (1, 1, 1, "partial")


@pytest.mark.parametrize("value", [True, -1, float("nan"), float("inf"), "2", {}])
def test_untrusted_numeric_and_nested_metadata_are_not_exported(value):
    item = exports.observation(record(input_tokens=value, cost_usd=value, error={"message": "private"}, provenance=[{}, "private", "provider"]), "flask")
    assert item["usage"]["input_tokens"] is None and item["cost"]["usd"] is None
    assert item["error"] is None and item["provenance"] == ["provider"]


def test_finalized_accounting_response_exports_once_with_exact_bytes(monkeypatch):
    from flask import Flask, Response, g
    from services import request_accounting as accounting
    external = exports.ObservabilityExporter(settings("helicone"), auto_start=False)
    monkeypatch.setattr(accounting.telemetry_export, "OBSERVABILITY_EXPORTER", external)
    monkeypatch.setattr(accounting.usage_ledger.LEDGER, "record", lambda row: True)
    monkeypatch.setattr(accounting.BudgetService, "settle", lambda *args, **kwargs: None)
    monkeypatch.setattr(accounting.BudgetService, "record_cost", lambda row: None)
    monkeypatch.setenv("USAGE_RESERVATIONS_ENABLED", "false")
    monkeypatch.setenv("PROMPT_CACHE_USAGE_BUCKETS_ENABLED", "false")
    monkeypatch.setenv("MODEL_PRICING_USD_PER_MILLION", "{}")
    for name in ["OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"]:
        monkeypatch.setenv(name, "")
    app = Flask(__name__)
    raw = b'{"choices":[{"message":{"content":"private-output"}}]}'
    @app.post("/v1/chat/completions")
    def complete():
        context = accounting.UsageContext(kind="chat", models=["openai:test"], provider="openai",
            user={"username": "private-user"}, started=accounting.time.perf_counter(), start_ns=1,
            input_tokens=1, output_tokens=1, path="/v1/chat/completions", trace=("a" * 32, None), request_id="req-finalized")
        g.usage_context = context
        g.request_id = "req-finalized"
        g.multillm_model = "openai:test"
        response = accounting.finish(Response(raw, headers={"X-Request-ID": "unchanged"}))
        return accounting.finish(response)
    response = app.test_client().post("/v1/chat/completions")
    assert response.data == raw and response.headers["X-Request-ID"] == "unchanged"
    assert external.status()["accepted"] == 1
