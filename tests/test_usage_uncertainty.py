"""Partial observations remain distinct from measured zero through accounting."""

import json
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import requests
from flask import Flask, g

from services import request_accounting as accounting, usage_ledger, usage_store
from services.budget_service import BudgetService
from services.cost_service import CostService
from tests.unified_api_test_case import UnifiedApiTestCase


@pytest.fixture(autouse=True)
def accounting_clock(monkeypatch):
    monkeypatch.setattr(accounting, "time", SimpleNamespace(
        perf_counter=lambda: 1000.0, time_ns=lambda: 1_000_000))


@pytest.fixture
def pricing(monkeypatch):
    monkeypatch.setenv(CostService.ENV_NAME, json.dumps({
        "opencode:*": {"input": 2, "output": 8},
        "flat": {"request": 0.04},
        "free": {"input": 0, "output": 0},
    }))


@pytest.mark.parametrize("usage,expected", [
    ({"prompt_tokens": 9}, (9, None)),
    ({"output_tokens": 4}, (None, 4)),
    ({"input_tokens": 0, "output_tokens": 0}, (0, 0)),
    ({"input_tokens": 3, "output_tokens": None}, (3, None)),
    ({"input_tokens": True, "output_tokens": 2}, (None, 2)),
    ({"input_tokens": -1, "output_tokens": 2}, (None, 2)),
    ({"input_tokens": "3", "output_tokens": 2}, (None, 2)),
    ({"total_tokens": 10}, (None, None)),
])
def test_json_components_are_independent(usage, expected):
    observed = accounting._usage_from({"usage": usage})
    assert (observed.input_tokens, observed.output_tokens) == expected
    assert observed.basis == ("unknown" if expected == (None, None) else "provider")


def test_nested_responses_and_anthropic_start_usage():
    for body in ({"response": {"usage": {"input_tokens": 8}}},
                 {"message": {"usage": {"input_tokens": 8}}}):
        observed = accounting._usage_from(body)
        assert (observed.input_tokens, observed.output_tokens) == (8, None)


@pytest.mark.parametrize("tokens,expected", [
    ((None, 4), None), ((9, None), None), ((None, None), None),
    ((0, 0), 0.0), ((9, 4), 0.00005),
])
def test_optional_cost_components(pricing, tokens, expected):
    assert CostService.estimate("opencode:test", *tokens) == expected


def test_only_required_priced_components_are_needed(pricing):
    assert CostService.estimate("flat", None, None) == 0.04
    assert CostService.estimate("free", None, None) == 0.0
    assert CostService.estimate("unknown", 0, 0) is None


def test_partial_estimates_keep_provenance():
    from services.usage_types import UsageObservation

    measured = UsageObservation.from_body({"usage": {"input_tokens": 0}})
    estimated = measured.with_estimates(99, 12)
    assert (estimated.input_tokens, estimated.output_tokens) == (0, 12)
    assert estimated.basis == "estimated"
    assert estimated.provenance == ("provider", "request_estimate")
    assert measured.basis == "provider" and measured.output_tokens is None
    assert UsageObservation().basis == "unknown"
    assert measured.with_estimates(None, None) == measured
    assert estimated.storage_basis(0.001) == "estimate"
    assert estimated.storage_basis(None) is None


def test_split_sse_merges_last_reported_component_without_inventing_zero():
    events = (b'data: {"message":{"usage":{"input_tokens":8}}}\n\n'
              b'data: {"usage":{"output_tokens":4}}\n\n'
              b'data: {"usage":{"output_tokens":0}}\n\n'
              b'data: {"usage":{"output_tokens":null}}\n\ndata: [DONE]\n\n')
    observed = accounting._sse_usage(events)
    assert (observed.input_tokens, observed.output_tokens, observed.basis) == (8, 0, "provider")
    partial = accounting._json_tail_usage(b'{"usage":{"input_tokens":0}}')
    assert (partial.input_tokens, partial.output_tokens) == (0, None)


def context():
    return accounting.UsageContext(kind="chat", models=["opencode:test"], provider=None,
                                   user={"username": "reader"}, started=accounting.time.perf_counter(),
                                   start_ns=1, input_tokens=100, output_tokens=200,
                                   path="/v1/chat/completions", trace=(None, None))


def test_partial_row_is_unknown_and_full_row_retains_legacy_basis(pricing):
    partial = accounting._row(context(), 200, accounting._usage_from({"usage": {"input_tokens": 0}}), None)
    assert (partial["input_tokens"], partial["output_tokens"], partial["cost_usd"], partial["cost_basis"]) == (0, None, None, None)
    full = accounting._row(context(), 200, accounting._usage_from({"usage": {"input_tokens": 9, "output_tokens": 4}}), None)
    assert (full["input_tokens"], full["output_tokens"], full["cost_usd"], full["cost_basis"]) == (9, 4, 0.00005, "usage")
    absent = accounting._row(context(), 200, None, None)
    assert (absent["input_tokens"], absent["output_tokens"], absent["cost_usd"], absent["cost_basis"]) == (None, None, 0.0018, "estimate")
    invalid = accounting._row(context(), 200, accounting._usage_from({"usage": {"total_tokens": 20}}), None)
    assert invalid["cost_usd"] is None


def test_unknown_cost_retains_usage_and_current_d1_row_shape(pricing):
    unknown = context()
    unknown.models = ["unknown"]
    row = accounting._row(unknown, 200, accounting._usage_from({"usage": {"input_tokens": 0}}), None)
    assert set(row) == set(usage_store.ROW_FIELDS)
    assert row["input_tokens"] == 0 and row["output_tokens"] is None
    assert row["cost_usd"] is None and row["cost_basis"] is None
    result = subprocess.run(
        ["node", "--input-type=module", "-e",
         "import {validRow} from './worker/usage-ledger-d1.mjs';"
         "let data=''; for await (const chunk of process.stdin) data+=chunk;"
         "if (!validRow(JSON.parse(data))) process.exit(1);"],
        input=json.dumps(row), text=True, capture_output=True, check=False,
    )
    assert result.returncode == 0, result.stderr


def test_stream_usage_survives_tail_bounds_and_close_is_once(pricing):
    rows = []
    app = Flask(__name__)
    events = [b'data: {"usage":{"input_tokens":8}}\n\n', b'data: ' + b'x' * 70000 + b'\n\n',
              b'data: {"usage":{"output_tokens":4}}\n\n']
    with app.test_request_context("/v1/chat/completions", method="POST"):
        g.usage_context = context()
        with patch.object(usage_ledger.LEDGER, "record", side_effect=rows.append), \
             patch.object(BudgetService, "record_cost"), patch.object(BudgetService, "settle") as settle, \
             patch.object(accounting.telemetry_export.EXPORTER, "submit"):
            response = accounting.finish(app.response_class(iter(events), mimetype="text/event-stream"))
            assert b"".join(response.response) == b"".join(events)
            response.close()
            response.close()
            settle.assert_called_once()
    assert len(rows) == 1
    assert (rows[0]["input_tokens"], rows[0]["output_tokens"]) == (8, 4)


@pytest.mark.parametrize("chunk_size", [1, 3, 17, 65536])
def test_stream_chunk_boundaries_and_invalid_events(chunk_size):
    from services.usage_types import StreamUsageObserver

    body = (b'data: {"usage":{"input_tokens":0}}\r\n\r\n'
            b'data: {"usage":broken}\n\n'
            b'data: {"usage":{"output_tokens":2}}\n\n')
    observer = StreamUsageObserver(accounting.SSE_TAIL_BYTES)
    for start in range(0, len(body), chunk_size):
        observer.feed(body[start:start + chunk_size])
    usage = observer.finish()
    assert (usage.input_tokens, usage.output_tokens) == (0, 2)


def test_concurrent_stream_observations_are_request_local():
    from services.usage_types import StreamUsageObserver

    def observe(index):
        observer = StreamUsageObserver(1024)
        observer.feed(b'data: ' + json.dumps({"usage": {"input_tokens": index}}).encode() + b'\n\n')
        observer.feed(b'data: {"usage":{"output_tokens":0}}\n\n')
        return observer.finish()

    with ThreadPoolExecutor(max_workers=4) as executor:
        observations = list(executor.map(observe, range(20)))
    assert [(item.input_tokens, item.output_tokens) for item in observations] == [(i, 0) for i in range(20)]


def test_aborted_stream_records_only_observed_usage(pricing):
    rows = []
    app = Flask(__name__)
    body = [b'data: {"usage":{"input_tokens":0}}\n\n',
            b'data: {"usage":{"output_tokens":20}}\n\n']
    with app.test_request_context("/v1/chat/completions", method="POST"):
        g.usage_context = context()
        with patch.object(usage_ledger.LEDGER, "record", side_effect=rows.append), \
             patch.object(BudgetService, "record_cost"), patch.object(BudgetService, "settle"), \
             patch.object(accounting.telemetry_export.EXPORTER, "submit"):
            response = accounting.finish(app.response_class(iter(body), mimetype="text/event-stream"))
            assert next(response.response) == body[0]
            response.close()
    assert (rows[0]["input_tokens"], rows[0]["output_tokens"], rows[0]["cost_usd"]) == (0, None, None)


def test_cached_and_failure_rows_keep_existing_behavior(pricing):
    cached = context()
    cached.cached = True
    row = accounting._row(cached, 200, None, None)
    assert (row["cost_usd"], row["cost_basis"]) == (0.0, "cache")
    row = accounting._row(context(), 503, None, None)
    assert (row["cost_usd"], row["cost_basis"]) == (None, None)


@pytest.mark.parametrize("usage,expected", [
    ({"input_tokens": 9}, 0.001618),
    ({"output_tokens": 4}, 0.000232),
    ({"input_tokens": 0}, 0.0016),
    ({"total_tokens": 13}, 0.0018),
    ({"input_tokens": 9, "output_tokens": 4}, 0.00005),
    ({"input_tokens": 0, "output_tokens": 0}, 0.0),
])
@pytest.mark.parametrize("ledger_enabled", [False, True])
def test_budget_counts_missing_components_from_request_estimate(pricing, monkeypatch, usage, expected, ledger_enabled):
    monkeypatch.setenv("USAGE_LEDGER_ENABLED", str(ledger_enabled).lower())
    monkeypatch.setenv("USAGE_BUDGET_REFRESH_SECONDS", "1")
    BudgetService.reset()
    rows = []
    totals = SimpleNamespace(totals=lambda *args: {"day_usd": 0.0, "month_usd": 0.0})
    monkeypatch.setattr(usage_ledger.LEDGER, "store", lambda: totals)
    monkeypatch.setattr(usage_ledger.LEDGER, "record", rows.append)
    monkeypatch.setattr(accounting.telemetry_export.EXPORTER, "submit", lambda event: None)
    ctx = context()
    ctx.user["daily_budget_usd"] = 0.002
    ctx.user["monthly_budget_usd"] = 0.003
    admitted = BudgetService.check_and_reserve(ctx.user, 0.0018)
    assert admitted.allowed
    ctx.reservation = admitted.reservation
    try:
        accounting._record(ctx, 200, accounting._usage_from({"usage": usage}), None)
        accounting._record(ctx, 200, accounting._usage_from({"usage": usage}), None)
        [row] = rows
        complete = "input_tokens" in usage and "output_tokens" in usage
        assert row["cost_usd"] == (expected if complete else None)
        assert row["cost_basis"] == ("usage" if complete else None)
        # Unknown ledger costs never replace the conservative local charge on flush/drop.
        (BudgetService.on_flushed if ledger_enabled else BudgetService.on_dropped)(rows)
        stored = expected if ledger_enabled and complete else 0.0
        totals.totals = lambda *args: {"day_usd": stored, "month_usd": stored}
        BudgetService._principals["reader"].fetched = 0.0
        status = BudgetService.status(ctx.user)
        assert status["spent_today_usd"] == pytest.approx(expected)
        assert status["spent_this_month_usd"] == pytest.approx(expected)
        assert status["in_flight_usd"] == 0.0
        next_request = BudgetService.check_and_reserve(ctx.user, 0.0005)
        assert next_request.allowed == (expected + 0.0005 <= 0.002)
    finally:
        BudgetService.reset()


def test_unpriced_partial_usage_keeps_existing_budget_behavior(pricing, monkeypatch):
    monkeypatch.setenv("USAGE_LEDGER_ENABLED", "false")
    monkeypatch.setattr(usage_ledger.LEDGER, "record", lambda row: None)
    monkeypatch.setattr(accounting.telemetry_export.EXPORTER, "submit", lambda event: None)
    BudgetService.reset()
    ctx = context()
    ctx.models = ["unpriced"]
    ctx.user["daily_budget_usd"] = 0.001
    try:
        accounting._record(ctx, 200, accounting._usage_from({"usage": {"input_tokens": 9}}), None)
        assert BudgetService.status(ctx.user)["spent_today_usd"] == 0.0
        assert BudgetService.check_and_reserve(ctx.user, 0.001).allowed
    finally:
        BudgetService.reset()


@pytest.mark.parametrize("path,data", [
    ("/v1/embeddings", []),
    ("/opencode/v1/embeddings", [{"embedding": [0.1, 0.2], "index": 0}]),
])
@pytest.mark.parametrize("usage,expected", [
    ({"prompt_tokens": 9, "total_tokens": 9}, (9, 0, 0.000018, "usage")),
    ({"total_tokens": 9}, (None, 0, None, None)),
])
def test_embedding_usage_is_measured_zero_output_and_preserves_body(pricing, path, data, usage, expected):
    rows = []
    app = Flask(__name__)
    body = json.dumps({"data": data, "usage": usage}).encode()
    with app.test_request_context(path, method="POST"):
        g.usage_context = context()
        with patch.object(usage_ledger.LEDGER, "record", side_effect=rows.append), \
             patch.object(BudgetService, "record_cost") as record_cost, \
             patch.object(BudgetService, "settle"), \
             patch.object(accounting.telemetry_export.EXPORTER, "submit"):
            response = accounting.finish(app.response_class(body, mimetype="application/json"))
            assert response.get_data() == body
            [row] = rows
            assert (row["input_tokens"], row["output_tokens"], row["cost_usd"], row["cost_basis"]) == expected
            budget_cost = expected[2] if expected[2] is not None else 0.0002
            record_cost.assert_called_once_with({**row, "cost_usd": budget_cost})


class UsageUncertaintyRoutesTest(UnifiedApiTestCase):
    def setUp(self):
        # Block runtime environment loading and unmocked outbound HTTP before app creation.
        self.env_patch = patch("config.load_runtime_env")
        self.http_patch = patch("requests.sessions.Session.request", side_effect=AssertionError("unexpected HTTP"))
        self.env_patch.start()
        self.http_patch.start()
        self.addCleanup(self.env_patch.stop)
        self.addCleanup(self.http_patch.stop)
        super().setUp()
        self.rows = []
        self.record_patch = patch.object(usage_ledger.LEDGER, "record", side_effect=self.rows.append)
        self.record_patch.start()
        self.addCleanup(self.record_patch.stop)
        BudgetService.reset()
        self.addCleanup(BudgetService.reset)
        self.app.config["TESTING"] = True
        os.environ[CostService.ENV_NAME] = json.dumps({"opencode:*": {"input": 2, "output": 8}})

    def send(self, body, *, stream=False, path="/v1/chat/completions", status=200):
        upstream = requests.Response()
        upstream.status_code = status
        upstream._content = body
        upstream.headers["Content-Type"] = "text/event-stream" if stream else "application/json"
        with patch("app.ProxyService.make_request", return_value=upstream) as dispatch:
            response = self.client.post(path, headers={"Authorization": "Bearer admin-test-key"},
                                        json={"model": "opencode:glm-5.2", "messages": [{"role": "user", "content": "hi"}],
                                              "stream": stream})
            content = response.get_data()
            response.close()
        dispatch.assert_called_once()
        return response, content

    def test_registered_json_keeps_partial_usage_and_response_bytes(self):
        body = b'{"choices":[],"usage":{"prompt_tokens":0}}'
        response, content = self.send(body)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(content, body)
        self.assertEqual(len(self.rows), 1)
        self.assertEqual((self.rows[0]["input_tokens"], self.rows[0]["output_tokens"], self.rows[0]["cost_usd"]), (0, None, None))

    def test_registered_sse_preserves_bytes_and_split_usage(self):
        body = (b'data: {"usage":{"prompt_tokens":8}}\n\n'
                b'data: {"usage":{"completion_tokens":4}}\n\ndata: [DONE]\n\n')
        response, content = self.send(body, stream=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(content, body)
        self.assertEqual((self.rows[0]["input_tokens"], self.rows[0]["output_tokens"], self.rows[0]["cost_basis"]), (8, 4, "usage"))

    def test_raw_provider_body_remains_byte_identical(self):
        body = b'{ "usage": {"input_tokens": 0}, "native_extra": [1, 2] }'
        response, content = self.send(body, path="/opencode/v1/chat/completions")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(content, body)
        self.assertEqual((self.rows[0]["input_tokens"], self.rows[0]["output_tokens"]), (0, None))

    def test_registered_failure_without_usage_has_no_cost(self):
        response, _ = self.send(b'{"error":{"message":"unavailable"}}', status=503)
        self.assertEqual(response.status_code, 503)
        self.assertIsNone(self.rows[0]["cost_usd"])

    def test_registered_zero_and_unpriced_usage_remain_distinct(self):
        body = b'{"choices":[],"usage":{"prompt_tokens":0,"completion_tokens":0}}'
        self.send(body)
        self.assertEqual((self.rows[-1]["cost_usd"], self.rows[-1]["cost_basis"]), (0.0, "usage"))
        os.environ[CostService.ENV_NAME] = "{}"
        self.send(body)
        self.assertEqual((self.rows[-1]["input_tokens"], self.rows[-1]["output_tokens"]), (0, 0))
        self.assertIsNone(self.rows[-1]["cost_usd"])

    def test_registered_admin_usage_summary_retains_coverage(self):
        self.send(b'{"choices":[],"usage":{"prompt_tokens":0}}')
        self.send(b'{"choices":[],"usage":{"prompt_tokens":0,"completion_tokens":0}}')
        os.environ["USAGE_DB_PATH"] = os.path.join(self.temp_dir.name, "usage.sqlite3")
        os.environ["CONTROL_PLANE_DATABASE_URL"] = ""
        store = usage_store.SqlUsageStore()
        store.record("b" * 32, self.rows)
        with patch.object(usage_ledger.LEDGER, "store", return_value=store):
            response = self.client.get("/v1/usage", headers={"Authorization": "Bearer admin-test-key"})
        self.assertEqual(response.status_code, 200)
        summary = response.get_json()["daily"][0]
        self.assertEqual((summary["requests"], summary["priced_requests"], summary["cost_usd"]), (2, 1, 0.0))


def test_admin_summary_preserves_priced_coverage(pricing, monkeypatch, tmp_path):
    monkeypatch.setenv("USAGE_DB_PATH", str(tmp_path / "usage.sqlite3"))
    monkeypatch.setenv("CONTROL_PLANE_DATABASE_URL", "")
    store = usage_store.SqlUsageStore()
    rows = [accounting._row(context(), 200, accounting._usage_from({"usage": usage}), None)
            for usage in ({"input_tokens": 0}, {"input_tokens": 0, "output_tokens": 0},
                          {"input_tokens": 9, "output_tokens": 4})]
    store.record("a" * 32, rows)
    [summary] = store.summary("day", "2000-01-01", "2999-12-31", None, 10)
    summary = usage_store.summarize(summary)
    assert summary["requests"] == 3 and summary["priced_requests"] == 2
    assert summary["cost_usd"] == 0.00005
    recent = store.recent("2000-01-01T00:00:00.000Z", None, None, 10)
    assert recent[-1]["output_tokens"] is None and recent[-1]["cost_usd"] is None
