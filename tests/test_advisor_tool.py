"""Claude's advisor tool on /v1/messages: a stronger model advises while the request's
model writes the answer.

The replies below follow the shape the Claude API returned on 7 November 2026 for
Claude Haiku 5.5 with a Claude Sonnet 5.5 advisor: `usage.iterations` lists the
executor's two turns and the advisor's own turn, and top-level usage counts only the
executor.
"""

import io
import json
import os
import sys
from unittest.mock import patch

import requests

from services import usage_ledger
from services.budget_service import BudgetService
from services.tool_repair_runtime import HEADER
from tests.test_claude_pricing import SHIPPED_PRICES
from tests.unified_api_test_case import UnifiedApiTestCase

HAIKU = "anthropic:claude-haiku-5-5"
SONNET = "anthropic:claude-sonnet-5-5"
BETA = {"anthropic-beta": "advisor-tool-2026-03-01", "anthropic-version": "2023-06-01"}


def advisor_tool(model="claude-sonnet-5-5", **extra):
    return {"type": "advisor_20260301", "name": "advisor", "model": model, "max_uses": 1, "max_tokens": 1500, **extra}


def iteration(kind, input_tokens, output_tokens, *, model=None, read=0, written=0, one_hour=0):
    entry = {"input_tokens": input_tokens, "output_tokens": output_tokens, "cache_read_input_tokens": read,
             "cache_creation_input_tokens": written,
             "cache_creation": {"ephemeral_5m_input_tokens": written - one_hour, "ephemeral_1h_input_tokens": one_hour},
             "type": kind}
    if model:
        entry["model"] = model
    return entry


ITERATIONS = [
    iteration("message", 1097, 92),
    iteration("advisor_message", 2778, 685, model="claude-sonnet-5-5"),
    iteration("message", 1542, 112),
]


def advised_usage(iterations=None):
    iterations = ITERATIONS if iterations is None else iterations
    executor = [entry for entry in iterations if entry["type"] == "message"]
    return {"input_tokens": sum(entry["input_tokens"] for entry in executor),
            "cache_creation_input_tokens": sum(entry["cache_creation_input_tokens"] for entry in executor),
            "cache_read_input_tokens": sum(entry["cache_read_input_tokens"] for entry in executor),
            "output_tokens": sum(entry["output_tokens"] for entry in executor),
            "iterations": iterations}


ADVICE = {"type": "advisor_redacted_result", "encrypted_content": "c3ludGhldGljIGFkdmljZQ==", "stop_reason": "end_turn"}


def advised_message(usage=None):
    return {"id": "msg_advised", "type": "message", "role": "assistant", "model": "claude-haiku-5-5",
            "content": [
                {"type": "server_tool_use", "id": "srvtoolu_synthetic", "name": "advisor", "input": {}},
                {"type": "advisor_tool_result", "tool_use_id": "srvtoolu_synthetic", "content": ADVICE},
                {"type": "text", "text": "A synthetic answer."},
            ],
            "stop_reason": "end_turn", "stop_sequence": None, "usage": usage or advised_usage()}


def advised_frames(usage=None):
    usage = usage or advised_usage()
    first = usage["iterations"][0]
    start = {key: first[key] for key in ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")}
    events = (
        ("message_start", {"type": "message_start", "message": {
            "id": "msg_advised", "type": "message", "role": "assistant", "model": "claude-haiku-5-5", "content": [],
            "stop_reason": None, "stop_sequence": None, "usage": {**start, "output_tokens": 8}}}),
        ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {
            "type": "server_tool_use", "id": "srvtoolu_synthetic", "name": "advisor", "input": {}}}),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        ("content_block_start", {"type": "content_block_start", "index": 1, "content_block": {
            "type": "advisor_tool_result", "tool_use_id": "srvtoolu_synthetic", "content": ADVICE}}),
        ("content_block_stop", {"type": "content_block_stop", "index": 1}),
        ("content_block_start", {"type": "content_block_start", "index": 2, "content_block": {"type": "text", "text": ""}}),
        ("content_block_delta", {"type": "content_block_delta", "index": 2,
                                 "delta": {"type": "text_delta", "text": "A synthetic answer."}}),
        ("content_block_stop", {"type": "content_block_stop", "index": 2}),
        ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                           "usage": usage}),
        ("message_stop", {"type": "message_stop"}),
    )
    return b"".join(f"event: {name}\ndata: {json.dumps(data)}\n\n".encode() for name, data in events)


def json_reply(body):
    response = requests.Response()
    response.status_code = 200
    response._content = json.dumps(body).encode()
    response.raw = io.BytesIO(response._content)
    response.headers["Content-Type"] = "application/json"
    return response


def stream_reply(body):
    response = requests.Response()
    response.status_code = 200
    response.raw = io.BytesIO(body)
    response.headers["Content-Type"] = "text/event-stream"
    return response


class AdvisorTestCase(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        os.environ["ANTHROPIC_API_KEY"] = "anthropic-provider-key"

    def messages(self, body, reply, *, key="admin-test-key", headers=None):
        payload = {"model": HAIKU, "max_tokens": 1024, "messages": [{"role": "user", "content": "A synthetic question"}],
                   "tools": [advisor_tool()], **body}
        with patch.object(self.app_module.ProxyService, "make_request", return_value=reply) as send:
            response = self.client.post("/v1/messages", json=payload,
                                        headers={"Authorization": f"Bearer {key}", **BETA, **(headers or {})})
            data = response.get_data()
            response.close()
        return response, data, send


class AdvisorPassthroughTest(AdvisorTestCase):
    """Tool repair cannot carry server tool blocks, so advisor replies pass through."""

    def test_streamed_advisor_reply_passes_through_unchanged(self):
        body = advised_frames()
        for mode in ("repair", "full"):
            with self.subTest(mode=mode):
                response, data, send = self.messages({"stream": True}, stream_reply(body), headers={HEADER: mode})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(data, body)
                self.assertEqual(response.headers[HEADER], f"mode={mode}; streaming=1")
                self.assertEqual(json.loads(send.call_args.kwargs["data"])["tools"], [advisor_tool()])

    def test_advisor_reply_with_a_function_tool_keeps_its_advice_blocks(self):
        lookup = {"name": "lookup", "input_schema": {"type": "object", "properties": {"q": {"type": "string"}}}}
        reply = advised_message()
        response, data, _ = self.messages({"tools": [advisor_tool(), lookup]}, json_reply(reply))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(data), reply)
        self.assertEqual(response.headers[HEADER], "checked=0 repaired=0 extracted=0 invalid=0 reasked=0")


ADMIN = {"username": "admin", "is_admin": True}


class AdvisorPolicyTest(AdvisorTestCase):
    """The advisor's model is held to the key's model controls before dispatch."""

    def restricted_key(self, allowed=(HAIKU,), official_only=True):
        with patch.object(self.app_module.AuthService, "get_current_user", return_value=ADMIN):
            key = self.app_module.AuthService.create_user("restricted", scopes=["chat", "models"])["api_key"]
            self.app_module.AuthService.set_key_controls(
                "restricted", {"allowed_models": list(allowed), "official_only": official_only})
        return key

    def test_a_restricted_key_cannot_reach_an_opus_advisor(self):
        key = self.restricted_key()
        for model in ("claude-opus-5-5", "anthropic:claude-opus-5-5", "Claude-Opus-5-5"):
            with self.subTest(model=model):
                response, data, send = self.messages({"tools": [advisor_tool(model)]}, json_reply(advised_message()),
                                                     key=key)
                self.assertEqual(response.status_code, 403)
                self.assertEqual(json.loads(data)["error"]["type"], "permission_error")
                self.assertIn("anthropic:claude-opus-5-5", json.loads(data)["error"]["message"].lower())
                send.assert_not_called()

    def test_the_refusal_matches_a_disallowed_top_level_model(self):
        key = self.restricted_key()
        _, advised, _ = self.messages({"tools": [advisor_tool("claude-opus-5-5")]}, json_reply(advised_message()), key=key)
        _, direct, _ = self.messages({"model": "anthropic:claude-opus-5-5", "tools": []}, json_reply(advised_message()),
                                     key=key)
        advised, direct = json.loads(advised), json.loads(direct)
        self.assertEqual(advised["error"]["type"], direct["error"]["type"])
        self.assertEqual(advised["error"]["message"], direct["error"]["message"])

    def test_an_allowed_advisor_is_sent_under_its_bare_id(self):
        key = self.restricted_key(allowed=(HAIKU, SONNET))
        for model in ("claude-sonnet-5-5", "anthropic:claude-sonnet-5-5"):
            with self.subTest(model=model):
                response, _, send = self.messages({"tools": [advisor_tool(model)]}, json_reply(advised_message()),
                                                  key=key)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(json.loads(send.call_args.kwargs["data"])["tools"], [advisor_tool("claude-sonnet-5-5")])

    def test_a_wildcard_allowlist_admits_its_advisors(self):
        key = self.restricted_key(allowed=("anthropic:*",))
        response, _, _ = self.messages({"tools": [advisor_tool("claude-opus-5-5")]}, json_reply(advised_message()), key=key)
        self.assertEqual(response.status_code, 200)

    def test_an_advisor_from_another_provider_is_refused_before_dispatch(self):
        for model in ("openai:gpt-5.5", "opencode:claude-opus-5-5", "", None, 5):
            with self.subTest(model=model):
                response, data, send = self.messages({"tools": [advisor_tool(model)]}, json_reply(advised_message()))
                self.assertEqual(response.status_code, 400)
                self.assertEqual(json.loads(data)["error"]["type"], "invalid_request_error")
                send.assert_not_called()

    def test_a_disabled_advisor_model_is_refused_like_the_model_itself(self):
        fable = "anthropic:claude-fable-5-1"
        status = lambda model: "disabled" if model == fable else "available"
        registry = sys.modules["services.model_registry"].ModelRegistry
        with patch.object(registry, "get_model_status", side_effect=status):
            for model in ("claude-fable-5-1", fable):
                with self.subTest(model=model):
                    response, data, send = self.messages({"tools": [advisor_tool(model)]},
                                                         json_reply(advised_message()))
                    self.assertEqual(response.status_code, 400)
                    self.assertIn(f"Model is disabled: {fable}", json.loads(data)["error"]["message"])
                    send.assert_not_called()
            _, direct, _ = self.messages({"model": fable, "tools": []}, json_reply(advised_message()))
            self.assertIn(f"Model is disabled: {fable}", json.loads(direct)["error"]["message"])

    def test_every_advisor_tool_is_checked(self):
        key = self.restricted_key(allowed=(HAIKU, SONNET))
        tools = [advisor_tool("claude-sonnet-5-5"), advisor_tool("claude-fable-5-1", name="second")]
        response, _, send = self.messages({"tools": tools}, json_reply(advised_message()), key=key)
        self.assertEqual(response.status_code, 403)
        send.assert_not_called()


# The executor's two steps at Haiku 5.5 prices, and the advisor's at Sonnet 5.5's.
HAIKU_COST = (1097 + 1542) * 0.1 / 1e6 + (92 + 112) * 0.5 / 1e6
SONNET_COST = 2778 * 2 / 1e6 + 685 * 10 / 1e6


class LedgerTestCase(AdvisorTestCase):
    """Production pricing: the shipped table with prompt cache buckets on."""

    def setUp(self):
        super().setUp()
        os.environ.update({
            "USAGE_LEDGER_ENABLED": "true", "USAGE_LEDGER_BACKEND": "sql", "USAGE_LEDGER_FLUSH_SECONDS": "300",
            "USAGE_DB_PATH": os.path.join(self.temp_dir.name, "usage.sqlite3"),
            "CONTROL_PLANE_DATABASE_URL": "",
            "MODEL_PRICING_USD_PER_MILLION": SHIPPED_PRICES,
            "PROMPT_CACHE_USAGE_BUCKETS_ENABLED": "true",
            "PROMPT_CACHE_PRICE_METADATA_JSON": "{}",
        })
        usage_ledger.LEDGER.reset()
        BudgetService.reset()
        with patch.object(self.app_module.AuthService, "get_current_user", return_value=ADMIN):
            self.key = self.app_module.AuthService.create_user("advised", scopes=["chat", "models"])["api_key"]

    def tearDown(self):
        usage_ledger.LEDGER.reset()
        BudgetService.reset()
        super().tearDown()

    def rows(self):
        self.assertTrue(usage_ledger.LEDGER.flush(timeout=5))
        rows = usage_ledger.LEDGER.store().recent("2000-01-01T00:00:00.000Z", "advised", None, 50)
        return {row["selected_model"]: row for row in rows}


class AdvisorLedgerTest(LedgerTestCase):
    """Advisor steps are priced at the advisor's model and recorded under it."""

    def assert_priced(self, rows):
        self.assertEqual(set(rows), {HAIKU, SONNET})
        haiku, sonnet = rows[HAIKU], rows[SONNET]
        self.assertEqual((haiku["endpoint"], sonnet["endpoint"]), ("/v1/messages", "/v1/messages/advisor"))
        self.assertEqual((haiku["input_tokens"], haiku["output_tokens"]), (2639, 204))
        self.assertEqual((sonnet["input_tokens"], sonnet["output_tokens"]), (2778, 685))
        self.assertAlmostEqual(haiku["cost_usd"], HAIKU_COST)
        self.assertAlmostEqual(sonnet["cost_usd"], SONNET_COST)
        self.assertEqual((haiku["cost_basis"], sonnet["cost_basis"]), ("usage", "usage"))
        self.assertEqual(sonnet["request_id"], haiku["request_id"])
        self.assertEqual(sonnet["at"], haiku["at"])

    def test_a_three_step_reply_is_priced_per_model(self):
        response, _, _ = self.messages({}, json_reply(advised_message()), key=self.key)
        self.assertEqual(response.status_code, 200)
        self.assert_priced(self.rows())

    def test_a_streamed_reply_is_priced_per_model(self):
        response, _, _ = self.messages({"stream": True}, stream_reply(advised_frames()), key=self.key)
        self.assertEqual(response.status_code, 200)
        self.assert_priced(self.rows())

    def test_v1_usage_lists_the_advisor_under_its_own_model(self):
        self.messages({}, json_reply(advised_message()), key=self.key)
        self.assertTrue(usage_ledger.LEDGER.flush(timeout=5))
        summary = self.client.get("/v1/usage", headers={"Authorization": f"Bearer {self.key}"}).get_json()
        models = {entry["model"]: entry for entry in summary["models"]}
        self.assertEqual((models[SONNET]["input_tokens"], models[SONNET]["output_tokens"]), (2778, 685))
        self.assertAlmostEqual(models[SONNET]["cost_usd"], SONNET_COST)
        self.assertAlmostEqual(models[HAIKU]["cost_usd"], HAIKU_COST)
        self.assertAlmostEqual(summary["totals"]["cost_usd"], HAIKU_COST + SONNET_COST)

    def test_a_budget_counts_the_advisor(self):
        with patch.object(self.app_module.AuthService, "get_current_user", return_value=ADMIN):
            self.app_module.AuthService.set_key_controls("advised", {"daily_budget_usd": 1, "monthly_budget_usd": 5})
        self.messages({}, json_reply(advised_message()), key=self.key)
        self.assertTrue(usage_ledger.LEDGER.flush(timeout=5))
        budget = self.client.get("/v1/usage", headers={"Authorization": f"Bearer {self.key}"}).get_json()["budget"]
        self.assertAlmostEqual(budget["daily_remaining_usd"], 1 - HAIKU_COST - SONNET_COST)

    def test_advisor_cache_reads_and_writes_use_the_advisor_prices(self):
        steps = [iteration("message", 1000, 50),
                 iteration("advisor_message", 100, 500, model="claude-sonnet-5-5", read=10_000, written=4_000,
                           one_hour=1_000),
                 iteration("message", 1200, 60)]
        self.messages({}, json_reply(advised_message(advised_usage(steps))), key=self.key)
        sonnet = self.rows()[SONNET]
        expected = (100 * 2 + 10_000 * 0.2 + 3_000 * 2.5 + 1_000 * 4 + 500 * 10) / 1e6
        self.assertAlmostEqual(sonnet["cost_usd"], expected)
        self.assertEqual((sonnet["input_tokens"], sonnet["cached_input_tokens"]), (14_100, 10_000))

    def test_each_step_has_its_own_long_prompt_tier(self):
        # Two Haiku steps of 60,000 prompt tokens each stay under the 100,000 threshold.
        steps = [iteration("message", 60_000, 10), iteration("advisor_message", 61_000, 10, model="claude-sonnet-5-5"),
                 iteration("message", 60_000, 10)]
        self.messages({}, json_reply(advised_message(advised_usage(steps))), key=self.key)
        self.assertAlmostEqual(self.rows()[HAIKU]["cost_usd"], (120_000 * 0.1 + 20 * 0.5) / 1e6)

    def test_an_unpriced_advisor_is_recorded_without_a_cost(self):
        steps = [iteration("message", 1000, 50), iteration("advisor_message", 2000, 500, model="claude-unlisted-9"),
                 iteration("message", 1200, 60)]
        self.messages({}, json_reply(advised_message(advised_usage(steps))), key=self.key)
        rows = self.rows()
        self.assertIsNone(rows["anthropic:claude-unlisted-9"]["cost_usd"])
        self.assertAlmostEqual(rows[HAIKU]["cost_usd"], (2200 * 0.1 + 110 * 0.5) / 1e6)

    def test_a_message_step_naming_a_snapshot_stays_with_the_request(self):
        steps = [iteration("message", 1000, 50, model="claude-haiku-5-5-20261001"),
                 iteration("advisor_message", 2000, 500, model="claude-sonnet-5-5"),
                 iteration("message", 1200, 60, model="claude-haiku-5-5")]
        self.messages({}, json_reply(advised_message(advised_usage(steps))), key=self.key)
        rows = self.rows()
        self.assertEqual(set(rows), {HAIKU, SONNET})
        self.assertEqual((rows[HAIKU]["input_tokens"], rows[HAIKU]["output_tokens"]), (2200, 110))

    def test_steps_past_the_cap_are_still_billed(self):
        steps = [iteration("message", 1000, 10) for _ in range(299)]
        steps.append(iteration("advisor_message", 2778, 685, model="claude-sonnet-5-5"))
        self.messages({}, json_reply(advised_message(advised_usage(steps))), key=self.key)
        rows = self.rows()
        self.assertEqual((rows[HAIKU]["input_tokens"], rows[HAIKU]["output_tokens"]), (299_000, 2_990))
        self.assertAlmostEqual(rows[HAIKU]["cost_usd"], (299_000 * 0.1 + 2_990 * 0.5) / 1e6)
        self.assertEqual((rows[SONNET]["input_tokens"], rows[SONNET]["output_tokens"]), (2778, 685))
        self.assertAlmostEqual(rows[SONNET]["cost_usd"], SONNET_COST)

    def test_a_reply_without_steps_keeps_one_row(self):
        usage = {"input_tokens": 1000, "output_tokens": 50, "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0}
        self.messages({"tools": []}, json_reply(advised_message(usage)), key=self.key)
        rows = self.rows()
        self.assertEqual(set(rows), {HAIKU})
        self.assertEqual(rows[HAIKU]["endpoint"], "/v1/messages")


class AdvisorReservationTest(LedgerTestCase):
    """Admission reserves the advisor's worst case, so a cap cannot be overrun."""

    def budget(self, daily):
        with patch.object(self.app_module.AuthService, "get_current_user", return_value=ADMIN):
            self.app_module.AuthService.set_key_controls("advised", {"daily_budget_usd": daily})

    def test_a_budget_that_fits_the_request_but_not_its_advisor_refuses_it(self):
        self.budget(0.01)
        plain = {"input_tokens": 20, "output_tokens": 10, "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0}
        response, _, send = self.messages({"tools": []}, json_reply(advised_message(plain)), key=self.key)
        self.assertEqual(response.status_code, 200)
        response, data, send = self.messages({}, json_reply(advised_message()), key=self.key)
        self.assertEqual(response.status_code, 429)
        self.assertEqual(json.loads(data)["error"]["type"], "rate_limit_error")
        send.assert_not_called()

    def test_the_reserved_estimate_covers_every_advisor_call(self):
        self.budget(0.0001)
        _, plain, _ = self.messages({"tools": []}, json_reply(advised_message()), key=self.key)
        _, once, _ = self.messages({}, json_reply(advised_message()), key=self.key)
        _, thrice, _ = self.messages({"tools": [advisor_tool(max_uses=3)]}, json_reply(advised_message()), key=self.key)
        plain, once, thrice = (json.loads(body)["error"]["message"] for body in (plain, once, thrice))
        estimate = lambda message: float(message.split("estimated at $")[1].split(")")[0])
        # Each call can write 1,500 Sonnet tokens ($0.015) and read the transcript.
        self.assertGreater(estimate(once) - estimate(plain), 1500 * 10 / 1e6 + 4096 * 2 / 1e6)
        self.assertGreater(estimate(thrice) - estimate(plain), 3 * (estimate(once) - estimate(plain)))

    def test_a_capped_key_must_bound_its_advisor(self):
        self.budget(5)
        for missing in ("max_uses", "max_tokens"):
            with self.subTest(missing=missing):
                tool = {key: value for key, value in advisor_tool().items() if key != missing}
                response, data, send = self.messages({"tools": [tool]}, json_reply(advised_message()), key=self.key)
                self.assertEqual(response.status_code, 400)
                self.assertIn(missing, json.loads(data)["error"]["message"])
                send.assert_not_called()

    def test_token_counting_needs_no_advisor_bounds(self):
        with patch.object(self.app_module.AuthService, "get_current_user", return_value=ADMIN):
            self.app_module.AuthService.set_key_controls("admin", {"daily_budget_usd": 5})
        tool = {"type": "advisor_20260301", "name": "advisor", "model": "claude-sonnet-5-5"}
        payload = {"model": "claude-haiku-5-5", "max_tokens": 1024, "tools": [tool],
                   "messages": [{"role": "user", "content": "A synthetic question"}]}
        headers = {"x-api-key": "admin-test-key", **BETA}
        for path, status in (("/anthropic/v1/messages", 400), ("/anthropic/v1/messages/count_tokens", 200)):
            with self.subTest(path=path), patch.object(self.app_module.ProxyService, "make_request",
                                                       return_value=json_reply({"input_tokens": 8})) as send:
                response = self.client.post(path, json=payload, headers=headers)
                self.assertEqual(response.status_code, status)
                self.assertEqual(send.call_count, 1 if status == 200 else 0)

    def test_an_uncapped_key_may_leave_its_advisor_unbounded(self):
        tool = {"type": "advisor_20260301", "name": "advisor", "model": "claude-sonnet-5-5"}
        response, _, _ = self.messages({"tools": [tool]}, json_reply(advised_message()), key=self.key)
        self.assertEqual(response.status_code, 200)


def test_strict_reservations_refuse_an_unpriced_advisor(monkeypatch):
    from services import request_accounting
    from services.advisor_tool import Advisor

    monkeypatch.setenv("MODEL_PRICING_USD_PER_MILLION", SHIPPED_PRICES)
    context = request_accounting.UsageContext("chat", [HAIKU], None, {}, 0.0, 0, input_tokens=1000, output_tokens=500,
                                              advisors=(Advisor("anthropic:claude-unlisted-9", 2, 2000),))
    assert request_accounting.advisor_exposure(context, [HAIKU], strict=True) is None
    # Without strict pricing an unpriced advisor adds only the request's own re-reads.
    rereads = 2 * (1000 + 500 + 2 * 2000) * 0.1 / 1e6
    assert abs(request_accounting.advisor_exposure(context, [HAIKU], strict=False) - rereads) < 1e-12
    priced = request_accounting.UsageContext("chat", [HAIKU], None, {}, 0.0, 0, input_tokens=1000, output_tokens=500,
                                             advisors=(Advisor(SONNET, 2, 2000),))
    transcript = 1000 + 500 + 2 * 2000
    expected = 2 * ((transcript + 4096) * 2 / 1e6 + 2000 * 10 / 1e6 + transcript * 0.1 / 1e6)
    assert abs(request_accounting.advisor_exposure(priced, [HAIKU], strict=True) - expected) < 1e-12
