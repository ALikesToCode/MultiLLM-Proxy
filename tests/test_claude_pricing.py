"""Claude API prices shipped in wrangler.jsonc, as the usage ledger and budgets apply them.

Per-key budgets never decreased for Claude Haiku 5.5 because no Claude model had a
price, so every request was recorded at no cost. These tests price the shipped
table the way production does (prompt cache buckets on), through the real routes.
"""

import io
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest
import requests

from services import prompt_cache_cost, usage_ledger
from services.budget_service import BudgetService
from services.cost_service import CostService
from services.prompt_cache_cost import CacheObservation
from services.protocol_translation.anthropic_usage import anthropic_usage_to_chat
from services.protocol_translation.responses import (
    chat_usage_to_responses,
    responses_usage_to_chat,
)
from tests.unified_api_test_case import UnifiedApiTestCase

ROOT = Path(__file__).resolve().parents[1]
SHIPPED_PRICES = json.loads(ROOT.joinpath("wrangler.jsonc").read_text())["vars"]["RUNTIME_FEATURE_FLAGS"][
    "MODEL_PRICING_USD_PER_MILLION"]
HAIKU = "anthropic:claude-haiku-5-5"
ADMIN = {"username": "admin", "is_admin": True}
# Every Claude API model the gateway lists under anthropic:, plus the undated aliases
# of the two dated ids, with (input, output, cache read, 5-minute write, 1-hour write)
# in USD per million tokens from https://platform.claude.com/docs/en/about-claude/pricing.
LISTED_PRICES = {
    "claude-fable-5-1": (10, 50, 0.25, 12.5, 20),
    "claude-fable-5": (10, 50, 1, 12.5, 20),
    "claude-opus-5-5": (4, 20, 0.2, 5, 8),
    "claude-opus-5": (5, 25, 0.5, 6.25, 10),
    "claude-opus-4-8": (5, 25, 0.5, 6.25, 10),
    "claude-opus-4-7": (5, 25, 0.5, 6.25, 10),
    "claude-opus-4-6": (5, 25, 0.5, 6.25, 10),
    "claude-opus-4-5": (5, 25, 0.5, 6.25, 10),
    "claude-opus-4-5-20251101": (5, 25, 0.5, 6.25, 10),
    "claude-sonnet-5-5": (2, 10, 0.2, 2.5, 4),
    "claude-sonnet-5": (2, 10, 0.2, 2.5, 4),
    "claude-sonnet-4-6": (3, 15, 0.3, 3.75, 6),
    "claude-haiku-5-5": (0.1, 0.5, 0.01, 0.125, 0.2),
    "claude-haiku-4-5": (1, 5, 0.1, 1.25, 2),
    "claude-haiku-4-5-20251001": (1, 5, 0.1, 1.25, 2),
}


def claude_usage(input_tokens, output_tokens, *, read=0, five_minute=0, one_hour=0):
    """Usage as the Claude API reports it: input_tokens excludes cache reads and writes."""
    return {
        "input_tokens": input_tokens,
        "cache_creation_input_tokens": five_minute + one_hour,
        "cache_read_input_tokens": read,
        "cache_creation": {"ephemeral_5m_input_tokens": five_minute, "ephemeral_1h_input_tokens": one_hour},
        "output_tokens": output_tokens,
    }


def claude_message(usage):
    return {"id": "msg_priced", "type": "message", "role": "assistant", "model": "claude-haiku-5-5",
            "content": [{"type": "text", "text": "Hello"}], "stop_reason": "end_turn",
            "stop_sequence": None, "usage": usage}


def claude_stream(usage):
    """A streamed reply: message_start carries the prompt counts, message_delta the output."""
    start = {**usage, "output_tokens": 1}
    frames = (
        ("message_start", {"type": "message_start", "message": {
            "id": "msg_stream", "type": "message", "role": "assistant", "model": "claude-haiku-5-5",
            "content": [], "stop_reason": None, "usage": start}}),
        ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
        ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Hi"}}),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn"},
                           "usage": {"output_tokens": usage["output_tokens"]}}),
        ("message_stop", {"type": "message_stop"}),
    )
    body = b"".join(f"event: {name}\ndata: {json.dumps(data)}\n\n".encode() for name, data in frames)
    response = requests.Response()
    response.status_code = 200
    response.raw = io.BytesIO(body)
    response.headers["Content-Type"] = "text/event-stream"
    return response


def upstream(body):
    response = requests.Response()
    response.status_code = 200
    response._content = json.dumps(body).encode()
    response.raw = io.BytesIO(response._content)
    response.headers["Content-Type"] = "application/json"
    return response


@pytest.fixture
def shipped_prices(monkeypatch):
    monkeypatch.setenv("MODEL_PRICING_USD_PER_MILLION", SHIPPED_PRICES)
    monkeypatch.setenv("PROMPT_CACHE_USAGE_BUCKETS_ENABLED", "true")
    monkeypatch.setenv("PROMPT_CACHE_PRICE_METADATA_JSON", "{}")


def bucket_cost(usage, model=HAIKU):
    return prompt_cache_cost.price_buckets(model, CacheObservation.from_body({"type": "message", "usage": usage}))


@pytest.mark.parametrize("model", sorted(LISTED_PRICES))
def test_every_listed_claude_model_has_its_list_price(shipped_prices, model):
    input_price, output_price, read, five_minute, one_hour = LISTED_PRICES[model]
    # 40,000 prompt tokens stays under every long-prompt threshold; a price per
    # million tokens is the cost of one token in microUSD.
    usage = claude_usage(10_000, 10_000, read=10_000, five_minute=10_000, one_hour=10_000)
    result = bucket_cost(usage, f"anthropic:{model}")
    assert result["ordinary_input_cost_microusd"] == pytest.approx(input_price * 10_000)
    assert result["cache_read_input_cost_microusd"] == pytest.approx(read * 10_000)
    assert result["cache_write_input_cost_microusd"] == pytest.approx((five_minute + one_hour) * 10_000)
    assert result["output_cost_microusd"] == pytest.approx(output_price * 10_000)
    assert CostService.pricing_for(f"anthropic:{model}") is not None


def test_only_haiku_5_5_has_a_long_prompt_tier(shipped_prices):
    table = json.loads(SHIPPED_PRICES)
    tiers = {model: entry["long_context"] for model, entry in table.items() if "long_context" in entry}
    assert tiers == {HAIKU: {"above_input_tokens": 100_000, "input": 0.5, "output": 2.5, "cache_read": 0.05,
                             "cache_write": 0.625, "cache_write_1h": 1}}
    assert not any(key.endswith(":*") or key == "*" for key in table), "no guessed prices for unlisted models"


def test_normal_haiku_request(shipped_prices):
    result = bucket_cost(claude_usage(6_000, 4_000))
    # 6,000 x $0.10 + 4,000 x $0.50 per million tokens.
    assert result["cost_usd"] == pytest.approx(0.0026)


def test_cached_haiku_request_prices_reads_and_both_write_durations(shipped_prices):
    result = bucket_cost(claude_usage(1_000, 500, read=50_000, five_minute=6_000, one_hour=2_000))
    assert (result["ordinary_input_tokens"], result["cache_read_input_tokens"],
            result["cache_write_input_tokens"]) == (1_000, 50_000, 8_000)
    assert result["cache_read_input_cost_microusd"] == pytest.approx(500)      # 50,000 x $0.01
    assert result["cache_write_input_cost_microusd"] == pytest.approx(1_150)  # 6,000 x $0.125 + 2,000 x $0.20
    assert result["cost_usd"] == pytest.approx(0.002)                          # + 1,000 x $0.10 + 500 x $0.50


def test_a_prompt_just_over_100k_pays_five_times_for_the_whole_request(shipped_prices):
    # Cache reads count toward the threshold, and the output pays the higher price too.
    at_limit = bucket_cost(claude_usage(0, 1_000, read=100_000))
    over = bucket_cost(claude_usage(1, 1_000, read=100_000))
    assert at_limit["cost_usd"] == pytest.approx(0.0015)      # 100,000 x $0.01 + 1,000 x $0.50
    assert over["cost_usd"] == pytest.approx(0.0075005)       # 1 x $0.50 + 100,000 x $0.05 + 1,000 x $2.50
    written = bucket_cost(claude_usage(1, 0, five_minute=60_000, one_hour=40_000))
    assert written["cache_write_input_cost_microusd"] == pytest.approx(60_000 * 0.625 + 40_000 * 1)


def test_budget_estimates_use_the_long_prompt_price(shipped_prices):
    assert CostService.estimate(HAIKU, 100_000, 1_000) == pytest.approx(0.0105)
    assert CostService.estimate(HAIKU, 100_001, 1_000) == pytest.approx(0.0525005)
    estimated = prompt_cache_cost.budget_price([HAIKU], CacheObservation(150_000, 2_000), 1)
    assert estimated == pytest.approx(150_000 * 0.5e-6 + 2_000 * 2.5e-6)


def test_one_hour_writes_survive_chat_and_responses_translation(shipped_prices):
    usage = claude_usage(10, 5, read=20, five_minute=30, one_hour=40)
    chat = anthropic_usage_to_chat(usage)
    assert chat["prompt_tokens_details"]["cache_write_1h_tokens"] == 40
    responses = chat_usage_to_responses(chat)
    assert responses["input_tokens_details"]["cache_write_1h_tokens"] == 40
    assert responses_usage_to_chat(responses)["prompt_tokens_details"]["cache_write_1h_tokens"] == 40
    priced = prompt_cache_cost.price_buckets(HAIKU, CacheObservation.from_body({"object": "response", "usage": responses}))
    assert priced["cache_write_input_cost_microusd"] == pytest.approx(30 * 0.125 + 40 * 0.2)


def test_five_minute_only_usage_keeps_its_chat_shape(monkeypatch):
    monkeypatch.setenv("PROMPT_CACHE_USAGE_BUCKETS_ENABLED", "false")
    chat = anthropic_usage_to_chat(claude_usage(10, 5, read=20, five_minute=30))
    assert chat["prompt_tokens_details"] == {"cached_tokens": 20, "cache_write_tokens": 30}


class ClaudeLedgerRoutesTest(UnifiedApiTestCase):
    """Ledger cost for Claude Haiku 5.5 through /v1 and the Lean /lean/v1 routes."""

    def setUp(self):
        super().setUp()
        os.environ.update({
            "ANTHROPIC_API_KEY": "anthropic-provider-key",
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
            self.key = self.app_module.AuthService.create_user("budgeted", scopes=["chat", "models"])["api_key"]

    def tearDown(self):
        usage_ledger.LEDGER.reset()
        BudgetService.reset()
        super().tearDown()

    def send(self, path, body, reply):
        with patch("app.ProxyService.make_request", return_value=reply):
            response = self.client.post(path, json={"model": HAIKU, **body},
                                        headers={"Authorization": f"Bearer {self.key}"})
            response.get_data()
            response.close()
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        return response

    def row(self):
        self.assertTrue(usage_ledger.LEDGER.flush(timeout=5))
        [row] = usage_ledger.LEDGER.store().recent("2000-01-01T00:00:00.000Z", "budgeted", None, 50)
        self.assertEqual(row["selected_model"], HAIKU)
        self.assertEqual(row["cost_basis"], "usage")
        return row

    def chat(self, **extra):
        return {"messages": [{"role": "user", "content": "Hi"}], "max_tokens": 64, **extra}

    def test_v1_chat_records_the_haiku_cost(self):
        self.send("/v1/chat/completions", self.chat(), upstream(claude_message(claude_usage(6_000, 4_000))))
        row = self.row()
        self.assertEqual((row["input_tokens"], row["output_tokens"]), (6_000, 4_000))
        self.assertAlmostEqual(row["cost_usd"], 0.0026)

    def test_v1_chat_just_over_100k_records_the_long_prompt_cost(self):
        self.send("/v1/chat/completions", self.chat(),
                  upstream(claude_message(claude_usage(1, 1_000, read=100_000))))
        self.assertAlmostEqual(self.row()["cost_usd"], 0.0075005)

    def test_lean_chat_records_cached_usage(self):
        response = self.send("/lean/v1/chat/completions", self.chat(),
                             upstream(claude_message(claude_usage(1_000, 500, read=50_000, five_minute=6_000,
                                                                  one_hour=2_000))))
        self.assertEqual(response.headers["X-MultiLLM-Lean"], "applied")
        row = self.row()
        self.assertEqual((row["input_tokens"], row["cached_input_tokens"], row["output_tokens"]), (59_000, 50_000, 500))
        self.assertAlmostEqual(row["cost_usd"], 0.002)

    def test_lean_streamed_chat_records_cached_usage(self):
        self.send("/lean/v1/chat/completions", self.chat(stream=True, stream_options={"include_usage": True}),
                  claude_stream(claude_usage(1_000, 500, read=50_000, five_minute=6_000, one_hour=2_000)))
        self.assertAlmostEqual(self.row()["cost_usd"], 0.002)

    def test_lean_messages_record_cached_usage(self):
        self.send("/lean/v1/messages", self.chat(),
                  upstream(claude_message(claude_usage(1_000, 500, read=50_000, five_minute=6_000, one_hour=2_000))))
        self.assertAlmostEqual(self.row()["cost_usd"], 0.002)

    def test_lean_streamed_messages_record_cached_usage(self):
        self.send("/lean/v1/messages", self.chat(stream=True),
                  claude_stream(claude_usage(1_000, 500, read=50_000, five_minute=6_000, one_hour=2_000)))
        self.assertAlmostEqual(self.row()["cost_usd"], 0.002)

    def test_lean_streamed_responses_record_cached_usage(self):
        self.send("/lean/v1/responses", {"input": "Hi", "max_output_tokens": 64, "stream": True},
                  claude_stream(claude_usage(1_000, 500, read=50_000, five_minute=6_000, one_hour=2_000)))
        self.assertAlmostEqual(self.row()["cost_usd"], 0.002)

    def test_budgeted_key_spend_reduces_its_remaining_budget(self):
        with patch.object(self.app_module.AuthService, "get_current_user", return_value=ADMIN):
            self.app_module.AuthService.set_key_controls(
                "budgeted", {"daily_budget_usd": 1, "monthly_budget_usd": 5})
        for _ in range(2):
            self.send("/lean/v1/chat/completions", self.chat(), upstream(claude_message(claude_usage(6_000, 4_000))))
        self.assertTrue(usage_ledger.LEDGER.flush(timeout=5))
        summary = self.client.get("/v1/usage", headers={"Authorization": f"Bearer {self.key}"}).get_json()
        self.assertAlmostEqual(summary["totals"]["cost_usd"], 0.0052)
        self.assertEqual(summary["totals"]["priced_requests"], 2)
        self.assertAlmostEqual(summary["budget"]["daily_remaining_usd"], 1 - 0.0052)
        self.assertAlmostEqual(summary["budget"]["monthly_remaining_usd"], 5 - 0.0052)
