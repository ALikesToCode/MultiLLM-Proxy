"""Wave 4 contracts through registered managed routes with synthetic upstreams."""

import importlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from unittest.mock import patch

from flask import g, has_request_context

from tests.unified_api_test_case import UnifiedApiTestCase
from tests.intelligence_fixtures import (
    IntelligenceApiTestCase,
    completion,
    upstream,
    frames,
)
from tests.test_managed_idempotency import Authority
from tests.test_protocol_routes import (
    ANTHROPIC_MESSAGE,
    RESPONSES_BODY,
    CHAT_STREAM,
    json_upstream,
    sse_upstream,
)


class ManagedPipelineTests(UnifiedApiTestCase):
    def setUp(self):
        with patch("config.load_runtime_env"):
            super().setUp()
        for flag in (
            "MANAGED_IDEMPOTENCY_ENABLED",
            "PROTOCOL_EXTRAS_ENABLED",
            "PROMPT_CACHE_AFFINITY_ENABLED",
            "USAGE_RESERVATIONS_ENABLED",
            "CONTENT_RETENTION_ENABLED",
            "GENERATION_CACHE_SHARED_ENABLED",
            "USAGE_LEDGER_ENABLED",
        ):
            os.environ[flag] = "false"
        os.environ["SESSION_TIER_MODE"] = "off"
        self.app.config["OUTPUT_SCHEMA_VALIDATION_ENABLED"] = False
        self.headers = {"Authorization": "Bearer admin-test-key"}
        from services.budget_service import BudgetService

        BudgetService.reset()
        self.addCleanup(BudgetService.reset)

    def post(self, body, path="/v1/chat/completions", text="ok", reply=None):
        with patch.object(
            self.app_module.ProxyService,
            "make_request",
            return_value=reply if reply is not None else self._chat_response(text),
        ) as send:
            response = self.client.post(path, json=body, headers=self.headers)
            response.get_data()
        return response, send

    def test_registered_validation_strips_option_and_rejects_output(self):
        self.app.config["OUTPUT_SCHEMA_VALIDATION_ENABLED"] = True
        body = {
            "model": "mimo:mimo-v2.5",
            "messages": [{"role": "user", "content": "test"}],
            "multillm_output_validation": {
                "mode": "strict",
                "schema": {"type": "integer"},
            },
        }
        response, send = self.post(body, text="invalid")
        assert response.status_code == 502
        assert response.json["error"]["code"] == "output_schema_violation"
        assert "multillm_output_validation" not in json.loads(
            send.call_args.kwargs["data"]
        )
        assert send.call_count == 1

    def test_registered_extras_strip_same_protocol_namespace(self):
        os.environ["PROTOCOL_EXTRAS_ENABLED"] = "true"
        body = {
            "model": "mimo:mimo-v2.5",
            "messages": [{"role": "user", "content": "test"}],
            "_multillm": {
                "protocol_extras": {"source_protocol": "chat", "fields": {"seed": 7}}
            },
        }
        response, send = self.post(body)
        assert response.status_code == 200
        upstream = json.loads(send.call_args.kwargs["data"])
        assert "_multillm" not in upstream and "seed" not in upstream

    def test_registered_option_order_and_explicit_tier_stripping(self):
        self.app.config["OUTPUT_SCHEMA_VALIDATION_ENABLED"] = True
        os.environ.update(PROTOCOL_EXTRAS_ENABLED="true", SESSION_TIER_MODE="sticky")
        body = {
            "model": "mimo:mimo-v2.5",
            "messages": [{"role": "user", "content": "test"}],
            "session_tier": {"untrusted": "explicit route"},
            "_multillm": {
                "protocol_extras": {"source_protocol": "chat", "fields": {"seed": 7}}
            },
            "multillm_output_validation": {
                "mode": "strict",
                "schema": {"type": "integer"},
            },
        }
        response, send = self.post(body, text="2")
        assert response.status_code == 200
        upstream = json.loads(send.call_args.kwargs["data"])
        assert (
            not {"_multillm", "session_tier", "multillm_output_validation"}
            & upstream.keys()
        )

    def test_flags_off_preserve_body_and_response(self):
        body = {
            "model": "mimo:mimo-v2.5",
            "messages": [{"role": "user", "content": "test"}],
            "multillm_output_validation": {"ignored": True},
            "_multillm": {"ignored": True},
            "session_tier": {"ignored": True},
        }
        response, send = self.post(body)
        assert (
            response.status_code == 200
            and response.data == self._chat_response().content
        )
        assert json.loads(send.call_args.kwargs["data"]) == {
            **body,
            "model": "mimo-v2.5",
        }

    def test_provider_submission_marks_accounting(self):
        accounting = importlib.import_module("services.request_accounting")
        with patch.object(accounting, "mark_dispatched") as handoff:
            response, send = self.post(
                {
                    "model": "mimo:mimo-v2.5",
                    "messages": [{"role": "user", "content": "test"}],
                }
            )
        assert (
            response.status_code == 200 and send.call_count == handoff.call_count == 1
        )

    def test_flags_off_native_protocol_bytes_and_provider_bodies(self):
        cases = (
            (
                "/v1/messages",
                {
                    "model": "opencode:minimax-m3",
                    "max_tokens": 10,
                    "messages": [{"role": "user", "content": "hi"}],
                },
                ANTHROPIC_MESSAGE,
            ),
            (
                "/v1/responses",
                {"model": "opencode:grok-4.6", "input": "hi"},
                RESPONSES_BODY,
            ),
        )
        for path, body, result in cases:
            with (
                self.subTest(path=path),
                patch.object(
                    self.app_module.ProxyService,
                    "make_request",
                    return_value=json_upstream(result),
                ) as send,
            ):
                response = self.client.post(path, json=body, headers=self.headers)
                assert response.status_code == 200
                assert response.data == json.dumps(result).encode()
                assert json.loads(send.call_args.kwargs["data"]) == {
                    **body,
                    "model": body["model"].split(":", 1)[1],
                }

    def test_flags_off_translated_protocol_body_and_stream_bytes(self):
        body = {
            "model": "opencode:minimax-m3",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 10,
        }
        with patch.object(
            self.app_module.ProxyService,
            "make_request",
            return_value=json_upstream(ANTHROPIC_MESSAGE),
        ) as send:
            response = self.client.post(
                "/v1/chat/completions", json=body, headers=self.headers
            )
        assert response.status_code == 200
        assert response.json["choices"][0]["message"]["content"] == "Bonjour"
        assert json.loads(send.call_args.kwargs["data"]) == {
            "model": "minimax-m3",
            "messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}],
            "max_tokens": 10,
        }
        streamed = {
            "model": "opencode:kimi-k2.6",
            "messages": body["messages"],
            "stream": True,
        }
        with patch.object(
            self.app_module.ProxyService,
            "make_request",
            return_value=sse_upstream(CHAT_STREAM),
        ) as send:
            response = self.client.post(
                "/v1/chat/completions", json=streamed, headers=self.headers
            )
            data = response.get_data()
        assert response.status_code == 200 and data == b"".join(CHAT_STREAM)
        assert json.loads(send.call_args.kwargs["data"]) == {
            **streamed,
            "model": "kimi-k2.6",
        }

    def test_native_validation_alone_runs_after_protocol_dispatch(self):
        self.app.config["OUTPUT_SCHEMA_VALIDATION_ENABLED"] = True
        cases = (
            (
                "/v1/messages",
                {
                    "model": "opencode:minimax-m3",
                    "max_tokens": 10,
                    "messages": [{"role": "user", "content": "hi"}],
                },
                ANTHROPIC_MESSAGE,
            ),
            (
                "/v1/responses",
                {"model": "opencode:grok-4.6", "input": "hi"},
                RESPONSES_BODY,
            ),
        )
        for path, body, result in cases:
            body["multillm_output_validation"] = {
                "mode": "strict",
                "schema": {"type": "integer"},
            }
            with (
                self.subTest(path=path),
                patch.object(
                    self.app_module.ProxyService,
                    "make_request",
                    return_value=json_upstream(result),
                ) as send,
            ):
                response = self.client.post(path, json=body, headers=self.headers)
                assert response.status_code == 502
                assert response.json["error"]["code"] == "output_schema_violation"
                assert "multillm_output_validation" not in json.loads(
                    send.call_args.kwargs["data"]
                )

    def enable_stack(self):
        from services.auto_route_service import AutoRouteService
        from services.idempotency_store import IdempotencyStore
        from services.shared_generation_cache import SharedGenerationCache
        from services import reservation_store

        os.environ.update(
            MANAGED_IDEMPOTENCY_ENABLED="true",
            PROTOCOL_EXTRAS_ENABLED="true",
            PROMPT_CACHE_AFFINITY_ENABLED="true",
            USAGE_RESERVATIONS_ENABLED="true",
            GENERATION_CACHE_SHARED_ENABLED="true",
            GENERATION_CACHE_BACKEND="d1-r2",
            RESPONSE_CACHE_ENABLED="true",
            CONTENT_RETENTION_ENABLED="true",
            SESSION_TIER_MODE="sticky",
        )
        os.environ["MODEL_PRICING_USD_PER_MILLION"] = json.dumps(
            {"mimo:mimo-v2.5": {"input": 1000, "output": 1000}}
        )
        self.reservations = reservation_store.SqlReservationStore(
            os.path.join(self.temp_dir.name, "wave4-usage.sqlite3")
        )
        storage = patch.object(reservation_store, "_store", self.reservations)
        storage.start()
        self.addCleanup(storage.stop)
        self.app.extensions["gateway_after_authentication"].append(
            lambda: g.authenticated_user.update(
                daily_budget_usd=1.0, monthly_budget_usd=5.0
            )
        )
        self.app.config["OUTPUT_SCHEMA_VALIDATION_ENABLED"] = True
        self.authority = Authority()
        self.app.extensions["managed_idempotency_store"] = IdempotencyStore(
            self.authority
        )
        self.admitted = []

        def after_admission():
            self.admitted.append(True)

        self.app.extensions["gateway_after_authentication"].append(after_admission)
        self.rows, self.cache_calls = {}, []

        def transport(value):
            self.cache_calls.append(value)
            identity = tuple(
                value[field]
                for field in ("principal_hash", "cache_key", "policy_hash", "model")
            )
            if value["operation"] == "get":
                return {"version": 1, "entry": self.rows.get(identity)}
            self.rows[identity] = {
                "body": value["body"],
                "metadata": value["metadata"],
                "age": 0,
            }
            return {"version": 1, "stored": True}

        self.app.extensions["shared_generation_cache"] = SharedGenerationCache(
            transport
        )
        importlib.import_module("routes.chat_cache").clear()
        AutoRouteService.save_route(
            "auto:wave4", ["mimo:mimo-v2.5"], self.app.config["API_BASE_URLS"]
        )
        self.headers.update({"X-MultiLLM-Cache": "on", "Idempotency-Key": "wave4-key"})
        return {
            "model": "auto:wave4",
            "messages": [{"role": "user", "content": "test"}],
            "temperature": 0,
            "max_tokens": 10,
            "session_tier": {"ignored": "non-intelligence"},
            "_multillm": {
                "protocol_extras": {"source_protocol": "chat", "fields": {"seed": 7}}
            },
            "multillm_output_validation": {
                "mode": "strict",
                "schema": {"type": "integer"},
            },
        }

    def test_combined_validation_failure_blocks_key_and_never_caches(self):
        body = self.enable_stack()
        response, send = self.post(body, text="invalid")
        assert response.status_code == 502 and send.call_count == 1
        assert (
            not {"session_tier", "_multillm", "multillm_output_validation"}
            & json.loads(send.call_args.kwargs["data"]).keys()
        )
        assert response.json["error"]["code"] == "output_schema_violation"
        assert not self.rows
        blocked, send = self.post(body, text="2")
        assert blocked.status_code == 409 and send.call_count == 0
        assert blocked.json["error"]["code"] == "outcome_unknown"
        assert (
            self.reservations.summary("admin", datetime.now(timezone.utc))["unknown"]
            == 1
        )

    def test_idempotency_alone_replays_registered_auto_route(self):
        body = self.enable_stack()
        os.environ.update(
            PROTOCOL_EXTRAS_ENABLED="false",
            PROMPT_CACHE_AFFINITY_ENABLED="false",
            USAGE_RESERVATIONS_ENABLED="false",
            GENERATION_CACHE_SHARED_ENABLED="false",
            CONTENT_RETENTION_ENABLED="false",
            SESSION_TIER_MODE="off",
        )
        self.app.config["OUTPUT_SCHEMA_VALIDATION_ENABLED"] = False
        for option in ("_multillm", "session_tier", "multillm_output_validation"):
            body.pop(option)
        self.headers.pop("X-MultiLLM-Cache")
        first, send = self.post(body)
        assert first.status_code == 200 and send.call_count == 1
        replay, send = self.post(body)
        assert replay.data == first.data and send.call_count == 0
        assert replay.headers["X-MultiLLM-Idempotency"] == "replayed"

    def test_shared_cache_alone_uses_registered_cache_position(self):
        body = self.enable_stack()
        os.environ.update(
            MANAGED_IDEMPOTENCY_ENABLED="false",
            PROTOCOL_EXTRAS_ENABLED="false",
            PROMPT_CACHE_AFFINITY_ENABLED="false",
            USAGE_RESERVATIONS_ENABLED="false",
            CONTENT_RETENTION_ENABLED="false",
            SESSION_TIER_MODE="off",
        )
        self.app.config["OUTPUT_SCHEMA_VALIDATION_ENABLED"] = False
        for option in ("_multillm", "session_tier", "multillm_output_validation"):
            body.pop(option)
        self.headers.pop("Idempotency-Key")
        first, send = self.post(body)
        assert first.status_code == 200 and send.call_count == 1
        hit, send = self.post(body)
        assert hit.data == first.data and send.call_count == 0
        assert hit.headers["X-MultiLLM-Cache-Backend"] == "d1-r2"

    def test_combined_cache_hit_completes_key_and_replay_skips_provider(self):
        body = self.enable_stack()
        first, send = self.post(body, text="2")
        assert first.status_code == 200 and send.call_count == 1
        assert self.rows
        self.headers["Idempotency-Key"] = "wave4-cache-key"
        hit, send = self.post(body, text="3")
        assert (
            hit.status_code == 200 and send.call_count == 0 and hit.data == first.data
        )
        assert hit.headers["X-MultiLLM-Cache"] == "hit"
        with sqlite3.connect(self.reservations.path) as database:
            assert (
                database.execute(
                    "SELECT count(*) FROM usage_reservations WHERE state='settled' AND basis='released' AND charged_units=0"
                ).fetchone()[0]
                == 1
            )
        before = self.reservations.summary("admin", datetime.now(timezone.utc))
        replay, send = self.post(body, text="4")
        assert (
            replay.headers["X-MultiLLM-Idempotency"] == "replayed"
            and send.call_count == 0
        )
        assert replay.data == hit.data
        assert len(self.admitted) == 2
        conflict, send = self.post({**body, "max_tokens": 11})
        assert conflict.status_code == 422 and send.call_count == 0
        assert len(self.admitted) == 2
        operations = [value["operation"] for value in self.authority.calls]
        assert operations.count("complete") == 2
        summary = self.reservations.summary("admin", datetime.now(timezone.utc))
        assert summary == before
        assert summary["unknown"] == 1 and summary["held_usd"] > 0

    def test_combined_zero_retention_stores_no_replay_or_cache(self):
        body = self.enable_stack()
        self.headers["X-MultiLLM-Retention"] = "zero"
        first, send = self.post(body, text="2")
        assert first.status_code == 200 and send.call_count == 1
        assert not self.rows
        assert all(
            row["status"] == "unknown" and "response" not in row
            for row in self.authority.rows.values()
        )
        retry, send = self.post(body)
        assert retry.status_code == 409 and send.call_count == 0

    def test_combined_unknown_completion_never_caches_or_replays(self):
        body = self.enable_stack()
        body.pop("multillm_output_validation")
        result = completion("partial")
        result["choices"][0]["finish_reason"] = "length"
        with patch.object(
            self.app_module.ProxyService, "make_request", return_value=upstream(result)
        ):
            first = self.client.post(
                "/v1/chat/completions", json=body, headers=self.headers
            )
        assert first.status_code == 200 and not self.rows
        retry, send = self.post(body)
        assert retry.status_code == 409 and send.call_count == 0

    def test_combined_schema_failure_preserves_measured_provider_spend(self):
        body = self.enable_stack()
        response, send = self.post(body, reply=upstream(completion("invalid")))
        assert response.status_code == 502 and send.call_count == 1 and not self.rows
        summary = self.reservations.summary("admin", datetime.now(timezone.utc))
        assert summary["held_usd"] == 0 and summary["spent_today_usd"] == 0.006

    def test_combined_deadline_before_submission_releases_hold(self):
        body = self.enable_stack()
        from services.generation_deadline import Deadline

        def expire():
            g.generation_deadline = Deadline(1, clock=lambda: 2)

        self.app.extensions["gateway_after_authentication"].append(expire)
        response, send = self.post(body, text="2")
        assert response.status_code == 504 and send.call_count == 0 and not self.rows
        assert response.json["error"]["code"] == "generation_deadline_exceeded"
        assert (
            self.reservations.summary("admin", datetime.now(timezone.utc))["held_usd"]
            == 0
        )

    def test_combined_deadline_after_submission_retains_hold_and_blocks_key(self):
        body = self.enable_stack()
        from services.generation_deadline import Deadline

        ticks = [0]

        def install():
            g.generation_deadline = Deadline(1, clock=lambda: ticks[0])

        self.app.extensions["gateway_after_authentication"].append(install)

        def late(*args, **kwargs):
            ticks[0] = 2
            return upstream(completion("2"))

        with patch.object(
            self.app_module.ProxyService, "make_request", side_effect=late
        ) as send:
            response = self.client.post(
                "/v1/chat/completions", json=body, headers=self.headers
            )
        assert response.status_code == 504 and send.call_count == 1 and not self.rows
        summary = self.reservations.summary("admin", datetime.now(timezone.utc))
        assert summary["unknown"] == 1 and summary["held_usd"] > 0
        ticks[0] = 0
        blocked, send = self.post(body)
        assert blocked.status_code == 409 and send.call_count == 0

    def test_combined_cancellation_after_handoff_keeps_hold_and_blocks_key(self):
        body = self.enable_stack()
        from services.request_cancellation import (
            CancellationContext,
            RequestCancellation,
        )

        def cancelled(*args, **kwargs):
            owner = RequestCancellation()
            context = CancellationContext(lambda: None)
            context.handoff()
            owner.bind(context)
            owner.cancel()
            g.gateway_cancellation = owner
            return upstream(completion("2"))

        with patch.object(
            self.app_module.ProxyService, "make_request", side_effect=cancelled
        ) as send:
            response = self.client.post(
                "/v1/chat/completions", json=body, headers=self.headers
            )
        assert response.status_code == 200
        assert send.call_count == 1 and not self.rows
        blocked, send = self.post(body)
        assert blocked.status_code == 409 and send.call_count == 0
        summary = self.reservations.summary("admin", datetime.now(timezone.utc))
        assert summary["unknown"] == 1 and summary["held_usd"] > 0

    def test_reservations_alone_settle_measured_usage(self):
        from services import reservation_store

        os.environ.update(
            USAGE_RESERVATIONS_ENABLED="true",
            MODEL_PRICING_USD_PER_MILLION=json.dumps(
                {"mimo:mimo-v2.5": {"input": 1000, "output": 1000}}
            ),
        )
        store = reservation_store.SqlReservationStore(
            os.path.join(self.temp_dir.name, "single-usage.sqlite3")
        )
        self.app.extensions["gateway_after_authentication"].append(
            lambda: g.authenticated_user.update(
                daily_budget_usd=1.0, monthly_budget_usd=5.0
            )
        )
        with patch.object(reservation_store, "_store", store):
            response, send = self.post(
                {
                    "model": "mimo:mimo-v2.5",
                    "max_tokens": 10,
                    "messages": [{"role": "user", "content": "test"}],
                },
                reply=upstream(completion()),
            )
            summary = store.summary("admin", datetime.now(timezone.utc))
        assert response.status_code == 200 and send.call_count == 1
        assert summary["spent_today_usd"] == 0.006 and summary["held_usd"] == 0

    def test_deadline_alone_bounds_timeout_and_preserves_success(self):
        from services.generation_deadline import Deadline

        self.app.extensions["gateway_after_authentication"].append(
            lambda: setattr(g, "generation_deadline", Deadline(1, clock=lambda: 0))
        )
        response, send = self.post(
            {
                "model": "mimo:mimo-v2.5",
                "messages": [{"role": "user", "content": "test"}],
            }
        )
        assert response.status_code == 200
        timeout = send.call_args.kwargs["timeout_override"]
        assert all(value <= 0.5 for value in timeout)


class IntelligenceManagedTests(IntelligenceApiTestCase):
    def setUp(self):
        with patch("config.load_runtime_env"):
            super().setUp()
        os.environ.update(
            MANAGED_IDEMPOTENCY_ENABLED="false",
            PROTOCOL_EXTRAS_ENABLED="false",
            PROMPT_CACHE_AFFINITY_ENABLED="false",
            USAGE_RESERVATIONS_ENABLED="false",
            GENERATION_CACHE_SHARED_ENABLED="false",
            SESSION_TIER_MODE="off",
        )
        self.app.config["OUTPUT_SCHEMA_VALIDATION_ENABLED"] = False
        self.seed()
        from services import session_tiers, prompt_cache_affinity

        self.lanes = session_tiers.LocalSessionTierStore()
        self.app.extensions["session_tier_store"] = self.lanes
        self.affinities = prompt_cache_affinity.PromptCacheAffinity()
        storage = patch.object(prompt_cache_affinity, "store", self.affinities)
        storage.start()
        self.addCleanup(storage.stop)

    def test_session_tier_alone_constrains_selection_and_strips_metadata(self):
        os.environ["SESSION_TIER_MODE"] = "sticky"
        with self.requests(return_value=upstream(completion())) as send:
            result = self.post(
                session_tier={
                    "session": "synthetic-session",
                    "lane": "main",
                    "approved_model": "navyai:large",
                    "approved_tier": 2,
                }
            )
        assert (
            result.status_code == 200
            and send.call_args.kwargs["api_provider"] == "navyai"
        )
        assert "session_tier" not in json.loads(send.call_args.kwargs["data"])
        assert next(iter(self.lanes.rows.values()))["safe_turn"] is True

    def test_affinity_alone_binds_only_classified_completion(self):
        os.environ["PROMPT_CACHE_AFFINITY_ENABLED"] = "true"
        with self.requests(return_value=upstream(completion())) as send:
            result = self.post(
                messages=[
                    {"role": "system", "content": "synthetic reusable prefix"},
                    {"role": "user", "content": "test"},
                ]
            )
        assert result.status_code == 200 and send.call_count == 1
        assert len(self.affinities) == 1
        assert self.affinities.entries()[0][1].model == "openai:small"

    def test_stream_submission_carries_accounting_outside_request_context(self):
        from services.budget_service import BudgetService

        os.environ["USAGE_RESERVATIONS_ENABLED"] = "true"
        observed = []
        stream = frames(
            {
                "choices": [
                    {"index": 0, "delta": {"content": "ok"}, "finish_reason": None}
                ]
            },
            {
                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                "usage": {
                    "prompt_tokens": 4,
                    "completion_tokens": 2,
                    "total_tokens": 6,
                },
            },
            "[DONE]",
        )
        with (
            patch.object(
                BudgetService,
                "mark_dispatched",
                side_effect=lambda reservation: observed.append(has_request_context()),
            ),
            self.requests(return_value=upstream(chunks=stream)) as send,
        ):
            response = self.post(stream=True)
            data = response.get_data()
        assert response.status_code == 200 and send.call_count == 1
        assert b"[DONE]" in data and False in observed

    def test_tier_and_affinity_finalize_after_outer_validation(self):
        os.environ.update(
            SESSION_TIER_MODE="sticky",
            PROMPT_CACHE_AFFINITY_ENABLED="true",
            PROTOCOL_EXTRAS_ENABLED="true",
        )
        self.app.config["OUTPUT_SCHEMA_VALIDATION_ENABLED"] = True
        with self.requests(return_value=upstream(completion("invalid"))) as send:
            result = self.post(
                messages=[
                    {"role": "system", "content": "synthetic reusable prefix"},
                    {"role": "user", "content": "test"},
                ],
                session_tier={
                    "session": "synthetic-session",
                    "lane": "main",
                    "approved_model": "openai:small",
                    "approved_tier": 1,
                },
                _multillm={
                    "protocol_extras": {
                        "source_protocol": "chat",
                        "fields": {"seed": 7},
                    }
                },
                multillm_output_validation={
                    "mode": "strict",
                    "schema": {"type": "integer"},
                },
            )
        assert result.status_code == 502 and send.call_count == 1
        assert result.json["error"]["code"] == "output_schema_violation"
        assert len(self.affinities) == 0
        assert next(iter(self.lanes.rows.values()))["safe_turn"] is False
        assert (
            not {"session_tier", "_multillm", "multillm_output_validation"}
            & json.loads(send.call_args.kwargs["data"]).keys()
        )
