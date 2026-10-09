"""Concurrent image pipelines preserve order, admission controls and accounting."""
import base64
import json
import os
import threading
from functools import partial
from unittest.mock import patch

from flask import Response, g

from error_handlers import APIError
from routes.media_images import IMAGE_PARALLELISM, run_image_tasks
from routes.unified_images import generation_headers
from services import usage_ledger
from services.budget_service import BudgetDecision, BudgetService
from tests import test_image_quality as qa_tests
from tests.unified_api_test_case import UnifiedApiTestCase


class ParallelRoundTwoTest(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        os.environ.update({"USAGE_LEDGER_ENABLED": "true", "USAGE_LEDGER_BACKEND": "sql",
                           "USAGE_LEDGER_FLUSH_SECONDS": "300", "USAGE_DB_PATH": os.path.join(self.temp_dir.name, "usage.sqlite3"),
                           "MODEL_PRICING_USD_PER_MILLION": json.dumps({"gguu:*": {"request": 0.04}})})
        usage_ledger.LEDGER.reset()
        BudgetService.reset()
        for name, result in (("get_api_key", "synthetic-provider"), ("get_api_keys", ["synthetic-provider"])):
            mock = patch.object(self.app_module.AuthService, name, return_value=result)
            mock.start()
            self.addCleanup(mock.stop)

    def tearDown(self):
        usage_ledger.LEDGER.reset()
        BudgetService.reset()
        super().tearDown()

    def test_pipeline_overlap_order_deterministic_keys_and_ledger(self):
        seen = []
        for round_number in range(2):
            generating = threading.Barrier(2)
            judging = threading.Barrier(2)
            calls = []
            def raw(*args, **kwargs):
                body, headers = args[4], kwargs["request_headers"]
                key = headers["Idempotency-Key"]
                if "Avoid:" in body["prompt"]:
                    number = 3
                else:
                    number = 1 if key == "synthetic-request" else 2
                    generating.wait(timeout=5)
                calls.append((number, key))
                return Response(json.dumps({"data": [qa_tests.image(number)]}), content_type="application/json")
            def judge(*args, **kwargs):
                body = args[4]
                source = body["messages"][1]["content"][1]["image_url"]["url"]
                number = int(base64.b64decode(source.split(",", 1)[1])[-1:])
                if number != 3:
                    judging.wait(timeout=5)
                score = {1: 9, 2: 3, 3: 8}[number]
                return Response(json.dumps(qa_tests.completion(qa_tests.grade(score))), content_type="application/json")
            with patch("routes.unified_images.dispatch_image_generation_raw", side_effect=raw), \
                 patch("routes.unified._dispatch_unified_chat_candidate", side_effect=judge):
                result = self.client.post("/v1/images/generations", headers={**qa_tests.ADMIN, "Idempotency-Key": "synthetic-request"},
                    json={"model": qa_tests.MODEL, "prompt": "square", "n": 2, "quality_check": {"judge_model": qa_tests.JUDGE}})
            assert result.status_code == 200
            entries = result.get_json()["data"]
            assert [item["b64_json"] for item in entries] == [qa_tests.image(1)["b64_json"], qa_tests.image(3)["b64_json"]]
            assert [item["quality"]["attempts"] for item in entries] == [1, 2]
            assert len(calls) == len({key for _, key in calls}) == 3
            seen.append(sorted(calls))
            assert usage_ledger.LEDGER.flush(timeout=5)
            rows = usage_ledger.LEDGER.store().recent("2000-01-01T00:00:00.000Z", "admin", None, 50)
            assert len(rows) == (round_number + 1) * 6
            assert sum(row["kind"] == "images" for row in rows) == (round_number + 1) * 3
            assert sum(row["kind"] == "chat" for row in rows) == (round_number + 1) * 3
            assert all(row["principal"] == "admin" and row["request_id"] for row in rows)
        assert seen[0] == seen[1]

    def test_budget_stop_reported_on_every_generated_image(self):
        judging = threading.Barrier(3)
        lock = threading.Lock()
        calls = 0
        def reserve(*args):
            nonlocal calls
            with lock:
                calls += 1
                return BudgetDecision(True) if calls <= 7 else BudgetDecision(False, error="budget_exceeded", status_code=429, message="Synthetic budget")
        def raw(*args, **kwargs):
            return Response(json.dumps({"data": [qa_tests.image()]}), content_type="application/json")
        def judge(*args, **kwargs):
            judging.wait(timeout=5)
            return Response(json.dumps(qa_tests.completion(qa_tests.grade(3))), content_type="application/json")
        with patch("services.request_accounting.budgeted", return_value=True), \
             patch.object(BudgetService, "check_and_reserve", side_effect=reserve), \
             patch("routes.unified_images.dispatch_image_generation_raw", side_effect=raw) as generate, \
             patch("routes.unified._dispatch_unified_chat_candidate", side_effect=judge):
            result = self.client.post("/v1/images/generations", headers=qa_tests.ADMIN,
                json={"model": qa_tests.MODEL, "prompt": "square", "n": 3, "quality_check": {"judge_model": qa_tests.JUDGE}})
        assert result.status_code == 200
        assert generate.call_count == 3
        assert [item["quality"]["stopped_reason"] for item in result.get_json()["data"]] == ["budget_exceeded"] * 3
        assert [item["quality"]["attempts"] for item in result.get_json()["data"]] == [1] * 3

    def test_allowance_stop_reported_on_every_generated_image(self):
        from services.rate_limit_service import LimitDecision
        def rate(*args, **kwargs):
            return (LimitDecision(False, error="daily_limit_exceeded", status_code=429, message="Synthetic allowance")
                    if "Avoid:" in (kwargs.get("payload_json") or {}).get("prompt", "") else LimitDecision(True))
        with patch("services.rate_limit_service.RateLimitService.enforce_request", side_effect=rate), \
             patch("services.accounted_dispatch.RateLimitService.enforce_request", side_effect=rate), \
             patch("routes.unified_images.dispatch_image_generation_raw", side_effect=lambda *args, **kwargs: Response(json.dumps({"data": [qa_tests.image()]}), content_type="application/json")) as generate, \
             patch("routes.unified._dispatch_unified_chat_candidate", side_effect=lambda *args, **kwargs: Response(json.dumps(qa_tests.completion(qa_tests.grade(3))), content_type="application/json")):
            result = self.client.post("/v1/images/generations", headers=qa_tests.ADMIN,
                json={"model": qa_tests.MODEL, "prompt": "square", "n": 3, "quality_check": {"judge_model": qa_tests.JUDGE}})
        assert result.status_code == 200
        assert generate.call_count == 3
        assert [item["quality"]["stopped_reason"] for item in result.get_json()["data"]] == ["daily_limit_exceeded"] * 3

    def test_batch_preserves_per_image_initial_refusals(self):
        import importlib

        qa_routes = importlib.import_module("routes.image_quality")
        original = qa_routes._one_image
        def pipeline(*args):
            if args[-1] == 1:
                raise APIError("Synthetic budget", 429, payload={"error": "budget_exceeded"})
            return original(*args)
        with patch.object(qa_routes, "_one_image", side_effect=pipeline), \
             patch("routes.unified_images.dispatch_image_generation_raw", side_effect=lambda *args, **kwargs: Response(json.dumps({"data": [qa_tests.image()]}), content_type="application/json")), \
             patch("routes.unified._dispatch_unified_chat_candidate", side_effect=lambda *args, **kwargs: Response(json.dumps(qa_tests.completion(qa_tests.grade(9))), content_type="application/json")):
            result = self.client.post("/v1/images/batch", headers=qa_tests.ADMIN,
                json={"quality_check": {"judge_model": qa_tests.JUDGE},
                      "items": [{"model": qa_tests.MODEL, "prompt": "square", "n": 2}]})
        assert result.status_code == 200
        item = result.get_json()["data"][0]
        assert item["status"] == "succeeded"
        assert len(item["images"]) == 1
        assert "stopped_reason" not in item["images"][0]["quality"]
        assert item["errors"][0]["index"] == 1
        assert item["errors"][0]["stopped_reason"] == "budget_exceeded"

    def test_context_controls_and_parallelism_bound(self):
        barrier = threading.Barrier(IMAGE_PARALLELISM)
        active = 0
        maximum = 0
        lock = threading.Lock()
        with self.app.test_request_context("/v1/images/generations"):
            controls = {"authenticated_user": {"username": "synthetic"}, "rate_limit": {"limit": 1},
                        "request_id": "synthetic-context", "usage_context": None, "request_started_at": 123,
                        "multillm_model": "synthetic:model", "multillm_provider": "synthetic", "multillm_route_decision": "test",
                        "judge_exclude_gemini": False}
            for name, value in controls.items():
                setattr(g, name, value)
            def task(index):
                nonlocal active, maximum
                assert {name: getattr(g, name) for name in controls} == controls
                with lock:
                    active += 1
                    maximum = max(maximum, active)
                if index < IMAGE_PARALLELISM:
                    barrier.wait(timeout=5)
                with lock:
                    active -= 1
                return {"index": index}
            results = run_image_tasks([partial(task, i) for i in range(IMAGE_PARALLELISM + 2)], read_response=False)
            assert results == [{"index": i} for i in range(IMAGE_PARALLELISM + 2)]
            assert maximum == IMAGE_PARALLELISM
            assert {name: getattr(g, name) for name in controls} == controls


def test_generation_keys_are_unique_per_image_and_attempt():
    headers = {"Idempotency-Key": "synthetic-request", "X-MultiLLM-Image-QA": "on"}
    keys = [generation_headers(headers, index, attempt)["Idempotency-Key"] for index in range(3) for attempt in range(3)]
    assert len(set(keys)) == 9
    assert keys == [generation_headers(headers, index, attempt)["Idempotency-Key"] for index in range(3) for attempt in range(3)]
    assert "X-MultiLLM-Image-QA" not in generation_headers(headers)
