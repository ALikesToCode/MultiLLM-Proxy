"""Image QA contracts and accounted generation/judge journeys with synthetic providers."""

import base64
import io
import json
import os
import threading
from unittest.mock import patch

import pytest
import requests
from flask import Response
from PIL import Image

from error_handlers import APIError
from services import image_quality, usage_ledger
from services.budget_service import BudgetDecision, BudgetService
from tests.unified_api_test_case import UnifiedApiTestCase

ADMIN = {"Authorization": "Bearer admin-test-key"}
MODEL = "gguu:gpt-image-2.5-sunburst"
JUDGE = "opencode:glm-5.2"


def image(number=1):
    return {"b64_json": base64.b64encode(b"\x89PNG\r\n\x1a\nsynthetic" + str(number).encode()).decode()}


def grade(score=9, text=None, fixes="Correct the lettering"):
    return {"score": score, "prompt_adherence": score, "text_accuracy": score if text is not None else None,
            "artifacts": 10, "visible_text": text, "issues": [] if score >= 7 else ["Poor lettering"],
            "fix_instructions": fixes}


def upstream(body, status=200):
    response = requests.Response()
    response.status_code = status
    response._content = json.dumps(body).encode()
    response._content_consumed = True
    response.headers["Content-Type"] = "application/json"
    return response


def completion(value):
    return {"choices": [{"message": {"content": json.dumps(value) if isinstance(value, dict) else value}}],
            "usage": {"prompt_tokens": 13, "completion_tokens": 17}}


@pytest.mark.parametrize("value", [None, "on", 1, [], {"extra": 1}, {"min_score": True},
                                  {"min_score": float("nan")}, {"min_score": 11}, {"min_score": -1},
                                  {"max_attempts": 0}, {"max_attempts": 4}, {"max_attempts": 1.5},
                                  {"max_attempts": True}, {"criteria": ["x"] * 6}, {"criteria": ["x" * 201]},
                                  {"criteria": [1]}, {"criteria": "x"}, {"judge_model": ""}])
def test_invalid_options(value):
    with pytest.raises(APIError) as error:
        image_quality.parse_options({"quality_check": value})
    assert error.value.status_code == 400


def test_defaults_header_and_curly_quote_scoring():
    assert image_quality.parse_options({}) is None
    options = image_quality.parse_options({}, "on")
    assert (options.judge_model, options.min_score, options.max_attempts) == ("free:vision", 7, 2)
    assert image_quality.expected_text('Write “Hello” and ‘World’') == "Hello World"
    assert image_quality.expected_text('Write “Hello\nWorld”') == "Hello\nWorld"
    assert image_quality.expected_text('Write "Hello" and \'World\'') == "Hello World"
    assert image_quality.expected_text("A person's portrait") == ""
    result = image_quality.parse_grade(json.dumps(grade(9, "Helo World")), "Hello World")
    assert result["score"] == 9
    assert image_quality.parse_grade(json.dumps(grade(10, "Goodbye")), "Hello World")["score"] < 7
    assert image_quality.text_similarity("ＦＯＯ  Bar", "foo bar") == 1
    assert len(image_quality._normalize("ﬃ" * 2000)) == image_quality.MAX_TEXT_CHARS
    assert image_quality.parse_options({"quality_check": {"criteria": [""]}}).criteria == ("",)
    assert image_quality.parse_options({}, "off") is None


@pytest.mark.parametrize("content", ['```json\n{}\n```', '{}', '{"score": NaN}', '{"score":1,"score":2}', '[]'])
def test_malformed_judge(content):
    with pytest.raises(ValueError):
        image_quality.parse_grade(content, "")


def test_image_source_reduces_large_bytes_without_new_libraries():
    pixels = os.urandom(1200 * 1200 * 3)
    output = io.BytesIO()
    Image.frombytes("RGB", (1200, 1200), pixels).save(output, format="PNG")
    assert len(output.getvalue()) > image_quality.MAX_INLINE_BYTES
    source, signed = image_quality.image_source({"b64_json": base64.b64encode(output.getvalue()).decode()}, MODEL)
    assert source.startswith("data:image/jpeg;base64,") and not signed
    assert len(base64.b64decode(source.split(",", 1)[1])) <= image_quality.MAX_INLINE_BYTES


def test_judge_content_limit_counts_utf8_bytes():
    value = grade(9, "\U0001f600" * 2000)
    value["issues"] = ["\U0001f600" * 200] * 5
    with pytest.raises(ValueError):
        image_quality.parse_grade(json.dumps(value, ensure_ascii=False), "")


class ImageQualityRoutesTest(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        os.environ.update({"USAGE_LEDGER_ENABLED": "true", "USAGE_LEDGER_BACKEND": "sql",
                           "USAGE_LEDGER_FLUSH_SECONDS": "300",
                           "USAGE_DB_PATH": os.path.join(self.temp_dir.name, "usage.sqlite3"),
                           "MODEL_PRICING_USD_PER_MILLION": json.dumps({"gguu:*": {"request": 0.04},
                                                                       "opencode:*": {"input": 1, "output": 1}})})
        usage_ledger.LEDGER.reset()
        BudgetService.reset()
        keys = {"gguu": "synthetic-image-provider", "opencode": "synthetic-chat-provider"}
        for name, side_effect in (("get_api_key", lambda provider: keys.get(provider)),
                                  ("get_api_keys", lambda provider: [keys[provider]] if provider in keys else [])):
            patcher = patch.object(self.app_module.AuthService, name, side_effect=side_effect)
            patcher.start()
            self.addCleanup(patcher.stop)

    def tearDown(self):
        usage_ledger.LEDGER.reset()
        BudgetService.reset()
        super().tearDown()

    def generate(self, scores, *, model=MODEL, options=None, prompt="A blue square", n=1, headers=None,
                 path="/v1/images/generations", body=None):
        generations, judges, forwarded = [], [], []
        values = iter(scores)

        def transport(**kwargs):
            payload = json.loads(kwargs["data"])
            forwarded.append((kwargs["url"], payload, kwargs["headers"]))
            if kwargs["url"].endswith("images/generations"):
                generations.append(payload)
                number = len(generations)
                if isinstance(scores, dict):
                    number = (3 if "Avoid:" in payload["prompt"] else
                              1 if kwargs["headers"].get("Idempotency-Key") == "synthetic-order" else 2)
                return upstream({"created": 1, "data": [image(number)]})
            judges.append(payload)
            if isinstance(scores, dict):
                source = payload["messages"][1]["content"][1]["image_url"]["url"]
                number = int(base64.b64decode(source.split(",", 1)[1])[-1:])
                value = scores[number]
            else:
                value = next(values)
            if isinstance(value, Exception):
                raise value
            return upstream(completion(grade(value) if isinstance(value, (int, float)) else value))

        payload = body or {"model": model, "prompt": prompt, "n": n,
                           "quality_check": {"judge_model": JUDGE, **(options or {})}}
        with patch.object(self.app_module.ProxyService, "make_request", side_effect=transport):
            response = self.client.post(path, headers={**ADMIN, **(headers or {})}, json=payload, buffered=True)
        return response, generations, judges, forwarded

    def test_pass_first_try_and_every_call_accounted_with_usage(self):
        response, generations, judges, forwarded = self.generate([9])
        self.assertEqual(response.status_code, 200)
        quality = response.get_json()["data"][0]["quality"]
        self.assertEqual((quality["score"], quality["passed"], quality["attempts"]), (9, True, 1))
        self.assertEqual(response.headers[image_quality.QA_HEADER], "attempts=1 best=9")
        self.assertEqual((len(generations), len(judges)), (1, 1))
        self.assertTrue(judges[0]["messages"][1]["content"][1]["image_url"]["url"].startswith("data:image/png;base64,"))
        self.assertTrue(all("quality_check" not in payload for _, payload, _ in forwarded))
        self.assertTrue(usage_ledger.LEDGER.flush(timeout=5))
        rows = usage_ledger.LEDGER.store().recent("2000-01-01T00:00:00.000Z", "admin", None, 50)
        self.assertEqual(len(rows), 2)
        judge_row = next(row for row in rows if row["kind"] == "chat")
        self.assertEqual((judge_row["input_tokens"], judge_row["output_tokens"]), (13, 17))
        self.assertEqual(judge_row["selected_model"], JUDGE)
        self.assertEqual(next(row for row in rows if row["kind"] == "images")["cost_usd"], 0.04)

    def test_retry_improves_and_pins_automatic_route(self):
        response, generations, judges, _ = self.generate([4, 9], model="auto:image")
        self.assertEqual(response.status_code, 200)
        entry = response.get_json()["data"][0]
        self.assertEqual(entry["b64_json"], image(2)["b64_json"])
        self.assertEqual(entry["quality"]["attempts"], 2)
        self.assertTrue(entry["quality"]["passed"])
        self.assertEqual([body["model"] for body in generations], ["gpt-image-2.5-sunburst"] * 2)
        self.assertEqual(generations[1]["prompt"], "A blue square\n\nAvoid: Correct the lettering")
        self.assertEqual(generations[1]["quality"], "max")
        self.assertEqual(len(judges), 2)
        self.assertTrue(usage_ledger.LEDGER.flush(timeout=5))
        self.assertEqual(len(usage_ledger.LEDGER.store().recent("2000-01-01T00:00:00.000Z", "admin", None, 50)), 4)

    def test_best_image_kept_and_attempts_are_bounded(self):
        response, generations, judges, _ = self.generate([5, 3, 4], options={"max_attempts": 3})
        entry = response.get_json()["data"][0]
        self.assertEqual(entry["b64_json"], image(1)["b64_json"])
        self.assertEqual((entry["quality"]["score"], entry["quality"]["attempts"]), (5, 3))
        self.assertFalse(entry["quality"]["passed"])
        self.assertEqual((len(generations), len(judges)), (3, 3))
        response, generations, judges, _ = self.generate([2], options={"max_attempts": 1})
        self.assertEqual(response.get_json()["data"][0]["quality"]["attempts"], 1)
        self.assertEqual((len(generations), len(judges)), (1, 1))

    def test_multiple_images_retry_only_the_failing_image(self):
        response, generations, judges, _ = self.generate({1: 9, 2: 3, 3: 8}, n=2, headers={"Idempotency-Key": "synthetic-order"})
        entries = response.get_json()["data"]
        self.assertEqual([entry["quality"]["attempts"] for entry in entries], [1, 2])
        self.assertEqual([entry["b64_json"] for entry in entries], [image(1)["b64_json"], image(3)["b64_json"]])
        self.assertEqual((len(generations), len(judges)), (3, 3))
        self.assertEqual(response.headers[image_quality.QA_HEADER], "attempts=3 best=9")

    def test_judge_failure_and_malformed_json_return_the_image(self):
        for failure in (requests.exceptions.ConnectionError("synthetic"), "not json", '{}'):
            response, generations, judges, _ = self.generate([failure])
            self.assertEqual(response.status_code, 200)
            entry = response.get_json()["data"][0]
            self.assertEqual(entry["b64_json"], image(1)["b64_json"])
            self.assertEqual(entry["quality"]["judge_error"], "judge_error")
            self.assertEqual((len(generations), len(judges)), (1, 1))

    def test_curly_quoted_text_lowers_the_score(self):
        response, _, _, _ = self.generate([grade(10, "Goodbye")], prompt="Write “Hello World”",
                                          options={"max_attempts": 1})
        quality = response.get_json()["data"][0]["quality"]
        self.assertLess(quality["score"], 7)
        self.assertFalse(quality["passed"])
        self.assertAlmostEqual(quality["text_similarity"], image_quality.text_similarity("Hello World", "Goodbye"))

    def test_header_enables_default_free_vision_and_is_validated(self):
        import routes.unified as unified

        with patch.object(unified, "dispatch_unified_chat_completion",
                          return_value=Response(json.dumps(completion(grade(9))), content_type="application/json")) as judge:
            response, generations, _, forwarded = self.generate([], headers={image_quality.QA_HEADER: "on"},
                body={"model": MODEL, "prompt": "A square"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(judge.call_args.args[4]["model"], "free:vision")
        self.assertTrue(all(image_quality.QA_HEADER.lower() not in {key.lower() for key in headers}
                            for _, _, headers in forwarded))
        response, generations, _, _ = self.generate([], headers={image_quality.QA_HEADER: "invalid"})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(generations)

    def test_invalid_model_and_options_fail_before_generation(self):
        for options in ({"max_attempts": 4}, {"judge_model": "missing"}, {"judge_model": "free:unknown"}):
            response, generations, _, _ = self.generate([], options=options)
            self.assertEqual(response.status_code, 400, response.get_json())
            self.assertFalse(generations)

    def test_judge_obeys_the_key_model_allowlist(self):
        with patch.object(self.app_module.AuthService, "get_current_user", return_value={"username": "admin", "is_admin": True}):
            key = self.app_module.AuthService.create_user("image-only", scopes=["chat"])["api_key"]
            self.app_module.AuthService.set_key_controls("image-only", {"allowed_models": ["gguu:*"]})
        response, generations, _, _ = self.generate([], headers={"Authorization": f"Bearer {key}"})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(generations)

    def test_budget_stop_keeps_the_first_image(self):
        decisions = iter([BudgetDecision(True), BudgetDecision(True), BudgetDecision(True),
                          BudgetDecision(False, error="budget_exceeded", status_code=429, message="Synthetic budget spent")])
        with patch("services.accounted_dispatch.budgeted", return_value=True), \
             patch("services.request_accounting.budgeted", return_value=True), \
             patch.object(BudgetService, "check_and_reserve", side_effect=lambda *args: next(decisions)):
            response, generations, judges, _ = self.generate([3])
        self.assertEqual(response.status_code, 200)
        quality = response.get_json()["data"][0]["quality"]
        self.assertEqual((quality["attempts"], quality["stopped_reason"]), (1, "budget_exceeded"))
        self.assertEqual((len(generations), len(judges)), (1, 1))

    def test_batch_route_and_top_level_validation(self):
        body = {"quality_check": {"judge_model": JUDGE}, "defaults": {"model": MODEL},
                "items": [{"prompt": "A square", "id": "one"}]}
        response, generations, judges, _ = self.generate([3, 9], path="/v1/images/batch", body=body)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["data"][0]["images"][0]["quality"]["attempts"], 2)
        self.assertEqual(response.headers[image_quality.QA_HEADER], "attempts=2 best=9")
        self.assertEqual((len(generations), len(judges)), (2, 2))
        self.assertTrue(usage_ledger.LEDGER.flush(timeout=5))
        rows = usage_ledger.LEDGER.store().recent("2000-01-01T00:00:00.000Z", "admin", None, 50)
        self.assertEqual(len(rows), 4)
        self.assertTrue(all(row["principal"] == "admin" for row in rows))
        body["quality_check"] = {"criteria": ["x"] * 6}
        response, generations, _, _ = self.generate([], path="/v1/images/batch", body=body)
        self.assertEqual(response.status_code, 400)
        self.assertFalse(generations)

    def test_budget_stop_reports_partial_multi_image_result(self):
        import importlib

        qa_routes = importlib.import_module("routes.image_quality")

        completed = threading.Event()
        original = qa_routes._one_image
        def ordered(*args):
            if args[-1]:
                self.assertTrue(completed.wait(timeout=5))
            result = original(*args)
            if not args[-1]:
                completed.set()
            return result
        decisions = iter([BudgetDecision(True)] * 3 + [
            BudgetDecision(False, error="budget_exceeded", status_code=429, message="Synthetic budget spent")])
        with patch("services.accounted_dispatch.budgeted", return_value=True), \
             patch("services.request_accounting.budgeted", return_value=True), \
             patch.object(qa_routes, "_one_image", side_effect=ordered), \
             patch.object(BudgetService, "check_and_reserve", side_effect=lambda *args: next(decisions)):
            response, generations, judges, _ = self.generate([9], n=2)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("stopped_reason", response.get_json()["data"][0]["quality"])
        self.assertEqual(response.get_json()["errors"][0]["index"], 1)
        self.assertEqual(response.get_json()["errors"][0]["stopped_reason"], "budget_exceeded")
        self.assertEqual(response.headers["X-MultiLLM-Images-Returned"], "1")
        self.assertEqual((len(generations), len(judges)), (1, 1))

    def test_mixed_batch_accounts_both_paths_and_reserves_non_qa_image_units(self):
        body = {"defaults": {"model": MODEL}, "items": [
            {"prompt": "A square", "quality_check": {"judge_model": JUDGE}},
            {"prompt": "Two circles", "n": 2}]}
        with patch("services.accounted_dispatch.budgeted", return_value=True), \
             patch.object(BudgetService, "check_and_reserve", return_value=BudgetDecision(True)) as reserve:
            response, generations, judges, _ = self.generate([9], path="/v1/images/batch", body=body)
        self.assertEqual(response.status_code, 200)
        self.assertIn(0.08, [call.args[1] for call in reserve.call_args_list])
        self.assertEqual((len(generations), len(judges)), (2, 1))
        items = response.get_json()["data"]
        self.assertIn("quality", items[0]["images"][0])
        self.assertNotIn("quality", items[1]["images"][0])
        self.assertTrue(usage_ledger.LEDGER.flush(timeout=5))
        rows = usage_ledger.LEDGER.store().recent("2000-01-01T00:00:00.000Z", "admin", None, 50)
        self.assertEqual(len(rows), 3)
        self.assertTrue(all(row["principal"] == "admin" for row in rows))

    def test_idempotency_key_changes_for_a_new_take(self):
        response, _, _, forwarded = self.generate([3, 9], headers={"Idempotency-Key": "synthetic-request"})
        self.assertEqual(response.status_code, 200)
        keys = [headers.get("Idempotency-Key") for url, _, headers in forwarded if url.endswith("images/generations")]
        self.assertEqual(keys[0], "synthetic-request")
        self.assertNotEqual(keys[0], keys[1])

    def test_rate_allowance_stop_keeps_generated_image(self):
        from services.rate_limit_service import LimitDecision

        admitted = LimitDecision(True)
        refused = LimitDecision(False, error="daily_limit_exceeded", status_code=429, message="Synthetic allowance")
        decisions = iter([admitted, admitted, refused])
        limit = lambda *args, **kwargs: next(decisions)
        with patch("services.rate_limit_service.RateLimitService.enforce_request", side_effect=limit), \
             patch("services.accounted_dispatch.RateLimitService.enforce_request", side_effect=limit):
            response, generations, judges, _ = self.generate([3])
        self.assertEqual(response.status_code, 200)
        quality = response.get_json()["data"][0]["quality"]
        self.assertEqual(quality["stopped_reason"], "daily_limit_exceeded")
        self.assertEqual((len(generations), len(judges)), (1, 1))

    def test_retry_judge_error_keeps_previously_graded_best(self):
        response, _, _, _ = self.generate([5, "malformed"])
        entry = response.get_json()["data"][0]
        self.assertEqual(entry["b64_json"], image(1)["b64_json"])
        self.assertEqual((entry["quality"]["score"], entry["quality"]["attempts"]), (5, 2))
        self.assertNotIn("judge_error", entry["quality"])
        self.assertEqual(entry["quality"]["stopped_reason"], "judge_error")

    def test_retry_judge_budget_stop_is_reported(self):
        decisions = iter([BudgetDecision(True)] * 4 + [
            BudgetDecision(False, error="budget_exceeded", status_code=429, message="Synthetic budget spent")])
        with patch("services.accounted_dispatch.budgeted", return_value=True), \
             patch("services.request_accounting.budgeted", return_value=True), \
             patch.object(BudgetService, "check_and_reserve", side_effect=lambda *args: next(decisions)):
            response, generations, judges, _ = self.generate([3])
        self.assertEqual(response.status_code, 200)
        quality = response.get_json()["data"][0]["quality"]
        self.assertEqual((quality["score"], quality["attempts"], quality["stopped_reason"]),
                         (3, 2, "budget_exceeded"))
        self.assertNotIn("judge_error", quality)
        self.assertEqual((len(generations), len(judges)), (2, 1))

    def test_qa_header_is_allowed_and_exposed_by_flask(self):
        response = self.client.options("/v1/images/generations", headers={"Origin": "https://client.invalid"})
        self.assertIn(image_quality.QA_HEADER, response.headers["Access-Control-Allow-Headers"])
        self.assertIn(image_quality.QA_HEADER, response.headers["Access-Control-Expose-Headers"])

    def test_signed_url_fallback_and_owned_storage_bytes(self):
        from flask import g

        file_id = "mf_" + "a" * 32
        with self.app.test_request_context("/v1/images/generations"):
            g.authenticated_user = {"username": "admin"}
            with patch("services.media_storage.enabled", return_value=True), \
                 patch("services.media_storage.stat", return_value={"owner": "admin", "kind": "image"}), \
                 patch("services.media_storage.read_file", return_value=b"\x89PNG\r\n\x1a\nsynthetic"):
                source, signed = image_quality.image_source({"file_id": file_id}, MODEL)
                self.assertTrue(source.startswith("data:image/png;base64,"))
                self.assertFalse(signed)
            with patch("services.media_storage.enabled", return_value=True), \
                 patch("services.media_storage.stat", return_value={"owner": "someone-else", "kind": "image"}), \
                 patch("services.media_storage.read_file") as read:
                with self.assertRaises(ValueError):
                    image_quality.image_source({"file_id": file_id}, MODEL)
                read.assert_not_called()
            huge = b"\x89PNG\r\n\x1a\n" + b"x" * image_quality.MAX_INLINE_BYTES
            with patch("services.media_storage.enabled", return_value=True), \
                 patch("services.image_quality._reduce", side_effect=ValueError("synthetic")), \
                 patch("services.media_storage.new_file_id", return_value=file_id), \
                 patch("services.media_storage.put_bytes", return_value={"size": len(huge)}) as put, \
                 patch("services.media_storage.file_url", return_value="https://gateway.example/signed-image"):
                source, signed = image_quality.image_source({"b64_json": base64.b64encode(huge).decode(),
                                                            "file_id": "mf_" + "b" * 32}, MODEL)
                self.assertEqual(source, "https://gateway.example/signed-image")
                self.assertTrue(signed)
                self.assertEqual(put.call_args.args[0], file_id)
                self.assertEqual(put.call_args.kwargs["owner"], "admin")

    def test_asynchronous_batch_submission_execution_and_grade_persistence(self):
        from services import media_signing

        os.environ.update({"MEDIA_JOBS_ENABLED": "true", "MEDIA_STORAGE_ENABLED": "true"})
        batch_id = "imgbatch_" + "a" * 32
        job = {"id": batch_id, "status": "queued", "created_at": 1, "item_count": 1, "counts": {}}
        with patch("services.media_jobs.call", return_value={"version": 1, "job": job}) as submit:
            response = self.client.post("/v1/images/batches", headers={**ADMIN, image_quality.QA_HEADER: "on"},
                                        json={"items": [{"model": MODEL, "prompt": "A square"}],
                                              "quality_check": {"judge_model": JUDGE}})
        self.assertEqual(response.status_code, 200)
        item = submit.call_args.kwargs["items"][0]["request"]
        self.assertEqual(item["quality_check"]["judge_model"], JUDGE)
        principal = media_signing.issue_principal("batch", batch_id, "admin", 60)
        with patch("services.media_storage.put_bytes", return_value={"size": 20, "content_type": "image/png"}):
            result, generations, judges, _ = self.generate([9], path="/internal/media/batch-items",
                headers={"Authorization": f"MultiLLM-Principal {principal}"},
                body={"job_id": batch_id, "items": [{"index": 0, "request": item}]})
        self.assertEqual(result.status_code, 200)
        files = result.get_json()["results"][0]["files"]
        self.assertEqual(files[0]["quality"]["score"], 9)
        self.assertEqual((len(generations), len(judges)), (1, 1))
        with patch("services.media_jobs.call", return_value={"version": 1, "has_more": False,
                "items": [{"index": 0, "custom_id": "0", "status": "succeeded", "files": files, "model": MODEL}]}):
            result = self.client.get(f"/v1/images/batches/{batch_id}/results", headers=ADMIN)
        self.assertEqual(result.get_json()["data"][0]["images"][0]["quality"]["score"], 9)
        self.assertTrue(usage_ledger.LEDGER.flush(timeout=5))
        self.assertEqual(len(usage_ledger.LEDGER.store().recent("2000-01-01T00:00:00.000Z", "admin", None, 50)), 2)
