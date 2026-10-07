"""Defensive judge parsing and explicit QA opt-out regressions."""
import json
import os
from unittest.mock import patch

import pytest
from flask import g

from error_handlers import APIError
from services import image_quality, usage_ledger
from services.budget_service import BudgetService
from tests.test_image_quality import MODEL, JUDGE, grade


@pytest.mark.parametrize("wrapper", ["{}", "  ```json\n{}\n```  ", "\n```\n{}\n```\n"])
def test_defensive_grade_variants(wrapper):
    value = grade()
    value.pop("text_accuracy")
    value.update(score="8.5", prompt_adherence="9", artifacts="10", extra="ignored")
    result = image_quality.parse_grade(wrapper.format(json.dumps(value)), "expected")
    assert result["score"] <= 8.5
    assert result["text_accuracy"] is None
    assert "extra" not in result


def test_grade_truncates_strings_and_filters_issues():
    value = grade(text="x" * 3000, fixes="x" * 500)
    value["issues"] = [None, 1] + ["x" * 300] * 8
    result = image_quality.parse_grade(json.dumps(value), "")
    assert result["issues"] == ["x" * 200] * 5
    assert len(result["fix_instructions"]) == 300
    assert len(result["visible_text"]) == 2000


@pytest.mark.parametrize("value", [None, True, "NaN", "inf", "bad", -1, 11, "11"])
def test_invalid_score_rejected(value):
    body = grade()
    body["score"] = value
    with pytest.raises(ValueError):
        image_quality.parse_grade(json.dumps(body), "")


@pytest.mark.parametrize("content", ["[]", "null", "no json", '{}', '{"score":1,"score":2}',
                                     json.dumps(grade()) + " " * 8192])
def test_remaining_contract_rejections(content):
    with pytest.raises(ValueError):
        image_quality.parse_grade(content, "")


from tests import test_image_quality as qa_tests
from tests.unified_api_test_case import UnifiedApiTestCase


class ContractRoundTwoTest(UnifiedApiTestCase):
    generate = qa_tests.ImageQualityRoutesTest.generate

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

    def test_provider_url_judged_without_storage_write(self):
        from tests.test_image_quality import completion
        from flask import Response
        with patch("services.media_storage.fetch_public", return_value=(b"\x89PNG\r\n\x1a\nsynthetic", "image/png")) as fetch, \
             patch("services.media_storage.put_bytes") as put, \
             patch("services.media_storage.store_image_entries") as store:
            with self.app.test_request_context("/v1/images/generations"):
                g.authenticated_user = {"username": "admin"}
                from routes.image_quality import _judge
                quality, _ = _judge({"url": "https://provider.example/image"}, MODEL, "square",
                    image_quality.QualityOptions(JUDGE),
                    lambda body: Response(json.dumps(completion(grade())), content_type="application/json"))
            assert quality["score"] == 9
            fetch.assert_called_once_with("https://provider.example/image", max_bytes=image_quality.media_storage.MAX_IMAGE_BYTES)
            put.assert_not_called()
            store.assert_not_called()

    def test_provider_url_signed_fallback_stores_only_once(self):
        huge = b"\x89PNG\r\n\x1a\n" + b"x" * image_quality.MAX_INLINE_BYTES
        with self.app.test_request_context("/v1/images/generations"):
            g.authenticated_user = {"username": "admin"}
            with patch("services.media_storage.fetch_public", return_value=(huge, "image/png")), \
                 patch("services.media_storage.enabled", return_value=True), \
                 patch("services.image_quality._reduce", side_effect=ValueError()), \
                 patch("services.media_storage.put_bytes") as put, \
                 patch("services.media_storage.file_url", return_value="https://gateway.example/signed"):
                assert image_quality.image_source({"url": "https://provider.example/image"}, MODEL) == ("https://gateway.example/signed", True)
                assert put.call_count == 1
                assert put.call_args.kwargs["owner"] == "admin"

    def test_retry_prompt_falls_back_to_issues_or_original(self):
        for issues, suffix in [(["Wrong color"], "\n\nAvoid: Wrong color"), ([], "")]:
            value = grade(3, fixes="")
            value["issues"] = issues
            response, generations, _, _ = self.generate([value, 9])
            assert response.status_code == 200
            assert generations[1]["prompt"] == "A blue square" + suffix
