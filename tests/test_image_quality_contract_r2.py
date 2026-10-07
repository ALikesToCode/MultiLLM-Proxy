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
