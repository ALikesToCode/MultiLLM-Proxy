"""Routed image judges exclude Gemini without changing ordinary chat routing."""
import json
import os
from unittest.mock import patch

import pytest
from flask import Response, g

from services.auto_route_service import AutoRouteService
from services.image_quality import QualityOptions
from services.judge_routing import judge_candidate_allowed
from tests import test_image_quality as qa_tests
from tests.test_free_routes import catalog_row
from tests.unified_api_test_case import UnifiedApiTestCase


def judge_response():
    return Response(json.dumps(qa_tests.completion(qa_tests.grade())), content_type="application/json")


class JudgeRoutingRoundTwoTest(UnifiedApiTestCase):
    generate = qa_tests.ImageQualityRoutesTest.generate

    def setUp(self):
        super().setUp()
        self.keys = {name: "synthetic-provider" for name in ("gguu", "opencode", "gemini", "openrouter", "cline-pass")}
        for name, side_effect in (("get_api_key", self.keys.get),
                                 ("get_api_keys", lambda provider: [self.keys[provider]] if provider in self.keys else [])):
            mock = patch.object(self.app_module.AuthService, name, side_effect=side_effect)
            mock.start()
            self.addCleanup(mock.stop)
        self.app.config.update(FREE_ROUTE_FREE_TIER_PROVIDERS="gemini", FREE_ROUTE_PROVIDER_ORDER="gemini,openrouter,cline-pass,opencode")

    def test_free_judge_excludes_gemini_and_opaque_routers_but_chat_does_not(self):
        rows = [catalog_row("gemini", "gemini-3.1-flash-lite", vision=True),
                catalog_row("openrouter", "google/GEMINI-synthetic:free", vision=True),
                catalog_row("cline-pass", "google/gemini-synthetic:free", vision=True),
                catalog_row("opencode", "mimo-v2.5-free", vision=True)]
        body = {"model": qa_tests.MODEL, "prompt": "square", "quality_check": True}
        with patch("services.free_model_policy.build_model_catalog", return_value=rows), \
             patch("routes.free_routes._try_candidate", side_effect=lambda *args: judge_response()) as dispatch:
            result, _, _, _ = self.generate([], body=body)
            assert result.status_code == 200
            assert result.get_json()["data"][0]["quality"]["score"] == 9
            assert dispatch.call_args.args[5].provider == "opencode"
            normal = self.client.post("/v1/chat/completions", headers=qa_tests.ADMIN,
                json={"model": "free:vision", "messages": [{"role": "user", "content": "square"}]})
            assert normal.status_code == 200
            assert dispatch.call_args.args[5].provider == "gemini"
            assert dispatch.call_count == 2

    def test_free_judge_no_safe_candidate_returns_judge_error(self):
        self.keys.pop("opencode")
        with patch("services.free_model_policy.build_model_catalog", return_value=[]), \
             patch("routes.free_routes._try_candidate") as dispatch:
            result, generations, _, _ = self.generate([], body={"model": qa_tests.MODEL, "prompt": "square", "quality_check": True})
            assert result.status_code == 200
            assert result.get_json()["data"][0]["quality"]["judge_error"] == "judge_error"
            assert len(generations) == 1
            dispatch.assert_not_called()

    def test_auto_judge_skips_gemini_candidate(self):
        AutoRouteService.save_route("auto:qa-review", ["gemini:gemini-3.1-flash-lite", qa_tests.JUDGE], self.app.config["API_BASE_URLS"])
        result, _, judges, forwarded = self.generate([9], options={"judge_model": "auto:qa-review"})
        assert result.status_code == 200
        assert result.get_json()["data"][0]["quality"]["score"] == 9
        assert [body["model"] for body in judges] == ["glm-5.2"]
        assert not any("googleapis" in url for url, _, _ in forwarded)

    def test_explicit_gemini_request_and_env_judges_are_allowed(self):
        for supplied in (True, False):
            model = "gemini:gemini-3.1-flash-lite"
            body = {"model": qa_tests.MODEL, "prompt": "square", "quality_check": {"judge_model": model} if supplied else True}
            with patch.dict(os.environ, {"IMAGE_QA_JUDGE_MODEL": model}), \
                 patch("routes.unified._dispatch_unified_chat_candidate", side_effect=lambda *args, **kwargs: judge_response()) as dispatch:
                result, _, _, _ = self.generate([], body=body)
                assert result.status_code == 200
                assert result.get_json()["data"][0]["quality"]["score"] == 9
                assert dispatch.call_args.args[4]["model"] == model

    def test_judge_local_switch_restored_after_failure_and_explicit_dispatch(self):
        from routes.image_quality import _judge
        with self.app.test_request_context("/v1/images/generations"):
            g.authenticated_user = {"username": "admin"}
            g.image_qa_exclude_gemini = True
            def dispatch(payload):
                assert g.image_qa_exclude_gemini is False
                return judge_response()
            quality, _ = _judge(qa_tests.image(), qa_tests.MODEL, "square", QualityOptions("gemini:synthetic"), dispatch)
            assert quality["score"] == 9
            assert g.image_qa_exclude_gemini is True
            g.image_qa_exclude_gemini = False
            def fail(payload):
                assert g.image_qa_exclude_gemini is True
                raise ValueError("synthetic")
            quality, _ = _judge(qa_tests.image(), qa_tests.MODEL, "square", QualityOptions("auto:qa-review"), fail)
            assert quality["judge_error"] == "judge_error"
            assert g.image_qa_exclude_gemini is False

    def test_all_candidate_forms_are_filtered_only_with_switch(self):
        with self.app.test_request_context():
            for model in ("gemini:other", "openrouter:google/GEMINI-synthetic:free", "cline-pass:google/gemini-synthetic:free", "openrouter:openrouter/free"):
                assert judge_candidate_allowed(model)
                g.image_qa_exclude_gemini = True
                assert not judge_candidate_allowed(model)
                g.image_qa_exclude_gemini = False
