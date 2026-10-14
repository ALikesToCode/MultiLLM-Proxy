"""Optional generation screening uses synthetic text and provider replies only."""

import io
import json
from pathlib import Path
from unittest.mock import patch

import pytest
from flask import Flask, Response, g

from services.child_safety import moderation_decision
from services.child_safety_inputs import generation_kind, generation_texts
from services.child_safety_settings import SafetyError, SafetySettingsStore
from services.intelligence_d1_store import PrivateIntelligenceError
from tests.test_media_audio import upstream
from tests.unified_api_test_case import UnifiedApiTestCase

ADMIN = {"Authorization": "Bearer admin-test-key"}
PROMPT = "A synthetic prompt marker."


def moderation(flagged=False, *, other=False, count=1):
    return {"model": "omni-moderation-latest", "results": [
        {"flagged": flagged or other, "categories": {"sexual": other, "sexual/minors": flagged},
         "category_scores": {"sexual/minors": 0.9 if flagged else 0.01}} for _ in range(count)]}


def test_settings_persist_and_stale_saves_cannot_overwrite(tmp_path):
    first = SafetySettingsStore(tmp_path / "safety.db")
    second = SafetySettingsStore(tmp_path / "safety.db")
    assert first.get().as_dict() == {"enabled": False, "failure_mode": "allow", "revision": 0}
    saved = first.configure({"enabled": True, "failure_mode": "block", "revision": 0})
    assert second.get(fresh=True) == saved
    with pytest.raises(SafetyError) as error:
        second.configure({"enabled": False, "failure_mode": "allow", "revision": 0})
    assert error.value.status == 409
    assert first.get(fresh=True) == saved
    for value in (None, {}, {"enabled": "yes", "failure_mode": "allow", "revision": 1},
                  {"enabled": True, "failure_mode": "ignore", "revision": 1},
                  {"enabled": True, "failure_mode": "block", "revision": True},
                  {**saved.as_dict(), "prompt": PROMPT}):
        with pytest.raises(SafetyError):
            first.configure(value)
    assert first.get(fresh=True) == saved


def test_d1_outage_retains_known_policy_and_cold_starts_refuse_unknown_policy(tmp_path):
    store = SafetySettingsStore(tmp_path / "unused.db")
    known = {"enabled": True, "failure_mode": "block", "revision": 3}
    with patch("services.child_safety_settings.control_state_d1.using_d1", return_value=True), \
            patch("services.child_safety_settings.control_state_d1.call", return_value={"settings": known}) as call:
        assert store.get().as_dict() == known
        call.assert_called_once_with("safety", "get")
        store._checked_at = 0
        call.side_effect = PrivateIntelligenceError(503, "storage_unavailable")
        assert store.get().as_dict() == known
        with pytest.raises(SafetyError) as error:
            store.get(fresh=True)
        assert error.value.code == "safety_settings_unavailable"
        with pytest.raises(SafetyError):
            SafetySettingsStore(tmp_path / "another.db").get()
        call.side_effect = PrivateIntelligenceError(409, "safety_settings_conflict")
        with pytest.raises(SafetyError) as error:
            store.configure(known)
        assert error.value.status == 409
    assert not (tmp_path / "unused.db").exists()


def test_d1_save_requires_a_matching_commit_receipt_and_keeps_known_policy(tmp_path):
    store = SafetySettingsStore(tmp_path / "unused.db")
    known = {"enabled": True, "failure_mode": "block", "revision": 3}
    wanted = {"enabled": False, "failure_mode": "allow", "revision": 3}
    with patch("services.child_safety_settings.control_state_d1.using_d1", return_value=True), \
            patch("services.child_safety_settings.control_state_d1.call", return_value={"settings": known}) as call:
        assert store.get().as_dict() == known
        for receipt in ({}, {**wanted, "revision": 3}, {**known, "revision": 4},
                        {**wanted, "revision": 4, "prompt": PROMPT}):
            call.return_value = {"settings": receipt}
            with pytest.raises(SafetyError) as error:
                store.configure(wanted)
            assert error.value.status == 503
            assert store.get().as_dict() == known
        call.return_value = {"settings": {**wanted, "revision": 4}}
        assert store.configure(wanted).as_dict() == {**wanted, "revision": 4}


def test_only_latest_user_text_is_extracted_without_images_or_tool_results():
    image = {"type": "image_url", "image_url": {"url": "https://example.com/private-marker.png"}}
    messages = [{"role": "system", "content": "System marker"}, {"role": "user", "content": "Earlier marker"},
                {"role": "user", "content": [{"type": "text", "text": "First"}, image,
                                               {"type": "text", "text": "Second"}]},
                {"role": "assistant", "content": "Output marker"}, {"role": "tool", "content": "Tool marker"}]
    assert generation_texts("completions", {"messages": messages}) == ["First\nSecond"]
    assert generation_texts("responses", {"input": messages}) == ["First\nSecond"]
    assert generation_texts("responses", {"input": [{"type": "input_text", "text": "A"}, image]}) == ["A"]
    assert generation_texts("responses", {"input": "B"}) == ["B"]
    assert generation_texts("batch", {"defaults": {"prompt": "Default"}, "items": [{}, {"prompt": "Override"}]}) == ["Default", "Override"]
    assert generation_texts("images", {"image": image}, {"prompt": "Edit"}) == ["Edit"]
    assert generation_kind("/openai/v1/images/edits") == "images"
    assert generation_kind("/optimize/v1/chat/completions") == "completions"
    assert generation_kind("/v1/moderations") is None
    assert generation_kind("/v1/videos/job/content") is None


def test_child_safety_requires_explicit_boolean_category_for_every_input():
    assert moderation_decision(moderation(other=True), 1) == (False, 0.01)
    assert moderation_decision(moderation(True), 1) == (True, 0.9)
    for body in ({}, {"results": []}, {"results": [{"flagged": False}]},
                 {"results": [{"categories": {"sexual/minors": 0}}]},
                 {"results": [{"categories": {"sexual/minors": False}, "category_scores": {"sexual/minors": float("nan")}}]}):
        with pytest.raises(SafetyError):
            moderation_decision(body, 1)


@pytest.mark.parametrize("unavailable", [False, True])
def test_moderation_cleanup_cannot_dispatch_or_settle_generation_reservation(unavailable):
    # Route fixtures reload modules; use the current transport and accounting objects.
    from routes import safety
    from services import request_accounting
    from services.request_cancellation import bind_cancellation

    app = Flask(__name__)
    context = request_accounting.UsageContext("chat", ["openai:gpt-test"], "openai", {}, 0, 0,
                                              reservation="generation-held", credit_hold=object())

    def moderate(*args):
        reply = Response(b"synthetic")
        cancellation = bind_cancellation(reply)
        g.request_id = "screen-only"
        reply.close()
        assert cancellation.outcome.ambiguous
        if unavailable:
            raise SafetyError("moderation_unavailable")
        return moderation()

    with app.test_request_context("/v1/chat/completions", method="POST"):
        g.usage_context, g.request_id = context, "generation-request"
        with patch.object(safety, "_check_text", side_effect=moderate), \
                patch.object(request_accounting, "mark_dispatched") as mark:
            if unavailable:
                with pytest.raises(SafetyError):
                    safety.check_text([PROMPT], app, None, None, None)
            else:
                assert safety.check_text([PROMPT], app, None, None, None) == moderation()
        mark.assert_not_called()
        assert g.usage_context is context
        assert g.request_id == "generation-request"
        assert not context.dispatched and not context.ambiguous and not context.finished


class ChildSafetyRouteTest(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        self.screen = self.app.extensions["child_safety"]
        self.screen.store = SafetySettingsStore(Path(self.temp_dir.name) / "screen.db")
        keys = {"openai": "synthetic-openai", "navyai": "synthetic-navy"}
        for name, value in {"get_api_key": lambda provider: keys.get(provider),
                            "get_api_keys": lambda provider: [keys[provider]] if provider in keys else []}.items():
            patcher = patch.object(self.app_module.AuthService, name, side_effect=value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def enable(self, failure_mode="allow"):
        self.screen.store.configure({"enabled": True, "failure_mode": failure_mode, "revision": 0})

    def post(self, path="/v1/chat/completions", replies=None, **kwargs):
        if not kwargs:
            kwargs["json"] = {"model": "openai:gpt-test", "messages": [{"role": "user", "content": PROMPT}]}
        with patch.object(self.app_module.ProxyService, "make_request", side_effect=replies or []) as transport:
            response = self.client.post(path, headers=ADMIN, **kwargs)
        return response, transport

    def test_default_off_does_not_call_moderation(self):
        response, transport = self.post(replies=[self._chat_response()])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(transport.call_count, 1)
        self.assertNotIn("moderations", transport.call_args.kwargs["url"])
        self.assertNotIn("X-MultiLLM-Child-Safety", response.headers)

    def test_flagged_category_blocks_generation_and_audits_metadata(self):
        self.enable()
        with patch("services.child_safety.audit_log.record") as audit, self.assertLogs("services.child_safety", level="INFO") as logs:
            response, transport = self.post(replies=[upstream(200, moderation(True))])
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["error"]["code"], "child_safety_blocked")
        self.assertEqual(transport.call_count, 1)
        self.assertEqual(response.headers["X-MultiLLM-Child-Safety"], "blocked")
        self.assertRegex(audit.call_args.kwargs["actor"], r"^[0-9a-f]{64}$")
        self.assertEqual(json.loads(audit.call_args.kwargs["detail"])["reason"], "sexual_minors")
        self.assertNotIn(PROMPT, repr(audit.call_args))
        self.assertNotIn(PROMPT, " ".join(logs.output))

    def test_other_flags_allow_generation_without_changing_model(self):
        self.enable()
        response, transport = self.post(replies=[upstream(200, moderation(other=True)), self._chat_response()])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-MultiLLM-Child-Safety"], "passed")
        self.assertEqual(json.loads(transport.call_args_list[0].kwargs["data"])["input"], [PROMPT])
        self.assertEqual(json.loads(transport.call_args_list[1].kwargs["data"])["model"], "gpt-test")

    def test_timeout_allows_and_logs_by_default_without_replaying_moderation(self):
        self.enable()
        with self.assertLogs("services.child_safety", level="INFO") as logs:
            response, transport = self.post(replies=[
                upstream(502, {"error": "Private failure marker"}, multillm_transport_failure="timeout"), self._chat_response()])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-MultiLLM-Child-Safety"], "unavailable-allowed")
        self.assertEqual(transport.call_count, 2)
        self.assertNotIn("Private failure marker", " ".join(logs.output))

    def test_block_mode_refuses_unavailable_or_incomplete_results(self):
        self.enable("block")
        for reply in (upstream(502, {}, multillm_transport_failure="timeout"), upstream(200, {"results": [{"flagged": False}]})):
            response, transport = self.post(replies=[reply])
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response.get_json()["error"]["code"], "child_safety_unavailable")
            self.assertEqual(transport.call_count, 1)

    def test_definite_refusal_can_fail_over_before_generation(self):
        self.enable()
        response, transport = self.post(replies=[upstream(429, {}), upstream(200, moderation()), self._chat_response()])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(transport.call_count, 3)
        self.assertIn("api.navy/v1/moderations", transport.call_args_list[1].kwargs["url"])

    def test_protocol_and_native_routes_are_screened(self):
        self.enable()
        for path, body in (("/v1/responses", {"model": "openai:gpt-test", "input": PROMPT}),
                           ("/openai/v1/responses", {"model": "gpt-test", "input": PROMPT}),
                           ("/v1/messages", {"model": "openai:gpt-test", "messages": [{"role": "user", "content": PROMPT}]}),
                           ("/anthropic/v1/messages", {"model": "claude-test", "messages": [{"role": "user", "content": PROMPT}]}),
                           ("/groq/openai/v1/chat/completions", {"model": "gpt-test", "messages": [{"role": "user", "content": PROMPT}]}),
                           ("/v1/free/chat/completions", {"messages": [{"role": "user", "content": PROMPT}]}),
                           ("/v1/free/balanced/chat/completions", {"messages": [{"role": "user", "content": PROMPT}]}),
                           ("/intelligence/v1/chat/completions", {"messages": [{"role": "user", "content": PROMPT}]}),
                           ("/optimize/v1/chat/completions", {"model": "openai:gpt-test", "messages": [{"role": "user", "content": PROMPT}]}),
                           ("/v1/videos", {"model": "openai:video-test", "prompt": PROMPT})):
            with self.subTest(path=path):
                response, transport = self.post(path, [upstream(200, moderation(True))], json=body)
                self.assertEqual(response.status_code, 403, response.get_data(as_text=True))
                self.assertEqual(transport.call_count, 1)

    def test_audit_outage_does_not_change_the_screen_decision_or_log_content(self):
        self.enable()
        with patch("services.child_safety.audit_log.record", side_effect=RuntimeError(PROMPT)), \
                self.assertLogs("services.child_safety", level="INFO") as logs:
            response, transport = self.post(replies=[upstream(200, moderation(True))])
        self.assertEqual(response.status_code, 403)
        self.assertEqual(transport.call_count, 1)
        self.assertNotIn(PROMPT, " ".join(logs.output))

    def test_multipart_and_batches_send_text_only(self):
        self.enable()
        response, transport = self.post("/v1/images/edits", [upstream(200, moderation(True))],
            data={"model": "openai:gpt-image-test", "prompt": PROMPT, "image": (io.BytesIO(b"synthetic"), "test.png")})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(json.loads(transport.call_args.kwargs["data"])["input"], [PROMPT])
        for path in ("/v1/images/batch", "/v1/images/batches"):
            response, transport = self.post(path, [upstream(200, moderation(True, count=2))], json={
                "defaults": {"model": "openai:gpt-image-test", "prompt": PROMPT}, "items": [{}, {"prompt": "Override"}]})
            self.assertEqual(response.status_code, 403)
            self.assertEqual(json.loads(transport.call_args.kwargs["data"])["input"], [PROMPT, "Override"])

    def test_standalone_moderation_is_not_recursively_screened(self):
        self.enable()
        response, transport = self.post("/v1/moderations", [upstream(200, moderation(True))], json={"input": PROMPT})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(transport.call_count, 1)

    def test_streaming_generation_starts_after_successful_screen(self):
        self.enable()
        event = b'data: {"choices":[{"delta":{"content":"ok"}}]}\n\ndata: [DONE]\n\n'
        response, transport = self.post(replies=[upstream(200, moderation()), upstream(200, event, "text/event-stream")],
            json={"model": "openai:gpt-test", "messages": [{"role": "user", "content": PROMPT}], "stream": True})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"[DONE]", response.get_data())
        self.assertEqual(transport.call_count, 2)

    def test_settings_require_admin_session_csrf_and_matching_revision(self):
        auth = self.app_module.AuthService
        with patch.object(auth, "is_authenticated", return_value=False):
            self.assertEqual(self.client.get("/admin/safety").status_code, 401)
        with patch.object(auth, "is_authenticated", return_value=True), patch.object(auth, "get_current_user", return_value={"is_admin": False}):
            self.assertEqual(self.client.get("/admin/safety").status_code, 403)
        with patch.object(auth, "is_authenticated", return_value=True), patch.object(auth, "get_current_user", return_value={"is_admin": True, "username": "owner"}):
            settings = self.client.get("/admin/safety").get_json()["settings"]
            self.assertFalse(settings["enabled"])
            response = self.client.post("/admin/safety", json={**settings, "enabled": True})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers["Cache-Control"], "no-store")
            self.assertEqual(self.client.post("/admin/safety", json=settings).status_code, 409)
            self.app.config["WTF_CSRF_ENABLED"] = True
            self.assertEqual(self.client.post("/admin/safety", json=settings).status_code, 400)
