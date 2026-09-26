"""Asynchronous image batches, their internal item endpoint and media webhooks."""

import hashlib
import json
import os
import re
from unittest.mock import patch

import requests

from error_handlers import APIError
from services import media_jobs, media_signing
from services.auto_route_service import AutoRouteService
from services.video_generation import issue_job_id
from tests.unified_api_test_case import UnifiedApiTestCase

KEYS = {"gguu": "gguu-test-key", "openai": "openai-test-key"}
ADMIN = {"Authorization": "Bearer admin-test-key"}


def upstream(status, body):
    response = requests.Response()
    response.status_code = status
    response._content = json.dumps(body).encode()
    response._content_consumed = True
    response.headers["Content-Type"] = "application/json"
    return response


def job(**overrides):
    return {"id": "imgbatch_" + "a" * 32, "kind": "image_batch", "owner": "admin", "status": "queued", "item_count": 2,
            "counts": {"queued": 2, "running": 0, "succeeded": 0, "failed": 0, "cancelled": 0}, "webhook_url": None,
            "webhook_status": None, "metadata": {}, "result": None, "created_at": 1, "started_at": None,
            "completed_at": None, **overrides}


class MediaBatchTest(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        os.environ.update({"MEDIA_JOBS_ENABLED": "true", "MEDIA_STORAGE_ENABLED": "true"})
        for name, value in {
            "get_api_key": lambda provider: KEYS.get(provider),
            "get_api_keys": lambda provider: [KEYS[provider]] if provider in KEYS else [],
        }.items():
            patcher = patch.object(self.app_module.AuthService, name, side_effect=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        AutoRouteService.save_route("auto:image-test", ["gguu:gpt-image-2"], self.app.config["API_BASE_URLS"])
        self.calls = []

    def jobs(self, replies):
        def call(operation, **fields):
            self.calls.append((operation, fields))
            reply = replies[operation]
            if isinstance(reply, Exception):
                raise reply
            return reply(fields) if callable(reply) else reply
        return patch("services.media_jobs.call", side_effect=call)

    def create(self, body, headers=None):
        with self.jobs({"create_batch": lambda fields: {"version": 1, "created": True, "job": job(
                id=fields["id"], item_count=len(fields["items"]), webhook_url=fields["webhook_url"],
                webhook_status="pending" if fields["webhook_url"] else None, metadata=fields["metadata"])}}):
            return self.client.post("/v1/images/batches", headers={**ADMIN, **(headers or {})}, json=body)

    def test_batches_need_the_workflow_d1_and_r2(self):
        os.environ.pop("MEDIA_STORAGE_ENABLED")
        with self.jobs({}) as call:
            for response in (self.client.post("/v1/images/batches", headers=ADMIN, json={"items": [{"prompt": "x"}]}),
                             self.client.get("/v1/images/batches", headers=ADMIN)):
                self.assertEqual(response.status_code, 503)
                self.assertEqual(response.get_json()["error"], "batches_not_configured")
        call.assert_not_called()

    def test_a_batch_is_validated_stored_and_signed_for_its_owner(self):
        response = self.create({
            "defaults": {"model": "auto:image-test", "size": "1024x1024", "response_format": "b64_json"},
            "items": [{"id": "hero", "prompt": "A skyline", "n": 2}, {"prompt": "An icon", "model": "gguu:gpt-image-2"}],
            "webhook_url": "https://hooks.example.com/multillm?team=7", "metadata": {"project": "launch"}})
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        operation, fields = self.calls[0]
        self.assertEqual(operation, "create_batch")
        self.assertRegex(fields["id"], r"^imgbatch_[a-f0-9]{32}$")
        self.assertEqual(fields["owner"], "admin")
        self.assertEqual(fields["items"], [
            {"custom_id": "hero", "request": {"model": "auto:image-test", "size": "1024x1024", "prompt": "A skyline", "n": 2}},
            {"custom_id": "1", "request": {"model": "gguu:gpt-image-2", "size": "1024x1024", "prompt": "An icon"}}])
        claims = media_signing.read_principal(fields["principal"], "batch")
        self.assertEqual((claims["s"], claims["o"]), (fields["id"], "admin"))
        self.assertRegex(fields["request_digest"], r"^[a-f0-9]{64}$")
        body = response.get_json()
        self.assertEqual(body["object"], "image.batch")
        self.assertEqual(body["request_counts"]["total"], 2)
        self.assertTrue(body["results_url"].endswith(f"/v1/images/batches/{fields['id']}/results"))
        self.assertEqual(body["webhook"]["secret"], media_signing.webhook_secret("admin"))
        self.assertEqual(body["metadata"], {"project": "launch"})

    def test_an_idempotency_key_names_the_batch(self):
        first = self.create({"items": [{"prompt": "x"}]}, {"Idempotency-Key": "run-42"}).get_json()["id"]
        second = self.create({"items": [{"prompt": "x"}]}, {"Idempotency-Key": "run-42"}).get_json()["id"]
        self.assertEqual(first, second)
        self.assertEqual(first, "imgbatch_" + hashlib.sha256(b"admin\0run-42").hexdigest()[:32])
        for code, status in (("idempotency_conflict", 409), ("too_many_active_batches", 429)):
            with self.jobs({"create_batch": media_jobs.MediaJobError(status, code)}):
                response = self.client.post("/v1/images/batches", headers=ADMIN, json={"items": [{"prompt": "x"}]})
            self.assertEqual((response.status_code, response.get_json()["error"]), (status, code))

    def test_invalid_batches_are_refused_before_storage(self):
        items = [{"prompt": "x"}]
        for body in ({"items": []}, {"items": [{"prompt": "x"}] * 501}, {"items": [{"size": "1024x1024"}]},
                     {"items": [{"prompt": "x", "mask": "y"}]}, {"items": [{"id": "a", "prompt": "x"}, {"id": "a", "prompt": "y"}]},
                     {"items": [{"prompt": "x", "n": 10}] * 101}, {"items": items, "webhook_url": "http://hooks.example.com/a"},
                     {"items": items, "webhook_url": "https://10.0.0.8/hook"}, {"items": items, "webhook_url": "https://api.internal/x"},
                     {"items": items, "metadata": {"a": 1}}, {"items": [{"prompt": "x", "model": "auto:missing"}]},
                     {"items": items, "extra": True}):
            with self.jobs({}) as call:
                response = self.client.post("/v1/images/batches", headers=ADMIN, json=body)
            self.assertEqual(response.status_code, 400, (body if len(json.dumps(body)) < 300 else "large", response.get_json()))
            call.assert_not_called()

    def test_results_list_signed_links_and_errors(self):
        batch_id = "imgbatch_" + "b" * 32
        items = {"version": 1, "has_more": True, "items": [
            {"index": 0, "custom_id": "hero", "status": "succeeded", "model": "gguu:gpt-image-2",
             "files": [{"id": f"mb_{'b' * 32}_0_0", "size": 3, "content_type": "image/png"}, {"url": "https://provider.example/x.png"}],
             "error": None},
            {"index": 1, "custom_id": "icon", "status": "failed", "model": None, "files": [],
             "error": {"code": "outcome_unknown", "message": "interrupted"}}]}
        with self.jobs({"list_items": items}):
            response = self.client.get(f"/v1/images/batches/{batch_id}/results?after=-1&limit=2", headers=ADMIN)
        body = response.get_json()
        hero, icon = body["data"]
        self.assertEqual(hero["images"][0]["file_id"], f"mb_{'b' * 32}_0_0")
        self.assertIn("signature=", hero["images"][0]["url"])
        self.assertEqual(hero["images"][1], {"url": "https://provider.example/x.png"})
        self.assertEqual(icon["error"]["code"], "outcome_unknown")
        self.assertEqual((body["has_more"], body["next_after"]), (True, 1))
        self.assertEqual(self.calls[0][1], {"id": batch_id, "owner": "admin", "after": -1, "limit": 2})
        with self.jobs({"get_job": media_jobs.MediaJobError(404, "not_found")}):
            self.assertEqual(self.client.get(f"/v1/images/batches/{batch_id}", headers=ADMIN).status_code, 404)
        self.assertEqual(self.client.get("/v1/images/batches/not-a-batch", headers=ADMIN).status_code, 404)
        with self.jobs({"cancel_job": {"version": 1, "job": job(id=batch_id, status="cancelling")}}):
            cancelled = self.client.post(f"/v1/images/batches/{batch_id}/cancel", headers=ADMIN).get_json()
        self.assertEqual(cancelled["status"], "cancelling")

    def internal(self, path, body, owner="admin", kind="batch", subject=None):
        token = media_signing.issue_principal(kind, subject or body.get("watch_id") or body.get("job_id"), owner, 60)
        return self.client.post(path, headers={"Authorization": f"MultiLLM-Principal {token}"}, json=body)

    def test_the_item_endpoint_runs_items_as_the_owner_and_stores_their_images(self):
        batch_id = "imgbatch_" + "c" * 32
        replies = {"good": upstream(200, {"created": 1, "data": [{"url": "https://provider.example/good.png"}]}),
                   "bad": upstream(400, {"error": {"message": "content policy"}})}

        def transport(**kwargs):
            return replies[json.loads(kwargs["data"])["prompt"]]

        stored = []
        with patch.object(self.app_module.ProxyService, "make_request", side_effect=transport), \
                patch("services.media_storage.import_url",
                      side_effect=lambda file_id, url, **kwargs: stored.append((file_id, url, kwargs)) or
                      {"id": file_id, "size": 5, "content_type": "image/png"}):
            response = self.internal("/internal/media/batch-items", {"job_id": batch_id, "items": [
                {"index": 0, "custom_id": "a", "request": {"model": "auto:image-test", "prompt": "good"}},
                {"index": 7, "custom_id": "b", "request": {"model": "auto:image-test", "prompt": "bad"}}]})
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        good, bad = response.get_json()["results"]
        self.assertEqual(good, {"index": 0, "status": "succeeded", "model": "gguu:gpt-image-2",
                                "files": [{"id": f"mb_{'c' * 32}_0_0", "size": 5, "content_type": "image/png"}]})
        self.assertEqual(stored[0][1:], ("https://provider.example/good.png", {"owner": "admin", "kind": "image",
                                                                               "model": "gguu:gpt-image-2"}))
        self.assertEqual((bad["index"], bad["status"], bad["error"]["status"]), (7, "failed", 400))

    def test_the_item_endpoint_refuses_forged_or_orphaned_principals(self):
        body = {"job_id": "imgbatch_" + "d" * 32, "items": [{"index": 0, "request": {"prompt": "x"}}]}
        with patch.object(self.app_module.ProxyService, "make_request") as make_request:
            self.assertEqual(self.client.post("/internal/media/batch-items", json=body).status_code, 401)
            self.assertEqual(self.client.post("/internal/media/batch-items", json=body,
                                              headers={"Authorization": "MultiLLM-Principal forged.token"}).status_code, 403)
            self.assertEqual(self.internal("/internal/media/batch-items", body, subject="imgbatch_" + "e" * 32).status_code, 400)
            self.assertEqual(self.internal("/internal/media/batch-items", body, kind="video").status_code, 403)
            orphaned = self.internal("/internal/media/batch-items", body, owner="ghost")
            self.assertEqual((orphaned.status_code, orphaned.get_json()["error"]), (403, "principal_rejected"))
            with patch.object(self.app_module.AuthService, "_load_user_by_username",
                              side_effect=APIError("Account storage is unavailable", 503)):
                retry = self.internal("/internal/media/batch-items", body)
            self.assertEqual((retry.status_code, retry.get_json()), (503, {"retry": True}))
        make_request.assert_not_called()

    def test_video_webhooks_register_a_watch_after_the_job_exists(self):
        created = upstream(200, {"id": "video_abc", "status": "queued"})
        with patch("services.video_generation._send", return_value=created) as send, \
                self.jobs({"watch_video": {"version": 1, "created": True, "job": job(kind="video")}}):
            response = self.client.post("/v1/videos", headers=ADMIN, json={
                "model": "openai:sora-2", "prompt": "A wave", "webhook_url": "https://hooks.example.com/video"})
        body = response.get_json()
        self.assertEqual(response.status_code, 200, body)
        send.assert_called_once()
        operation, fields = self.calls[0]
        self.assertEqual(operation, "watch_video")
        self.assertEqual(fields["metadata"]["job_id"], body["id"])
        self.assertEqual(fields["id"], "vwatch_" + hashlib.sha256(body["id"].encode()).hexdigest()[:32])
        self.assertEqual(media_signing.read_principal(fields["principal"], "video")["s"], fields["id"])
        self.assertEqual(body["webhook"], {"url": "https://hooks.example.com/video", "status": "pending",
                                           "secret": media_signing.webhook_secret("admin")})
        os.environ.pop("MEDIA_JOBS_ENABLED")
        with patch("services.video_generation._send") as send:
            refused = self.client.post("/v1/videos", headers=ADMIN, json={
                "model": "openai:sora-2", "prompt": "A wave", "webhook_url": "https://hooks.example.com/video"})
        self.assertEqual((refused.status_code, refused.get_json()["error"]), (503, "webhooks_not_configured"))
        send.assert_not_called()

    def test_the_video_status_endpoint_reports_and_stores_a_finished_job(self):
        job_id = issue_job_id("admin", "openai", "sora-2", "video_abc")
        watch_id = "vwatch_" + hashlib.sha256(job_id.encode()).hexdigest()[:32]
        finished = upstream(200, {"id": "video_abc", "status": "completed"})
        with patch("services.video_generation._send", return_value=finished), \
                patch("services.media_storage.stat", return_value={"owner": "admin"}):
            response = self.internal("/internal/media/video-status", {"watch_id": watch_id, "job_id": job_id}, kind="video")
        body = response.get_json()
        self.assertEqual((body["status"], body["model"]), ("completed", "openai:sora-2"))
        self.assertTrue(re.fullmatch(r"mv_[a-f0-9]{40}", body["file_id"]))
        other = self.internal("/internal/media/video-status", {"watch_id": watch_id, "job_id": job_id}, kind="video",
                              owner="ghost")
        self.assertEqual(other.status_code, 403)

    def test_each_owner_has_a_webhook_secret(self):
        body = self.client.get("/v1/media/webhook-secret", headers=ADMIN).get_json()
        self.assertEqual(body["secret"], media_signing.webhook_secret("admin"))
        self.assertTrue(body["secret"].startswith("whsec_"))
