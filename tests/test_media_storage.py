"""Durable media in R2: gateway links, owner access, signed links and stored videos."""

import base64
import json
import os
import time
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import requests

from services import media_signing, media_storage
from services.auto_route_service import AutoRouteService
from services.video_generation import issue_job_id
from tests.unified_api_test_case import UnifiedApiTestCase

KEYS = {"gguu": "gguu-test-key", "openai": "openai-test-key"}
ADMIN = {"Authorization": "Bearer admin-test-key"}
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 24


def upstream(status, body, content_type="application/json"):
    response = requests.Response()
    response.status_code = status
    response._content = json.dumps(body).encode() if isinstance(body, dict) else body
    response._content_consumed = True
    response.headers["Content-Type"] = content_type
    return response


def stored_file(size=10, content_type="image/png"):
    return {"id": "ignored", "size": size, "content_type": content_type}


def test_file_links_expire_and_bind_the_file():
    os.environ["MEDIA_SIGNING_SECRET"] = "unit-secret"
    try:
        params = media_signing.file_link_params("mf_0123456789abcdef", ttl=600)
        assert media_signing.verify_file_link("mf_0123456789abcdef", params["expires"], params["signature"])
        assert not media_signing.verify_file_link("mf_0123456789abcdeg", params["expires"], params["signature"])
        assert not media_signing.verify_file_link("mf_0123456789abcdef", str(int(params["expires"]) + 1), params["signature"])
        assert not media_signing.verify_file_link("mf_0123456789abcdef", params["expires"], params["signature"],
                                                  now=time.time() + 601)
        token = media_signing.issue_principal("batch", "imgbatch_1", "alice", 60)
        assert media_signing.read_principal(token, "batch")["o"] == "alice"
        for bad in (token + "x", token.replace(".", ".x"), "", None):
            try:
                media_signing.read_principal(bad, "batch")
            except Exception as error:
                assert getattr(error, "status_code", None) == 403
            else:
                raise AssertionError(bad)
    finally:
        os.environ.pop("MEDIA_SIGNING_SECRET", None)


def test_signatures_match_the_worker():
    """The same vectors are asserted in tests/test_media_files_worker.mjs."""
    os.environ["MEDIA_SIGNING_SECRET"] = "parity-secret"
    try:
        assert media_signing.sign_file("mf_0123456789abcdef", 2000000000) == "rOffj5ku5kWJTYCHV6r7c3o643_-cgliTTn2qxGpsRA"
        assert media_signing.webhook_secret("alice") == "whsec_mDjj2kRZZ7WCap4F63/rTQtrBvux7PsfG03IYoCycQ0="
        assert media_signing.webhook_signature("alice", "evt_1", 1700000000, b'{"a":1}') == \
            "v1,v/mRpTaO+aKRBHnYz195WvhGuyasIR8b/ckkVa9FMu8="
    finally:
        os.environ.pop("MEDIA_SIGNING_SECRET", None)


class MediaStorageTest(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        os.environ["MEDIA_STORAGE_ENABLED"] = "true"
        for name, value in {
            "get_api_key": lambda provider: KEYS.get(provider),
            "get_api_keys": lambda provider: [KEYS[provider]] if provider in KEYS else [],
        }.items():
            patcher = patch.object(self.app_module.AuthService, name, side_effect=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        AutoRouteService.save_route("auto:image-test", ["gguu:gpt-image-2"], self.app.config["API_BASE_URLS"])

    def generate(self, image, **extra):
        with patch.object(self.app_module.ProxyService, "make_request", side_effect=[upstream(200, {"created": 1, "data": [image]})]):
            return self.client.post("/v1/images/generations", headers=ADMIN,
                                    json={"model": "auto:image-test", "prompt": "A fox", **extra})

    def assert_gateway_link(self, entry):
        link = urlsplit(entry["url"])
        self.assertEqual(link.path, f"/v1/media/files/{entry['file_id']}")
        query = parse_qs(link.query)
        self.assertTrue(media_signing.verify_file_link(entry["file_id"], query["expires"][0], query["signature"][0]))

    def test_provider_urls_are_copied_to_r2_and_returned_as_signed_gateway_links(self):
        with patch("services.media_storage.import_url", return_value=stored_file()) as import_url:
            response = self.generate({"url": "https://provider.example/tmp/fox.png", "revised_prompt": "A fox"})
        self.assertEqual(response.status_code, 200)
        entry = response.get_json()["data"][0]
        self.assertEqual(entry["revised_prompt"], "A fox")
        self.assert_gateway_link(entry)
        self.assertEqual(import_url.call_args.args[1], "https://provider.example/tmp/fox.png")
        self.assertEqual(import_url.call_args.kwargs, {"owner": "admin", "kind": "image", "model": "gguu:gpt-image-2"})
        self.assertEqual(response.headers["X-MultiLLM-Media-Stored"], "1")

    def test_base64_images_are_stored_only_when_urls_were_requested(self):
        encoded = base64.b64encode(PNG).decode()
        with patch("services.media_storage.put_bytes", return_value=stored_file()) as put_bytes:
            untouched = self.generate({"b64_json": encoded})
            self.assertEqual(untouched.get_json()["data"], [{"b64_json": encoded}])
            put_bytes.assert_not_called()
            stored = self.generate({"b64_json": encoded}, response_format="url")
        entry = stored.get_json()["data"][0]
        self.assertNotIn("b64_json", entry)
        self.assert_gateway_link(entry)
        self.assertEqual(put_bytes.call_args.args[1:3], (PNG, "image/png"))

    def test_a_failed_copy_keeps_the_provider_result_and_no_binding_changes_nothing(self):
        with patch("services.media_storage.import_url", side_effect=media_storage.StorageError("fetch_failed")):
            response = self.generate({"url": "https://provider.example/fox.png"})
        self.assertEqual(response.get_json()["data"], [{"url": "https://provider.example/fox.png"}])
        os.environ.pop("MEDIA_STORAGE_ENABLED")
        with patch("services.media_storage.import_url") as import_url:
            response = self.generate({"url": "https://provider.example/fox.png"})
        import_url.assert_not_called()
        self.assertNotIn("X-MultiLLM-Media-Stored", response.headers)

    def test_owners_read_and_delete_their_files_and_others_see_nothing(self):
        meta = {"id": "mf_0123456789abcdef", "owner": "admin", "size": 3, "content_type": "image/png", "kind": "image"}
        body = upstream(200, b"png", "image/png")
        with patch("services.media_storage.stat", return_value=meta), \
                patch("services.media_storage.open_file", return_value=body):
            response = self.client.get("/v1/media/files/mf_0123456789abcdef", headers=ADMIN)
            self.assertEqual((response.status_code, response.data, response.mimetype), (200, b"png", "image/png"))
            described = self.client.get("/v1/media/files/mf_0123456789abcdef?format=json", headers=ADMIN).get_json()
            self.assert_gateway_link({"url": described["url"], "file_id": described["id"]})
        with patch("services.media_storage.stat", return_value={**meta, "owner": "someone-else"}):
            self.assertEqual(self.client.get("/v1/media/files/mf_0123456789abcdef",
                                             headers={"Authorization": "Bearer wrong"}).status_code, 401)
        with patch("services.media_storage.stat", return_value=meta), \
                patch("services.media_storage.delete", return_value=True) as delete:
            response = self.client.delete("/v1/media/files/mf_0123456789abcdef", headers=ADMIN)
        self.assertEqual(response.get_json(), {"id": "mf_0123456789abcdef", "object": "media.file", "deleted": True})
        delete.assert_called_once_with("mf_0123456789abcdef")
        with patch("services.media_storage.stat", return_value=None):
            self.assertEqual(self.client.get("/v1/media/files/mf_0123456789abcdef", headers=ADMIN).status_code, 404)

    def test_the_container_never_serves_a_file_on_a_signature_alone(self):
        params = media_signing.file_link_params("mf_0123456789abcdef")
        with patch("services.media_storage.open_file") as open_file:
            response = self.client.get("/v1/media/files/mf_0123456789abcdef", query_string=params)
        self.assertEqual(response.status_code, 401)
        open_file.assert_not_called()
        os.environ.pop("MEDIA_STORAGE_ENABLED")
        response = self.client.get("/v1/media/files/mf_0123456789abcdef", headers=ADMIN)
        self.assertEqual((response.status_code, response.get_json()["error"]), (404, "media_storage_not_configured"))

    def test_finished_videos_are_stored_once_and_served_from_r2(self):
        job_id = issue_job_id("admin", "openai", "sora-2", "video_abc")
        file_id = media_storage.video_file_id(job_id)
        finished = upstream(200, {"id": "video_abc", "status": "completed", "progress": 100})
        with patch("services.video_generation._send", return_value=finished), \
                patch("services.media_storage.stat", return_value=None), \
                patch("services.media_storage.store_video", return_value=stored_file(5, "video/mp4")) as store:
            status = self.client.get(f"/v1/videos/{job_id}", headers=ADMIN).get_json()
        self.assertEqual(status["file_id"], file_id)
        self.assert_gateway_link({"url": status["content_url"], "file_id": file_id})
        self.assertEqual(store.call_args.args[1], "https://api.openai.com/v1/videos/video_abc/content")
        with patch("services.media_storage.stat", return_value={"owner": "admin"}), \
                patch("services.media_storage.open_file", return_value=upstream(200, b"mp4", "video/mp4")) as open_file, \
                patch("services.video_generation.stream_content") as provider:
            response = self.client.get(f"/v1/videos/{job_id}/content", headers=ADMIN)
        self.assertEqual(response.data, b"mp4")
        open_file.assert_called_once_with(file_id, None)
        provider.assert_not_called()

    def test_batch_items_are_stored_when_r2_is_bound(self):
        with patch.object(self.app_module.ProxyService, "make_request",
                          side_effect=[upstream(200, {"created": 1, "data": [{"url": "https://provider.example/a.png"}]})]), \
                patch("services.media_storage.import_url", return_value=stored_file()):
            response = self.client.post("/v1/images/batch", headers=ADMIN, json={
                "defaults": {"model": "auto:image-test", "response_format": "url"}, "items": [{"prompt": "A fox"}]})
        image = response.get_json()["data"][0]["images"][0]
        self.assert_gateway_link(image)
