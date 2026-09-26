"""Large source images: upload routes take the media body limit, and uploads stored in R2
can be referenced by ID in edits instead of being sent again."""

import io
import json
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import requests

from tests.unified_api_test_case import UnifiedApiTestCase

ADMIN = {"Authorization": "Bearer admin-test-key"}
KEYS = {"gguu": "gguu-test-key", "openai": "openai-test-key"}
LARGE_PNG = b"\x89PNG\r\n\x1a\n" + b"\x01" * (5 * 1024 * 1024)
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 24
IMAGE = {"created": 1, "data": [{"b64_json": "aW1hZ2U="}]}
UPLOAD_ID = "mu_" + "a" * 32


def upstream(status, body):
    response = requests.Response()
    response.status_code = status
    response._content = json.dumps(body).encode()
    response._content_consumed = True
    response.headers["Content-Type"] = "application/json"
    return response


def stored(owner="admin", age=timedelta(minutes=5), kind="image"):
    uploaded = (datetime.now(timezone.utc) - age).isoformat().replace("+00:00", "Z")
    return {"id": UPLOAD_ID, "size": len(PNG), "content_type": "image/png", "owner": owner, "kind": kind,
            "model": None, "uploaded": uploaded}


class MediaUploadTest(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        for name, value in {
            "get_api_key": lambda provider: KEYS.get(provider),
            "get_api_keys": lambda provider: [KEYS[provider]] if provider in KEYS else [],
        }.items():
            patcher = patch.object(self.app_module.AuthService, name, side_effect=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        os.environ.pop("MEDIA_STORAGE_ENABLED", None)
        self.addCleanup(os.environ.pop, "MEDIA_STORAGE_ENABLED", None)

    def edit(self, data=None, json_body=None, path="/v1/images/edits", headers=ADMIN):
        with patch.object(self.app_module.ProxyService, "make_request", return_value=upstream(200, IMAGE)) as make_request:
            if json_body is not None:
                response = self.client.post(path, headers=headers, json=json_body)
            else:
                response = self.client.post(path, headers=headers, data=data, content_type="multipart/form-data")
        return response, make_request

    def test_a_large_source_image_passes_the_upload_limit_on_unified_and_native_routes(self):
        for path, model in (("/v1/images/edits", "gguu:gpt-image-2.5-sunburst"),
                            ("/gguu/v1/images/edits", "gpt-image-2.5-sunburst")):
            with self.subTest(path=path):
                response, make_request = self.edit({"model": model, "prompt": "Paint it",
                                                    "image": (io.BytesIO(LARGE_PNG), "big.png")}, path=path)
                self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
                make_request.assert_called_once()

    def test_other_routes_keep_the_provider_body_limit(self):
        with patch.object(self.app_module.ProxyService, "make_request") as make_request:
            response = self.client.post("/v1/chat/completions", headers=ADMIN, json={
                "model": "openai:gpt-4.1", "messages": [{"role": "user", "content": "x" * (2 * 1024 * 1024)}]})
        self.assertEqual((response.status_code, response.get_json()["error"]), (413, "request_too_large"))
        make_request.assert_not_called()

    def test_uploads_need_media_storage(self):
        response = self.client.post("/v1/media/uploads", headers=ADMIN, data={"file": (io.BytesIO(PNG), "a.png")},
                                    content_type="multipart/form-data")
        self.assertEqual((response.status_code, response.get_json()["error"]), (503, "media_storage_not_configured"))

    def test_an_upload_is_stored_temporarily_for_its_owner(self):
        os.environ["MEDIA_STORAGE_ENABLED"] = "true"
        calls = []

        def put_bytes(file_id, data, content_type, **kwargs):
            calls.append((file_id, data, content_type, kwargs))
            return {"id": file_id, "size": len(data), "content_type": content_type}

        with patch("services.media_storage.put_bytes", side_effect=put_bytes):
            multipart = self.client.post("/v1/media/uploads", headers=ADMIN, content_type="multipart/form-data",
                                         data={"file": (io.BytesIO(LARGE_PNG), "big.png")})
            raw = self.client.post("/v1/media/uploads", headers={**ADMIN, "Content-Type": "image/png"}, data=PNG)
            refused = self.client.post("/v1/media/uploads", headers={**ADMIN, "Content-Type": "image/png"}, data=b"not an image")
        self.assertEqual(multipart.status_code, 200, multipart.get_data(as_text=True))
        body = multipart.get_json()
        self.assertTrue(body["id"].startswith("mu_"))
        self.assertEqual((body["object"], body["bytes"], body["content_type"]), ("media.upload", len(LARGE_PNG), "image/png"))
        self.assertEqual(body["expires_at"] - body["created_at"], 24 * 60 * 60)
        self.assertIn(f"/v1/media/files/{body['id']}?", body["url"])
        self.assertEqual(raw.status_code, 200)
        self.assertEqual(calls[0][3], {"owner": "admin", "kind": "image"})
        self.assertEqual(refused.status_code, 400)

    def test_edits_read_referenced_uploads_back_from_storage(self):
        os.environ["MEDIA_STORAGE_ENABLED"] = "true"
        with patch("services.media_storage.stat", return_value=stored()), \
                patch("services.media_storage.read_file", return_value=PNG) as read_file:
            json_response, json_call = self.edit(json_body={"model": "gguu:gpt-image-2.5-sunburst", "prompt": "Paint it",
                                                            "images": [{"file_id": UPLOAD_ID}]})
            form_response, form_call = self.edit({"model": "gguu:gpt-image-2.5-sunburst", "prompt": "Paint it",
                                                  "image_file_id": UPLOAD_ID})
        for response, make_request in ((json_response, json_call), (form_response, form_call)):
            self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
            body = make_request.call_args.kwargs["data"]
            self.assertIn(PNG, body)
            self.assertNotIn(b"image_file_id", body)
        self.assertEqual(read_file.call_count, 2)

    def test_references_are_limited_to_the_owner_and_to_live_uploads(self):
        os.environ["MEDIA_STORAGE_ENABLED"] = "true"
        auth = self.app_module.AuthService
        with patch.object(auth, "get_current_user", return_value={"username": "admin", "is_admin": True}):
            key = auth.create_user("uploader", is_admin=False, scopes=["chat"])["api_key"]
        other = {"Authorization": f"Bearer {key}"}
        cases = ((stored(owner="admin"), other, 404, "file_not_found"),
                 (stored(owner="uploader", age=timedelta(days=2)), other, 410, "upload_expired"),
                 (stored(owner="uploader", kind="video"), other, 404, "file_not_found"),
                 (None, ADMIN, 404, "file_not_found"))
        for meta, headers, status, code in cases:
            with self.subTest(code=code, meta=meta and meta["owner"]), \
                    patch("services.media_storage.stat", return_value=meta), \
                    patch("services.media_storage.read_file", return_value=PNG):
                response, make_request = self.edit(json_body={"model": "gguu:gpt-image-2.5-sunburst", "prompt": "x",
                                                              "images": [{"file_id": UPLOAD_ID}]}, headers=headers)
                self.assertEqual((response.status_code, response.get_json()["error"]), (status, code))
                make_request.assert_not_called()
