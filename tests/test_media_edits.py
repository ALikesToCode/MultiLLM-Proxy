"""Image edits and reference images across providers with the image failover rule."""

import base64
import io
import json
import os
from unittest.mock import patch

import requests
from flask import Response

from services.auto_route_service import AutoRouteService
from services.media_catalog import image_edit_support, prepare_image_edit_payload
from tests.unified_api_test_case import UnifiedApiTestCase

KEYS = {"gguu": "gguu-test-key", "gguu-grok": "gguu-grok-test-key", "xai": "xai-test-key", "openai": "openai-test-key",
        "together": "together-test-key"}
ADMIN = {"Authorization": "Bearer admin-test-key"}
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 24
JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 24
IMAGE = {"created": 1, "data": [{"b64_json": "aW1hZ2U="}]}


def upstream(status, body, **attributes):
    response = requests.Response()
    response.status_code = status
    response._content = json.dumps(body).encode()
    response._content_consumed = True
    response.headers["Content-Type"] = "application/json"
    for name, value in attributes.items():
        setattr(response, name, value)
    return response


def data_url(data, kind="png"):
    return f"data:image/{kind};base64,{base64.b64encode(data).decode()}"


def test_edit_support_follows_each_provider_api():
    assert image_edit_support("gguu", "gpt-image-2.5-sunburst").transport == "multipart"
    assert image_edit_support("gguu-grok", "grok-imagine-image-2.0") is None
    assert (image_edit_support("xai", "grok-imagine-image-2.0").max_images, image_edit_support("xai", "grok-imagine-image-2.0").mask) == (3, False)
    assert image_edit_support("cloudflare", "openai/gpt-image-2.5-flare").transport == "cloudflare"
    assert image_edit_support("cloudflare", "@cf/leonardo/lucid-origin") is None
    assert image_edit_support("openai", "dall-e-2").max_images == 1
    assert image_edit_support("together", "openai/gpt-image-2") is None
    request = {"model": "x", "prompt": "p", "size": "3840x2160", "quality": "max", "moderation": "low", "n": 1,
               "response_format": "url", "input_fidelity": "high"}
    sunburst = prepare_image_edit_payload("gguu", "gpt-image-2.5-sunburst", request)
    assert "moderation" not in sunburst and sunburst["input_fidelity"] == "high" and sunburst["quality"] == "max"
    assert "response_format" not in prepare_image_edit_payload("openai", "gpt-image-2", request)
    assert prepare_image_edit_payload("xai", "grok-imagine-image-2.0", request) == {
        "model": "x", "prompt": "p", "n": 1, "response_format": "url"}
    assert "input_fidelity" not in prepare_image_edit_payload("openai", "gpt-image-1-mini", request)


class MediaEditTest(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        for name, value in {
            "get_api_key": lambda provider: KEYS.get(provider),
            "get_api_keys": lambda provider: [KEYS[provider]] if provider in KEYS else [],
        }.items():
            patcher = patch.object(self.app_module.AuthService, name, side_effect=value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def save(self, route_id, candidates):
        AutoRouteService.save_route(route_id, candidates, self.app.config["API_BASE_URLS"])

    def multipart(self, fields, files, transport):
        data = dict(fields)
        for name, content in files:
            data.setdefault(name, []).append((io.BytesIO(content), "upload.bin"))
        with patch.object(self.app_module.ProxyService, "make_request", side_effect=transport) as make_request:
            response = self.client.post("/v1/images/edits", headers=ADMIN, data=data, content_type="multipart/form-data")
        return response, make_request

    def post_json(self, path, body, transport):
        with patch.object(self.app_module.ProxyService, "make_request", side_effect=transport) as make_request:
            response = self.client.post(path, headers=ADMIN, json=body)
        return response, make_request

    def test_multipart_edit_sends_openai_form_and_fails_over_after_a_refusal(self):
        self.save("auto:edit-test", ["together:openai/gpt-image-2", "gguu:gpt-image-2.5-sunburst", "openai:gpt-image-2"])
        response, make_request = self.multipart(
            {"model": "auto:edit-test", "prompt": "Put a hat on the cat", "size": "1536x1024", "n": "1",
             "input_fidelity": "high"},
            [("image[]", PNG), ("image[]", JPEG), ("mask", PNG)],
            [upstream(503, {"error": {"message": "no channel"}}), upstream(200, IMAGE)])
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertEqual(response.get_json(), IMAGE)
        first, second = make_request.call_args_list
        self.assertEqual(first.kwargs["url"], "https://gguuai.com/v1/images/edits")
        self.assertEqual(second.kwargs["url"], "https://api.openai.com/v1/images/edits")
        self.assertTrue(first.kwargs["headers"]["Content-Type"].startswith("multipart/form-data; boundary="))
        self.assertIn("gguu-test-key", first.kwargs["headers"]["Authorization"])
        body = first.kwargs["data"]
        self.assertEqual(body.count(b'name="image[]"'), 2)
        self.assertIn(b'name="mask"', body)
        self.assertIn(b'name="model"\r\n\r\ngpt-image-2.5-sunburst', body)
        self.assertIn(b'name="quality"\r\n\r\nmax', body)
        self.assertIn(b'name="input_fidelity"\r\n\r\nhigh', body)
        self.assertNotIn(b'name="moderation"', body)
        self.assertIn(b'name="quality"\r\n\r\nhigh', second.kwargs["data"], "GPT Image 2 tops out at high")
        self.assertEqual(response.headers["X-MultiLLM-Auto-Selected-Model"], "openai:gpt-image-2")

    def test_a_timeout_after_sending_stops_the_route(self):
        self.save("auto:edit-test", ["gguu:gpt-image-2", "openai:gpt-image-2"])
        response, make_request = self.multipart(
            {"model": "auto:edit-test", "prompt": "Brighter"}, [("image", PNG)],
            [upstream(502, {"error": {"message": "timeout"}}, multillm_transport_failure="timeout")])
        self.assertEqual(response.status_code, 502)
        self.assertEqual(make_request.call_count, 1)

    def test_json_edit_reaches_xai_as_image_urls_and_skips_unbound_cloudflare(self):
        self.save("auto:edit-test", ["cloudflare:openai/gpt-image-2", "xai:grok-imagine-image-2.0"])
        with patch("services.media_storage.fetch_public", return_value=(JPEG, "image/jpeg")) as fetch:
            response, make_request = self.post_json("/v1/images/edits", {
                "model": "auto:edit-test", "prompt": "Pencil sketch", "size": "1024x1024",
                "images": [data_url(PNG), {"image_url": "https://images.example/cat.jpg"}]}, [upstream(200, IMAGE)])
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        fetch.assert_called_once()
        self.assertEqual(fetch.call_args.args[0], "https://images.example/cat.jpg")
        forwarded = make_request.call_args.kwargs
        self.assertEqual(forwarded["url"], "https://api.x.ai/v1/images/edits")
        body = json.loads(forwarded["data"])
        self.assertEqual(body["model"], "grok-imagine-image-2.0")
        self.assertEqual(body["images"], [{"url": data_url(PNG), "type": "image_url"}, {"url": data_url(JPEG, "jpeg"), "type": "image_url"}])
        self.assertNotIn("size", body)

    def test_a_mask_skips_candidates_that_ignore_masks(self):
        self.save("auto:edit-test", ["xai:grok-imagine-image-2.0", "gguu:gpt-image-2"])
        response, make_request = self.post_json("/v1/images/edits", {
            "model": "auto:edit-test", "prompt": "Fill", "images": [data_url(PNG)], "mask": data_url(PNG)},
            [upstream(200, IMAGE)])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(make_request.call_args.kwargs["url"], "https://gguuai.com/v1/images/edits")
        self.assertEqual(response.headers["X-MultiLLM-Auto-Attempts"], "1")

    def test_cloudflare_edits_send_images_through_the_ai_binding(self):
        os.environ["CLOUDFLARE_AI_ENABLED"] = "true"
        sent = {}

        def post(path, payload, timeout):
            sent.update(path=path, payload=payload)
            return Response(json.dumps(IMAGE), status=200, content_type="application/json")

        with patch("services.cloudflare_ai.post", side_effect=post):
            response = self.client.post("/v1/images/edits", headers=ADMIN, json={
                "model": "cloudflare:openai/gpt-image-2.5-flare", "prompt": "Clay", "images": [data_url(PNG)],
                "quality": "max", "moderation": "low"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(sent["path"], "/v1/images/edits")
        self.assertEqual(sent["payload"]["model"], "openai/gpt-image-2.5-flare")
        self.assertEqual(sent["payload"]["images"], [data_url(PNG)])
        self.assertNotIn("moderation", sent["payload"])

    def test_generation_with_reference_images_runs_on_candidates_that_accept_them(self):
        self.save("auto:image-test", ["gguu-grok:grok-imagine-image-2.0", "gguu:gpt-image-2"])
        response, make_request = self.post_json("/v1/images/generations", {
            "model": "auto:image-test", "prompt": "Same character, new pose", "images": [data_url(PNG)]},
            [upstream(200, IMAGE)])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(make_request.call_count, 1)
        self.assertEqual(make_request.call_args.kwargs["url"], "https://gguuai.com/v1/images/edits")
        self.assertEqual(response.headers["X-MultiLLM-Auto-Selected-Model"], "gguu:gpt-image-2")

    def test_the_seeded_edit_route_lists_only_edit_capable_candidates(self):
        route = AutoRouteService.get_route("auto:image-edit")
        self.assertTrue(route.candidates)
        from services.model_registry import ModelRegistry
        for candidate in route.candidates:
            self.assertIsNotNone(image_edit_support(*ModelRegistry.parse_model_id(candidate)), candidate)

    def test_invalid_edits_are_refused_before_any_provider_request(self):
        cases = [
            ({"model": "gguu:gpt-image-2", "prompt": "x"}, [("image", b"not an image")], 400),
            ({"model": "gguu:gpt-image-2", "prompt": "x"}, [("image", PNG), ("mask", JPEG)], 400),
            ({"model": "gguu:gpt-image-2"}, [("image", PNG)], 400),
            ({"model": "together:openai/gpt-image-2", "prompt": "x"}, [("image", PNG)], 400),
            ({"model": "gguu:gpt-image-2", "prompt": "x"}, [("image", PNG)] * 17, 400),
            ({"model": "gguu:gpt-image-2", "prompt": "x", "stream": "true"}, [("image", PNG)], 400),
            ({"model": "gguu:gpt-image-2", "prompt": "x"}, [("file", PNG)], 400),
        ]
        for fields, files, status in cases:
            response, make_request = self.multipart(fields, files, [])
            self.assertEqual(response.status_code, status, (fields, response.get_data(as_text=True)))
            make_request.assert_not_called()
        for body in ({"prompt": "x", "images": []}, {"prompt": "x", "images": ["http://images.example/a.png"]},
                     {"prompt": "x", "images": ["https://10.0.0.1/a.png"]}, {"prompt": "x", "images": ["data:text/plain;base64,eA=="]}):
            response, make_request = self.post_json("/v1/images/edits", {"model": "gguu:gpt-image-2", **body}, [])
            self.assertEqual(response.status_code, 400, body)
            make_request.assert_not_called()
