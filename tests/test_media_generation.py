"""Image routes, batches, Cloudflare AI and asynchronous video jobs."""

import json
import os
import threading
from unittest.mock import patch

import requests
from flask import Response

from services.auto_route_service import AutoRouteService
from services.media_catalog import prepare_image_payload
from tests.unified_api_test_case import UnifiedApiTestCase

KEYS = {"gguu": "gguu-test-key", "gguu-grok": "gguu-grok-test-key", "latix": "latix-test-key", "xai": "xai-test-key",
        "openai": "openai-test-key", "gemini": "gemini-test-key"}
IMAGE = {"created": 1, "data": [{"url": "https://images.example/one.png"}]}
ADMIN = {"Authorization": "Bearer admin-test-key"}


def upstream(status, body, **attributes):
    response = requests.Response()
    response.status_code = status
    response._content = json.dumps(body).encode()
    response._content_consumed = True
    response.headers["Content-Type"] = "application/json"
    for name, value in attributes.items():
        setattr(response, name, value)
    return response


def test_each_candidate_receives_the_closest_settings_its_model_supports():
    request = {"model": "x", "prompt": "p", "size": "3840x2160", "quality": "max", "background": "opaque",
               "moderation": "low", "n": 1}
    sunburst = prepare_image_payload("gguu", "gpt-image-2.5-sunburst", request)
    assert (sunburst["quality"], sunburst["size"], sunburst["moderation"]) == ("max", "3840x2160", "low")
    assert prepare_image_payload("gguu", "gpt-image-2", request)["quality"] == "high"
    assert prepare_image_payload("openai", "gpt-image-1.5", request)["size"] == "1536x1024"
    cloudflare = prepare_image_payload("cloudflare", "openai/gpt-image-2.5-sunburst", request)
    assert (cloudflare["size"], cloudflare["quality"]) == ("1536x1024", "max")
    grok = prepare_image_payload("xai", "grok-imagine-image-2.0", request)
    assert grok == {"model": "x", "prompt": "p", "n": 1, "quality": "medium", "aspect_ratio": "16:9", "resolution": "2k"}
    assert "quality" not in prepare_image_payload("gguu", "grok-imagine-image-quality", request)
    assert prepare_image_payload("cloudflare", "@cf/leonardo/lucid-origin", request) == {
        "model": "x", "prompt": "p", "size": "3840x2160", "quality": "max", "n": 1}
    assert prepare_image_payload("together", "black-forest-labs/flux", request) == request
    assert prepare_image_payload("gguu", "gpt-image-2.5", {**request, "quality": "auto", "size": "4000x1000"})["size"] == "3840x960"


class MediaRouteTest(UnifiedApiTestCase):
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

    def post(self, path, body, transport, headers=ADMIN):
        with patch.object(self.app_module.ProxyService, "make_request", side_effect=transport) as make_request:
            response = self.client.post(path, headers=headers, json=body)
        return response, make_request

    def test_auto_image_defaults_to_max_and_translates_settings_for_each_fallback(self):
        self.save("auto:image-test", ["gguu:gpt-image-2", "xai:grok-imagine-image-2.0"])
        response, make_request = self.post("/v1/images/generations",
                                           {"model": "auto:image-test", "prompt": "A red fox", "size": "1536x1024"},
                                           [upstream(503, {"error": {"message": "no channel"}}), upstream(200, IMAGE)])
        self.assertEqual(response.status_code, 200)
        first, second = (json.loads(call.kwargs["data"]) for call in make_request.call_args_list)
        self.assertEqual((first["model"], first["quality"], first["size"]), ("gpt-image-2", "high", "1536x1024"))
        self.assertEqual(make_request.call_args_list[1].kwargs["url"], "https://api.x.ai/v1/images/generations")
        self.assertEqual(second, {"model": "grok-imagine-image-2.0", "prompt": "A red fox", "quality": "medium",
                                  "aspect_ratio": "3:2", "resolution": "2k"})
        self.assertEqual(response.headers["X-MultiLLM-Auto-Selected-Model"], "xai:grok-imagine-image-2.0")

    def test_grok_on_gguu_uses_the_grok_group_key(self):
        self.save("auto:image-test", ["gguu:gpt-image-2", "gguu-grok:grok-imagine-image-2.0"])
        response, make_request = self.post("/v1/images/generations",
                                           {"model": "auto:image-test", "prompt": "A red fox", "size": "1024x1024"},
                                           [upstream(503, {"error": {"message": "no channel"}}), upstream(200, IMAGE)])
        self.assertEqual(response.status_code, 200)
        gpt, grok = make_request.call_args_list
        self.assertIn("gguu-test-key", gpt.kwargs["headers"]["Authorization"])
        self.assertEqual(grok.kwargs["url"], "https://gguuai.com/v1/images/generations")
        self.assertIn("gguu-grok-test-key", grok.kwargs["headers"]["Authorization"])
        self.assertEqual(json.loads(grok.kwargs["data"])["aspect_ratio"], "1:1")
        self.assertEqual(response.headers["X-MultiLLM-Auto-Selected-Model"], "gguu-grok:grok-imagine-image-2.0")

    def test_several_images_fan_out_one_request_each_and_merge(self):
        self.save("auto:image-test", ["gguu:gpt-image-2.5-sunburst", "latix:gpt-image-2"])
        replies = [upstream(200, IMAGE), upstream(429, {"error": {"message": "busy"}}), upstream(200, IMAGE), upstream(200, IMAGE)]
        lock = threading.Lock()
        def transport(**kwargs):
            with lock:
                return replies.pop(0)
        response, make_request = self.post("/v1/images/generations", {"model": "auto:image-test", "prompt": "A red fox", "n": 3},
                                           transport)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.get_json()["data"]), 3)
        self.assertEqual(response.headers["X-MultiLLM-Images-Returned"], "3")
        self.assertTrue(all(json.loads(call.kwargs["data"])["n"] == 1 for call in make_request.call_args_list))
        self.assertEqual(self.client.post("/v1/images/generations", headers=ADMIN,
                                          json={"model": "auto:image-test", "prompt": "x", "n": 11}).status_code, 400)

    def test_a_batch_runs_different_prompts_and_sizes_and_reports_each_item(self):
        self.save("auto:image-test", ["gguu:gpt-image-2.5-sunburst"])
        def transport(**kwargs):
            body = json.loads(kwargs["data"])
            if body["prompt"] == "fails":
                return upstream(400, {"error": {"message": "content policy"}})
            return upstream(200, {"created": 1, "data": [{"url": f"https://images.example/{body['size']}.png"}]})
        response, _ = self.post("/v1/images/batch", {
            "defaults": {"model": "auto:image-test", "response_format": "url"},
            "items": [{"id": "hero", "prompt": "A skyline", "size": "3840x2160"},
                      {"id": "icon", "prompt": "An icon", "size": "1024x1024", "n": 2},
                      {"id": "bad", "prompt": "fails"}]}, transport)
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["summary"], {"items": 3, "succeeded": 2, "failed": 1, "images": 3})
        hero, icon, bad = body["data"]
        self.assertEqual(hero["images"], [{"url": "https://images.example/3840x2160.png"}])
        self.assertEqual((icon["id"], len(icon["images"])), ("icon", 2))
        self.assertEqual((bad["status"], bad["error"]["status"]), ("failed", 400))
        for invalid in ({"items": []}, {"items": [{"size": "1024x1024"}]},
                        {"items": [{"prompt": "x", "n": 9}]}, {"items": [{"prompt": "x"}], "extra": 1}):
            self.assertEqual(self.client.post("/v1/images/batch", headers=ADMIN, json=invalid).status_code, 400, invalid)

    def test_cloudflare_candidates_run_only_when_the_worker_binds_cloudflare_ai(self):
        self.save("auto:image-test", ["cloudflare:openai/gpt-image-2.5-sunburst", "gguu:gpt-image-2.5-flare"])
        response, make_request = self.post("/v1/images/generations", {"model": "auto:image-test", "prompt": "x"},
                                           [upstream(200, IMAGE)])
        self.assertEqual(response.headers["X-MultiLLM-Auto-Selected-Model"], "gguu:gpt-image-2.5-flare")
        os.environ["CLOUDFLARE_AI_ENABLED"] = "true"
        sent = {}
        def cloudflare(path, payload, timeout):
            sent.update(path=path, payload=payload)
            return Response(json.dumps(IMAGE), status=200, content_type="application/json")
        with patch("services.cloudflare_ai.post", side_effect=cloudflare):
            response, make_request = self.post("/v1/images/generations", {"model": "auto:image-test", "prompt": "x",
                                                                           "size": "3840x2160"}, [])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(make_request.call_count, 0)
        self.assertEqual(sent["path"], "/v1/images/generations")
        self.assertEqual((sent["payload"]["model"], sent["payload"]["size"], sent["payload"]["quality"]),
                         ("openai/gpt-image-2.5-sunburst", "1536x1024", "max"))

    def test_seeded_media_routes_put_gguu_first_and_never_use_openrouter(self):
        routes = {route.id: route.candidates for route in AutoRouteService.list_routes()}
        self.assertEqual(routes["auto:image"][:4], ("gguu:gpt-image-2.5-sunburst", "gguu:gpt-image-2.5-flare",
                                                    "gguu:gpt-image-2", "gguu-grok:grok-imagine-image-2.0"))
        self.assertEqual(routes["auto:image-fast"][:3], ("gguu:gpt-image-2.5-flare", "gguu:gpt-image-2",
                                                         "gguu-grok:grok-imagine-image-2.0"))
        self.assertFalse([candidate for route in routes.values() for candidate in route if candidate.startswith("openrouter:")])
        self.assertIn("cloudflare:google/veo-3.1", routes["auto:video"])

    def test_stored_copy_of_the_previous_image_default_follows_the_current_one(self):
        from services.auto_route_service import DEFAULT_AUTO_ROUTES, LEGACY_DEFAULT_AUTO_ROUTES
        previous = LEGACY_DEFAULT_AUTO_ROUTES["auto:image"][0]
        self.assertIn("gguu:grok-imagine-image-2.0", previous)
        with patch("services.auto_route_d1.stored_routes", return_value={"auto:image": (previous, "t")}):
            routes = {route.id: route.candidates for route in AutoRouteService._durable_routes()}
        self.assertEqual(routes["auto:image"], DEFAULT_AUTO_ROUTES["auto:image"])

    def test_provider_status_and_admin_probe_report_which_candidates_work(self):
        status = self.client.get("/v1/media/providers", headers=ADMIN).get_json()
        image = next(route for route in status["routes"] if route["id"] == "auto:image")
        by_model = {entry["model"]: entry for entry in image["candidates"]}
        self.assertTrue(by_model["gguu:gpt-image-2.5-sunburst"]["available"])
        self.assertFalse(by_model["cloudflare:openai/gpt-image-2.5-sunburst"]["available"])
        self.assertFalse(by_model["together:openai/gpt-image-2"]["available"])
        video = next(route for route in status["routes"] if route["id"] == "auto:video")
        self.assertTrue(next(entry for entry in video["candidates"] if entry["model"].startswith("gemini:"))["available"])
        self.save("auto:image-probe", ["gguu:gpt-image-2.5-sunburst", "xai:grok-imagine-image-2.0", "together:openai/gpt-image-2"])
        response, make_request = self.post("/v1/media/probe", {"route": "auto:image-probe"},
                                           [upstream(200, IMAGE), upstream(402, {"error": {"message": "insufficient balance"}})])
        report = response.get_json()
        self.assertEqual(report["working"], ["gguu:gpt-image-2.5-sunburst"])
        self.assertEqual([entry.get("status") for entry in report["candidates"]], [200, 402, None])
        self.assertEqual(json.loads(make_request.call_args_list[1].kwargs["data"])["quality"], "low")
        self.assertEqual(make_request.call_count, 2, "unavailable candidates are not probed")


class VideoJobTest(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        patcher = patch.object(self.app_module.AuthService, "get_api_key", side_effect=lambda provider: KEYS.get(provider))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_video_jobs_fail_over_at_creation_then_poll_and_download_on_one_provider(self):
        calls = []
        def provider(method, url, **kwargs):
            calls.append((method, url, kwargs.get("json")))
            if "predictLongRunning" in url:
                return upstream(429, {"error": {"message": "quota"}})
            if url.endswith("/v1/videos/generations"):
                return upstream(200, {"request_id": "req-1"})
            if url.endswith("/v1/videos/req-1"):
                done = len([call for call in calls if call[1].endswith("req-1")]) > 1
                return upstream(200, {"status": "done", "video": {"url": "https://vidgen.x.ai/v.mp4"}} if done else {"status": "pending"})
            raise AssertionError(url)
        with patch("services.video_generation.requests.request", side_effect=provider):
            created = self.client.post("/v1/videos", headers=ADMIN, json={"prompt": "An eagle over mountains", "seconds": 10})
            self.assertEqual(created.status_code, 200)
            job = created.get_json()
            self.assertEqual((job["status"], job["model"], job["resolution"]), ("queued", "xai:grok-imagine-video-1.5", "1080p"))
            self.assertEqual(created.headers["X-MultiLLM-Auto-Attempts"], "2")
            self.assertEqual(calls[1][2], {"model": "grok-imagine-video-1.5", "prompt": "An eagle over mountains", "duration": 10,
                                           "aspect_ratio": "16:9", "resolution": "1080p"})
            pending = self.client.get(f"/v1/videos/{job['id']}", headers=ADMIN).get_json()
            self.assertEqual(pending["status"], "in_progress")
            done = self.client.get(f"/v1/videos/{job['id']}", headers=ADMIN).get_json()
            self.assertEqual(done["status"], "completed")
            self.assertTrue(done["content_url"].endswith(f"/v1/videos/{job['id']}/content"))
        stream = requests.Response()
        stream.status_code = 200
        stream.raw = __import__("io").BytesIO(b"mp4-bytes")
        stream.headers["Content-Type"] = "video/mp4"
        with patch("services.video_generation.requests.request", side_effect=provider), \
                patch("services.video_generation.requests.get", return_value=stream) as download:
            content = self.client.get(f"/v1/videos/{job['id']}/content", headers=ADMIN)
        self.assertEqual((content.status_code, content.data, content.mimetype), (200, b"mp4-bytes", "video/mp4"))
        self.assertEqual(download.call_args.args[0], "https://vidgen.x.ai/v.mp4")

    def test_video_jobs_belong_to_their_creator_and_tampered_ids_are_unknown(self):
        from services import video_generation
        with self.app.app_context():
            job_id = video_generation.issue_job_id("someone-else", "openai", "sora-2", "video_123")
        self.assertEqual(self.client.get(f"/v1/videos/{job_id}", headers=ADMIN).status_code, 404)
        with self.app.app_context():
            mine = video_generation.issue_job_id("admin", "openai", "sora-2", "video_123")
        self.assertEqual(self.client.get(f"/v1/videos/{mine[:-1]}0", headers=ADMIN).status_code, 404)
        for body in ({}, {"prompt": "x", "seconds": 60}, {"prompt": "x", "aspect_ratio": "21:9"},
                     {"prompt": "x", "image_url": "http://insecure.example/a.png"}):
            self.assertEqual(self.client.post("/v1/videos", headers=ADMIN, json=body).status_code, 400, body)

    def test_an_ambiguous_video_creation_is_never_started_on_another_provider(self):
        def provider(method, url, **kwargs):
            raise requests.exceptions.ReadTimeout("slow")
        with patch("services.video_generation.requests.request", side_effect=provider) as send:
            response = self.client.post("/v1/videos", headers=ADMIN, json={"prompt": "x"})
        self.assertEqual(response.status_code, 504)
        self.assertEqual(send.call_count, 1)
