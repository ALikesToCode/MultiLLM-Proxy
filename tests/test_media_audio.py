"""Embeddings, speech and transcription on media routes, and precedence over the intelligence path."""

import io
import json
import os
from unittest.mock import patch

import requests
from flask import Response

from services.auto_route_service import AutoRouteService
from services.intelligence_store import IntelligenceStore
from tests.test_intelligence_policy import candidate, policy
from tests.unified_api_test_case import UnifiedApiTestCase

KEYS = {"openai": "openai-test-key", "nanogpt": "nanogpt-test-key", "together": "together-test-key",
        "gemini": "gemini-test-key"}
ADMIN = {"Authorization": "Bearer admin-test-key"}
VECTORS = {"object": "list", "data": [{"object": "embedding", "index": 0, "embedding": [0.1, 0.2]}],
           "model": "text-embedding-3-small"}


def upstream(status, body, content_type="application/json", **attributes):
    response = requests.Response()
    response.status_code = status
    response._content = body if isinstance(body, bytes) else json.dumps(body).encode()
    response._content_consumed = True
    response.headers["Content-Type"] = content_type
    for name, value in attributes.items():
        setattr(response, name, value)
    return response


class MediaAudioRouteTest(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        os.environ["INTELLIGENCE_REQUIRE_DURABLE_STORAGE"] = "false"
        for name, value in {
            "get_api_key": lambda provider: KEYS.get(provider),
            "get_api_keys": lambda provider: [KEYS[provider]] if provider in KEYS else [],
        }.items():
            patcher = patch.object(self.app_module.AuthService, name, side_effect=value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def post(self, path, transport, **kwargs):
        with patch.object(self.app_module.ProxyService, "make_request", side_effect=transport) as make_request:
            response = self.client.post(path, headers=kwargs.pop("headers", ADMIN), **kwargs)
        return response, make_request

    def test_auto_embed_is_the_default_and_moves_on_only_after_a_refusal(self):
        response, make_request = self.post("/v1/embeddings", [upstream(429, {"error": {"message": "slow down"}}),
                                                              upstream(200, VECTORS)], json={"input": ["hello"]})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), VECTORS)
        first, second = make_request.call_args_list
        self.assertEqual(first.kwargs["url"], "https://api.openai.com/v1/embeddings")
        self.assertEqual(second.kwargs["url"], "https://nano-gpt.com/api/v1/embeddings")
        self.assertEqual(json.loads(second.kwargs["data"]), {"input": ["hello"], "model": "text-embedding-3-small"})
        self.assertEqual(response.headers["X-MultiLLM-Auto-Route"], "auto:embed")
        self.assertEqual(response.headers["X-MultiLLM-Auto-Selected-Model"], "nanogpt:text-embedding-3-small")
        for failure in (upstream(500, {"error": {"message": "boom"}}),
                        upstream(502, {"error": {"message": "timeout"}}, multillm_transport_failure="timeout")):
            response, make_request = self.post("/v1/embeddings", [failure, upstream(200, VECTORS)],
                                               json={"model": "auto:embed", "input": "hello"})
            self.assertEqual(make_request.call_count, 1, "a possibly billed call is never repeated")
            self.assertEqual(response.status_code, failure.status_code)

    def test_explicit_models_reach_each_provider_path(self):
        response, make_request = self.post("/v1/embeddings", [upstream(200, VECTORS)],
                                           json={"model": "gemini:gemini-embedding-001", "input": "hello", "dimensions": 768})
        self.assertEqual(response.status_code, 200)
        forwarded = make_request.call_args.kwargs
        self.assertEqual(forwarded["url"], "https://generativelanguage.googleapis.com/v1beta/openai/embeddings")
        self.assertIn("gemini-test-key", forwarded["headers"]["Authorization"])
        self.assertEqual(json.loads(forwarded["data"])["dimensions"], 768)
        for body in ({"model": "xai:grok-embed", "input": "x"}, {"model": "openai:text-embedding-3-small"},
                     {"model": "openai:text-embedding-3-small", "input": "x", "extra": 1},
                     {"model": "openai:text-embedding-3-small", "input": "x", "encoding_format": "hex"}):
            response, make_request = self.post("/v1/embeddings", [], json=body)
            self.assertEqual(response.status_code, 400, body)
            make_request.assert_not_called()

    def test_speech_fails_over_to_workers_ai_aura(self):
        os.environ["CLOUDFLARE_AI_ENABLED"] = "true"
        sent = {}

        def post(path, payload, timeout):
            sent.update(path=path, payload=payload)
            return Response(b"aura-audio", status=200, content_type="audio/mpeg")

        with patch("services.cloudflare_ai.post", side_effect=post):
            response, make_request = self.post("/v1/audio/speech", [upstream(402, {"error": {"message": "no credit"}})],
                                               json={"input": "Hello there", "voice": "coral"})
        self.assertEqual((response.status_code, response.data, response.mimetype), (200, b"aura-audio", "audio/mpeg"))
        openai = json.loads(make_request.call_args.kwargs["data"])
        self.assertEqual((openai["model"], openai["voice"], openai["response_format"]), ("gpt-4o-mini-tts", "coral", "mp3"))
        self.assertEqual(sent["path"], "/v1/audio/speech")
        self.assertEqual(sent["payload"]["model"], "@cf/deepgram/aura-2-en")
        self.assertEqual(response.headers["X-MultiLLM-Auto-Selected-Model"], "cloudflare:@cf/deepgram/aura-2-en")

    def test_transcription_uploads_the_file_and_skips_workers_ai_for_large_audio(self):
        os.environ["CLOUDFLARE_AI_ENABLED"] = "true"
        AutoRouteService.save_route("auto:stt-test", ["cloudflare:@cf/openai/whisper-large-v3-turbo",
                                                      "together:openai/whisper-large-v3"], self.app.config["API_BASE_URLS"])
        with patch("services.cloudflare_ai.post") as cloudflare:
            response, make_request = self.post("/v1/audio/transcriptions", [upstream(200, {"text": "hello"})], data={
                "model": "auto:stt-test", "language": "en",
                "file": (io.BytesIO(b"\x00" * (8 * 1024 * 1024 + 1)), "clip.mp3")}, content_type="multipart/form-data")
        self.assertEqual(response.get_json(), {"text": "hello"})
        cloudflare.assert_not_called()
        forwarded = make_request.call_args.kwargs
        self.assertEqual(forwarded["url"], "https://api.together.xyz/v1/audio/transcriptions")
        self.assertTrue(forwarded["headers"]["Content-Type"].startswith("multipart/form-data"))
        self.assertIn(b'name="model"\r\n\r\nopenai/whisper-large-v3', forwarded["data"])
        self.assertIn(b'filename="audio.mp3"', forwarded["data"])

        sent = {}

        def post(path, payload, timeout):
            sent.update(path=path, payload=payload)
            return Response(json.dumps({"text": "short clip"}), status=200, content_type="application/json")

        with patch("services.cloudflare_ai.post", side_effect=post):
            response, _ = self.post("/v1/audio/transcriptions", [], data={
                "model": "auto:stt-test", "response_format": "text",
                "file": (io.BytesIO(b"RIFF-audio"), "clip.wav")}, content_type="multipart/form-data")
        self.assertEqual((response.data, response.mimetype), (b"short clip", "text/plain"))
        self.assertEqual(sent["payload"]["audio"], "UklGRi1hdWRpbw==")
        for data in ({"file": (io.BytesIO(b"x"), "clip.exe")}, {"file": (io.BytesIO(b"x"), "clip.wav"), "response_format": "srt"}):
            response, make_request = self.post("/v1/audio/transcriptions", [], data=data, content_type="multipart/form-data")
            self.assertEqual(response.status_code, 400)
            make_request.assert_not_called()

    def test_the_intelligence_policy_keeps_its_principals_and_pinned_models(self):
        IntelligenceStore.seed(policy(media={"embeddings": {
            "candidate": candidate("openai:embed", capabilities=[]), "dimensions": 3, "max_input_bytes": 4096,
            "daily_requests": 4, "principal_daily_requests": 4}}))
        with patch("routes.intelligence_media._dispatch", return_value=Response("pinned", status=200)) as pinned:
            response, make_request = self.post("/v1/embeddings", [], json={"model": "openai:embed", "input": "x"})
            self.assertEqual(response.data, b"pinned")
            with patch.object(self.app_module.AuthService, "verify_api_key", return_value={
                    "id": "integration:omni", "username": "integration:omni", "scopes": ["embeddings"], "is_admin": False}):
                response, _ = self.post("/v1/embeddings", [], json={"model": "auto:embed", "input": "x"})
            self.assertEqual(response.data, b"pinned")
        self.assertEqual(pinned.call_count, 2)
        make_request.assert_not_called()
        response, make_request = self.post("/v1/embeddings", [upstream(200, VECTORS)],
                                           json={"model": "openai:text-embedding-3-small", "input": "x"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(make_request.call_args.kwargs["url"], "https://api.openai.com/v1/embeddings")

    def test_media_providers_lists_every_media_route_by_kind(self):
        status = self.client.get("/v1/media/providers", headers=ADMIN).get_json()
        kinds = {route["id"]: route["kind"] for route in status["routes"]}
        self.assertEqual({route: kinds.get(route) for route in ("auto:image", "auto:image-edit", "auto:video", "auto:embed",
                                                                "auto:tts", "auto:stt")},
                         {"auto:image": "image", "auto:image-edit": "image_edit", "auto:video": "video",
                          "auto:embed": "embeddings", "auto:tts": "speech", "auto:stt": "transcriptions"})
        self.assertNotIn("auto:glm-5.2", kinds)
        self.assertEqual((status["storage"], status["batches"], status["webhooks"]), (False, False, False))
        embed = {entry["model"]: entry for entry in next(route for route in status["routes"] if route["id"] == "auto:embed")["candidates"]}
        self.assertTrue(embed["openai:text-embedding-3-small"]["available"])
        edit = {entry["model"]: entry for entry in next(route for route in status["routes"]
                                                        if route["id"] == "auto:image-edit")["candidates"]}
        self.assertFalse(edit["cloudflare:openai/gpt-image-2.5-sunburst"]["available"])

    def test_model_listing_never_offers_audio_or_embedding_routes_for_chat(self):
        from services.media_catalog import is_speech_or_embedding_model

        for model in ("text-embedding-3-small", "gemini-embedding-001", "@cf/baai/bge-m3", "openai/whisper-large-v3",
                      "gpt-4o-mini-tts", "gpt-4o-mini-transcribe", "@cf/deepgram/aura-2-en", "whisper-1"):
            self.assertTrue(is_speech_or_embedding_model(model), model)
        for model in ("gpt-4o-mini", "glm-5.2", "gpt-image-2", "tts-something-chat"):
            self.assertFalse(is_speech_or_embedding_model(model), model)
        models = {model["id"]: model for model in self.client.get("/v1/models", headers=ADMIN).get_json()["data"]}
        for route in ("auto:embed", "auto:tts", "auto:stt"):
            self.assertFalse(any(models[route]["capabilities"].values()), route)

    def test_routes_never_read_the_policy_and_an_unreadable_policy_keeps_explicit_models_pinned(self):
        with patch.object(IntelligenceStore, "policy", side_effect=RuntimeError("store down")) as read_policy, \
                patch("routes.intelligence_media._dispatch", return_value=Response("pinned", status=503)) as pinned:
            response, _ = self.post("/v1/embeddings", [upstream(200, VECTORS)], json={"input": "x"})
            self.assertEqual(response.status_code, 200)
            read_policy.assert_not_called()
            response, make_request = self.post("/v1/embeddings", [], json={"model": "openai:text-embedding-3-small",
                                                                           "input": "x"})
        self.assertEqual(response.status_code, 503)
        pinned.assert_called_once()
        make_request.assert_not_called()
