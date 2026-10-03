"""Embeddings, speech and transcription on media routes, and precedence over the intelligence path."""

import base64
import io
import json
import os
from unittest.mock import patch

import requests
from flask import Response

from services import audio_codec
from services.auto_route_service import AutoRouteService
from services.intelligence_store import IntelligenceStore
from tests.test_intelligence_policy import candidate, policy
from tests.unified_api_test_case import UnifiedApiTestCase

KEYS = {"openai": "openai-test-key", "nanogpt": "nanogpt-test-key", "together": "together-test-key",
        "gemini": "gemini-test-key"}
ADMIN = {"Authorization": "Bearer admin-test-key"}
VECTORS = {"object": "list", "data": [{"object": "embedding", "index": 0, "embedding": [0.1, 0.2]}],
           "model": "text-embedding-3-small"}
GEMINI = "https://generativelanguage.googleapis.com/v1beta/models"
SAMPLES = bytes(range(256)) * 96  # 0.5 s of 24 kHz 16-bit mono PCM


def gemini_audio_reply(samples=SAMPLES, wav=True):
    """A Gemini TTS reply: 3.8 models send WAV, earlier ones headerless PCM."""
    data = audio_codec.wav_bytes(audio_codec.Pcm(samples, 24000)) if wav else samples
    mime = "audio/wav" if wav else "audio/L16;codec=pcm;rate=24000"
    return {"candidates": [{"content": {"role": "model", "parts": [
        {"inlineData": {"mimeType": mime, "data": base64.b64encode(data).decode()}}]}, "finishReason": "STOP"}]}


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

        refusals = [upstream(429, {"error": {"message": "quota"}}), upstream(429, {"error": {"message": "quota"}}),
                    upstream(402, {"error": {"message": "no credit"}})]
        with patch("services.cloudflare_ai.post", side_effect=post):
            response, make_request = self.post("/v1/audio/speech", refusals,
                                               json={"input": "Hello there", "voice": "coral"})
        self.assertEqual((response.status_code, response.data, response.mimetype), (200, b"aura-audio", "audio/mpeg"))
        self.assertEqual([call.kwargs["url"].rsplit("/", 1)[-1] for call in make_request.call_args_list],
                         ["gemini-3.8-flash-lite-tts:generateContent", "gemini-3.8-flash-tts:generateContent", "speech"])
        openai = json.loads(make_request.call_args.kwargs["data"])
        self.assertEqual((openai["model"], openai["voice"], openai["response_format"]), ("gpt-4o-mini-tts", "coral", "mp3"))
        self.assertEqual(sent["path"], "/v1/audio/speech")
        self.assertEqual(sent["payload"]["model"], "@cf/deepgram/aura-2-en")
        self.assertEqual(response.headers["X-MultiLLM-Auto-Selected-Model"], "cloudflare:@cf/deepgram/aura-2-en")

    def test_speech_runs_on_gemini_tts_with_its_own_auth_voice_and_style(self):
        hindi = "नमस्ते दोस्तों, आज की कहानी शुरू होती है।"
        response, make_request = self.post("/v1/audio/speech", [upstream(200, gemini_audio_reply())], json={
            "input": hindi, "voice": "coral", "instructions": "Warm documentary narrator", "speed": 1.2,
            "response_format": "wav"})
        self.assertEqual((response.status_code, response.mimetype), (200, "audio/wav"))
        self.assertEqual(audio_codec.parse_wav(response.data), audio_codec.Pcm(SAMPLES, 24000))
        self.assertEqual(response.headers["X-MultiLLM-Auto-Selected-Model"], "gemini:gemini-3.8-flash-lite-tts")
        forwarded = make_request.call_args.kwargs
        self.assertEqual(forwarded["url"], f"{GEMINI}/gemini-3.8-flash-lite-tts:generateContent")
        self.assertEqual(forwarded["headers"]["x-goog-api-key"], "gemini-test-key")
        self.assertNotIn("Authorization", forwarded["headers"])
        body = json.loads(forwarded["data"])
        self.assertEqual(body["contents"][0]["parts"][0], {
            "text": hindi, "speech_metadata": {"style": "Warm documentary narrator; speaking a little faster than usual"}})
        self.assertEqual(body["generationConfig"], {"responseModalities": ["AUDIO"], "speechConfig": {
            "voiceConfig": {"prebuiltVoiceConfig": {"voiceName": "Kore"}}}})

        for voice, expected in (("charon", {"prebuiltVoiceConfig": {"voiceName": "Charon"}}),
                                ("voice_abc123", {"voice": "voice_abc123"})):
            response, make_request = self.post("/v1/audio/speech", [upstream(200, gemini_audio_reply(wav=False))], json={
                "model": "gemini:gemini-3.8-flash-tts", "input": hindi, "voice": voice, "response_format": "pcm"})
            self.assertEqual((response.data, response.mimetype), (SAMPLES, "audio/pcm"))
            body = json.loads(make_request.call_args.kwargs["data"])
            self.assertEqual(body["generationConfig"]["speechConfig"]["voiceConfig"], expected)
            self.assertNotIn("speech_metadata", body["contents"][0]["parts"][0])

        response, _ = self.post("/v1/audio/speech", [upstream(200, gemini_audio_reply())], json={"input": hindi})
        self.assertEqual((response.status_code, response.mimetype), (200, "audio/mpeg"))
        self.assertIn(response.data[:2], (b"\xff\xf3", b"\xff\xfb", b"\xff\xf2", b"ID"))

    def test_gemini_speech_refusals_move_on_and_unservable_formats_skip_gemini(self):
        response, make_request = self.post("/v1/audio/speech", [upstream(200, b"opus-audio", "audio/ogg")],
                                           json={"input": "Hello", "response_format": "opus"})
        self.assertEqual(response.data, b"opus-audio")
        self.assertEqual(make_request.call_args.kwargs["url"], "https://api.openai.com/v1/audio/speech")
        self.assertEqual(make_request.call_count, 1, "Gemini returns no opus, so it is skipped before any request")

        blocked = upstream(200, {"promptFeedback": {"blockReason": "SAFETY"}})
        response, make_request = self.post("/v1/audio/speech", [blocked, upstream(200, gemini_audio_reply())],
                                           json={"input": "Hello", "response_format": "wav"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(make_request.call_args.kwargs["url"], f"{GEMINI}/gemini-3.8-flash-tts:generateContent")

        silent = upstream(200, {"candidates": [{"finishReason": "OTHER"}]})
        response, make_request = self.post("/v1/audio/speech", [silent, upstream(200, gemini_audio_reply())],
                                           json={"input": "Hello", "response_format": "wav"})
        self.assertEqual(response.status_code, 502)
        self.assertEqual(make_request.call_count, 1, "a reply without audio may be billed, so the route stops")
        for body in ({"model": "gemini:gemini-3.8-flash", "input": "Hello"},
                     {"model": "gemini:gemini-3.5-transcribe", "input": "Hello"}):
            response, make_request = self.post("/v1/audio/speech", [], json=body)
            self.assertEqual(response.status_code, 400, body)
            make_request.assert_not_called()

    def test_english_only_aura_is_skipped_for_other_scripts(self):
        os.environ["CLOUDFLARE_AI_ENABLED"] = "true"
        AutoRouteService.save_route("auto:tts-test", ["cloudflare:@cf/deepgram/aura-2-en", "openai:gpt-4o-mini-tts"],
                                    self.app.config["API_BASE_URLS"])
        with patch("services.cloudflare_ai.post", return_value=Response(b"aura", content_type="audio/mpeg")) as aura:
            response, make_request = self.post("/v1/audio/speech", [upstream(200, b"openai", "audio/mpeg")],
                                               json={"model": "auto:tts-test", "input": "भारत की कहानी"})
            self.assertEqual(response.data, b"openai")
            aura.assert_not_called()
            response, make_request = self.post("/v1/audio/speech", [], json={"model": "auto:tts-test",
                                                                            "input": "Café crème, señor!"})
            self.assertEqual(response.data, b"aura")
            make_request.assert_not_called()

    def test_transcription_runs_on_gemini_3_5_transcribe(self):
        # The shape gemini-3.5-transcribe returns: one audioTranscription segment per turn.
        reply = {"candidates": [{"content": {"role": "model", "parts": [
            {"audioTranscription": {"text": "नमस्ते"}}, {"audioTranscription": {"text": "दुनिया"}}]},
            "finishReason": "STOP"}]}
        response, make_request = self.post("/v1/audio/transcriptions", [upstream(200, reply)], data={
            "language": "hi", "prompt": "Kubernetes, BigQuery\nGemini",
            "file": (io.BytesIO(b"ID3-audio"), "clip.mp3")}, content_type="multipart/form-data")
        self.assertEqual(response.get_json(), {"text": "नमस्ते दुनिया"})
        self.assertEqual(response.headers["X-MultiLLM-Auto-Selected-Model"], "gemini:gemini-3.5-transcribe")
        forwarded = make_request.call_args.kwargs
        self.assertEqual(forwarded["url"], f"{GEMINI}/gemini-3.5-transcribe:generateContent")
        self.assertEqual(forwarded["headers"]["x-goog-api-key"], "gemini-test-key")
        self.assertEqual(json.loads(forwarded["data"]), {
            "contents": [{"role": "user", "parts": [{"inlineData": {"mimeType": "audio/mp3",
                                                                     "data": base64.b64encode(b"ID3-audio").decode()}}]}],
            "generationConfig": {"audioTranscriptionConfig": {"languageCodes": ["hi-IN"],
                                                              "customVocabulary": ["Kubernetes", "BigQuery", "Gemini"]}}})
        text_reply = {"candidates": [{"content": {"parts": [{"text": "नमस्ते दुनिया"}]}, "finishReason": "STOP"}]}
        response, make_request = self.post("/v1/audio/transcriptions", [upstream(200, text_reply)], data={
            "model": "gemini:gemini-3.5-transcribe", "language": "en-IN", "response_format": "text",
            "file": (io.BytesIO(b"RIFF"), "clip.wav")}, content_type="multipart/form-data")
        self.assertEqual((response.data.decode(), response.mimetype), ("नमस्ते दुनिया", "text/plain"))
        self.assertEqual(json.loads(make_request.call_args.kwargs["data"])["generationConfig"],
                         {"audioTranscriptionConfig": {"languageCodes": ["en-IN"]}})

        response, make_request = self.post("/v1/audio/transcriptions", [upstream(200, {"text": "large"})], data={
            "file": (io.BytesIO(b"\x00" * (14 * 1024 * 1024 + 1)), "clip.mp3")}, content_type="multipart/form-data")
        self.assertEqual(response.get_json(), {"text": "large"})
        self.assertEqual(make_request.call_args.kwargs["url"], "https://api.openai.com/v1/audio/transcriptions",
                         "audio above Gemini's inline limit goes to the next candidate unsent")

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
                                                                "auto:tts", "auto:tts-narration", "auto:stt")},
                         {"auto:image": "image", "auto:image-edit": "image_edit", "auto:video": "video",
                          "auto:embed": "embeddings", "auto:tts": "speech", "auto:tts-narration": "speech",
                          "auto:stt": "transcriptions"})
        self.assertNotIn("auto:glm-5.2", kinds)
        self.assertEqual((status["storage"], status["batches"], status["webhooks"]), (False, False, False))
        embed = {entry["model"]: entry for entry in next(route for route in status["routes"] if route["id"] == "auto:embed")["candidates"]}
        self.assertTrue(embed["openai:text-embedding-3-small"]["available"])
        speech = {entry["model"]: entry for entry in next(route for route in status["routes"]
                                                          if route["id"] == "auto:tts")["candidates"]}
        self.assertTrue(speech["gemini:gemini-3.8-flash-lite-tts"]["available"])
        edit = {entry["model"]: entry for entry in next(route for route in status["routes"]
                                                        if route["id"] == "auto:image-edit")["candidates"]}
        self.assertFalse(edit["cloudflare:openai/gpt-image-2.5-sunburst"]["available"])

    def test_model_listing_never_offers_audio_or_embedding_routes_for_chat(self):
        from services.media_catalog import is_speech_or_embedding_model

        for model in ("text-embedding-3-small", "gemini-embedding-001", "@cf/baai/bge-m3", "openai/whisper-large-v3",
                      "gpt-4o-mini-tts", "gpt-4o-mini-transcribe", "@cf/deepgram/aura-2-en", "whisper-1",
                      "gemini-3.8-flash-tts", "gemini-3.8-flash-lite-tts", "gemini-3.5-transcribe",
                      "gemini-3.1-flash-tts-preview"):
            self.assertTrue(is_speech_or_embedding_model(model), model)
        for model in ("gpt-4o-mini", "glm-5.2", "gpt-image-2", "tts-something-chat", "gemini-3.8-flash",
                      "gemini-3.5-flash-lite"):
            self.assertFalse(is_speech_or_embedding_model(model), model)
        models = {model["id"]: model for model in self.client.get("/v1/models", headers=ADMIN).get_json()["data"]}
        for route in ("auto:embed", "auto:tts", "auto:tts-narration", "auto:stt"):
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
