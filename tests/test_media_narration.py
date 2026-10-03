"""Storyboard narration: one file per shot, one voice, timed and padded to each shot."""

import base64
import json
import os
import struct
from unittest.mock import patch

from services import audio_codec
from tests.test_media_audio import ADMIN, KEYS, gemini_audio_reply, upstream
from tests.unified_api_test_case import UnifiedApiTestCase

RATE = 24000
GEMINI = "https://generativelanguage.googleapis.com/v1beta/models"


def pcm(seconds: float) -> bytes:
    return b"\x01\x00" * round(seconds * RATE)


def streamed_wav(seconds: float) -> bytes:
    """OpenAI streams WAV with unknown (0xFFFFFFFF) chunk sizes."""
    header = struct.pack("<4sI4s4sIHHIIHH4sI", b"RIFF", 0xFFFFFFFF, b"WAVE", b"fmt ", 16, 1, 1, RATE, RATE * 2, 2, 16,
                         b"data", 0xFFFFFFFF)
    return header + pcm(seconds)


class MediaNarrationTest(UnifiedApiTestCase):
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

    def narrate(self, body, transport):
        with patch.object(self.app_module.ProxyService, "make_request", side_effect=transport) as make_request:
            response = self.client.post("/v1/audio/narration", headers=ADMIN, json=body)
        return response, make_request

    def test_the_first_shot_fixes_the_voice_and_every_file_is_padded_to_its_shot(self):
        lengths = {"पहला दृश्य": 2.0, "दूसरा दृश्य": 1.5, "तीसरा दृश्य": 1.0}

        def gemini(**request):
            if request["url"].endswith("gemini-3.8-flash-tts:generateContent") and not hasattr(gemini, "refused"):
                gemini.refused = True
                return upstream(429, {"error": {"message": "quota"}})
            text = json.loads(request["data"])["contents"][0]["parts"][0]["text"]
            return upstream(200, gemini_audio_reply(pcm(lengths[text])))

        response, make_request = self.narrate({"voice": "Charon", "instructions": "Calm documentary narrator", "shots": [
            {"id": "s1", "input": "पहला दृश्य", "seconds": 3},
            {"id": "s2", "input": "दूसरा दृश्य", "start": 3.5, "end": 5.5, "voice": "Puck"},
            {"id": "s3", "input": "तीसरा दृश्य"}]}, gemini)
        self.assertEqual(response.status_code, 200)
        reply = response.get_json()
        self.assertEqual(reply["model"], "gemini:gemini-3.8-flash-lite-tts")
        urls = [call.kwargs["url"].rsplit("/", 1)[-1] for call in make_request.call_args_list]
        self.assertEqual(urls[:2], ["gemini-3.8-flash-tts:generateContent", "gemini-3.8-flash-lite-tts:generateContent"])
        self.assertEqual(set(urls[2:]), {"gemini-3.8-flash-lite-tts:generateContent"},
                         "after the first shot every shot keeps the same model")
        first = json.loads(make_request.call_args_list[1].kwargs["data"])
        self.assertEqual(first["generationConfig"]["speechConfig"]["voiceConfig"],
                         {"prebuiltVoiceConfig": {"voiceName": "Charon"}})
        self.assertEqual(first["contents"][0]["parts"][0]["speech_metadata"], {"style": "Calm documentary narrator"})

        s1, s2, s3 = reply["data"]
        self.assertEqual((s1["id"], s1["status"], s1["start"], s1["end"], s1["speech_seconds"], s1["audio_seconds"],
                          s1["fits"], s1["takes"]), ("s1", "succeeded", 0.0, 3.0, 2.0, 3.0, True, 1))
        self.assertEqual((s2["start"], s2["end"], s2["audio_seconds"]), (3.5, 5.5, 2.0))
        self.assertEqual((s3["start"], s3["end"], s3["audio_seconds"]), (5.5, 6.5, 1.0))
        self.assertNotIn("fits", s3, "a shot without a length is not timed")
        wav = audio_codec.parse_wav(base64.b64decode(s1["b64_audio"]))
        self.assertEqual((wav.rate, wav.seconds), (RATE, 3.0))
        self.assertEqual(wav.samples[:len(pcm(2.0))], pcm(2.0))
        self.assertEqual(set(wav.samples[len(pcm(2.0)):]), {0}, "padding is silence after the speech")
        self.assertEqual(reply["summary"], {"shots": 3, "succeeded": 3, "failed": 0, "overruns": 0, "seconds": 6.5})

    def test_an_overrun_is_retaken_faster_and_reported_when_it_still_does_not_fit(self):
        takes = iter([streamed_wav(2.5), streamed_wav(2.1)])
        response, make_request = self.narrate({"model": "openai:gpt-4o-mini-tts", "pad": False, "shots": [
            {"input": "A line that runs long", "seconds": 2}]}, lambda **request: upstream(200, next(takes), "audio/wav"))
        shot = response.get_json()["data"][0]
        self.assertEqual([json.loads(call.kwargs["data"])["speed"] for call in make_request.call_args_list], [1.0, 1.2])
        self.assertEqual(json.loads(make_request.call_args.kwargs["data"])["response_format"], "wav")
        self.assertEqual((shot["id"], shot["takes"], shot["speed"], shot["speech_seconds"], shot["fits"],
                          shot["overrun_seconds"], shot["audio_seconds"]), ("1", 2, 1.2, 2.1, False, 0.1, 2.1))
        self.assertEqual(response.get_json()["summary"]["overruns"], 1)

        takes = iter([streamed_wav(2.5)])
        response, make_request = self.narrate({"model": "openai:gpt-4o-mini-tts", "max_speed": 1, "shots": [
            {"input": "No retakes", "seconds": 2}]}, lambda **request: upstream(200, next(takes), "audio/wav"))
        self.assertEqual((make_request.call_count, response.get_json()["data"][0]["takes"]), (1, 1))

    def test_a_rate_limited_pinned_model_waits_instead_of_changing_voice(self):
        replies = iter([upstream(429, {"error": {"message": "slow down"}}), upstream(200, gemini_audio_reply(pcm(1)))])
        with patch("routes.media_narration.time.sleep") as sleep:
            response, make_request = self.narrate({"model": "gemini:gemini-3.8-flash-tts", "response_format": "mp3",
                                                   "shots": [{"input": "धन्यवाद", "seconds": 2}]},
                                                  lambda **request: next(replies))
        shot = response.get_json()["data"][0]
        self.assertEqual((shot["status"], make_request.call_count), ("succeeded", 2))
        sleep.assert_called_once()
        audio = base64.b64decode(shot["b64_audio"])
        self.assertIn(audio[:2], (b"\xff\xf3", b"\xff\xfb", b"\xff\xf2", b"ID"))

        failing = lambda **request: upstream(500, {"error": {"message": "backend error"}})  # noqa: E731
        response, make_request = self.narrate({"model": "gemini:gemini-3.8-flash-tts", "shots": [
            {"input": "एक"}, {"input": "दो"}]}, failing)
        reply = response.get_json()
        self.assertEqual([entry["status"] for entry in reply["data"]], ["failed", "failed"])
        self.assertEqual(reply["data"][0]["error"], {"status": 500, "message": "backend error"})
        self.assertEqual(make_request.call_count, 2, "a server error is never retried")

    def test_an_unexpected_error_fails_only_its_own_shot(self):
        def gemini(**request):
            if json.loads(request["data"])["contents"][0]["parts"][0]["text"] == "दो":
                raise RuntimeError("transport bug")
            return upstream(200, gemini_audio_reply(pcm(0.5)))

        response, _ = self.narrate({"model": "gemini:gemini-3.8-flash-tts", "shots": [
            {"input": "एक", "seconds": 1}, {"input": "दो", "seconds": 1}]}, gemini)
        self.assertEqual(response.status_code, 200)
        first, second = response.get_json()["data"]
        self.assertEqual((first["status"], second["status"]), ("succeeded", "failed"))
        self.assertEqual(second["error"], {"status": 502, "message": "The speech request failed"})

    def test_stored_shots_are_returned_as_gateway_links(self):
        os.environ["MEDIA_STORAGE_ENABLED"] = "true"
        with patch("services.media_storage.put_bytes", return_value={"id": "x", "size": 1, "content_type": "audio/wav"}) \
                as put:
            response, _ = self.narrate({"model": "gemini:gemini-3.8-flash-tts", "shots": [{"input": "एक", "seconds": 1}]},
                                       lambda **request: upstream(200, gemini_audio_reply(pcm(0.5))))
        shot = response.get_json()["data"][0]
        self.assertEqual(shot["status"], "succeeded", "signed links are made inside the shot's worker thread")
        self.assertNotIn("b64_audio", shot)
        self.assertRegex(shot["url"], rf"^http://localhost/v1/media/files/{shot['file_id']}\?expires=\d+&signature=")
        self.assertEqual((put.call_args.args[2], put.call_args.kwargs["kind"], put.call_args.kwargs["model"]),
                         ("audio/wav", "audio", "gemini:gemini-3.8-flash-tts"))
        self.assertEqual(audio_codec.parse_wav(put.call_args.args[1]).seconds, 1.0)

    def test_storyboards_are_validated_before_anything_is_generated(self):
        for body in ({}, {"shots": []}, {"shots": [{"input": ""}]}, {"shots": [{"input": "x", "seconds": 0}]},
                     {"shots": [{"input": "x", "end": 4}]}, {"shots": [{"input": "x", "start": 5, "end": 4}]},
                     {"shots": [{"input": "x", "start": 1, "end": 4, "seconds": 3}]},
                     {"shots": [{"id": "a", "input": "x"}, {"id": "a", "input": "y"}]},
                     {"shots": [{"input": "x", "speaker": "narrator"}]}, {"shots": [{"input": "x"}], "speed": 9},
                     {"shots": [{"input": "x"}], "max_speed": 2}, {"shots": [{"input": "x"}], "response_format": "opus"},
                     {"shots": [{"input": "x" * 4000}] * 16}, {"shots": [{"input": "x"}] * 65}):
            response, make_request = self.narrate(body, [])
            self.assertEqual(response.status_code, 400, body)
            make_request.assert_not_called()
