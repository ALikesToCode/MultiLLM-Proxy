import io
import json
from unittest.mock import patch

from services.control_plane_backup import capture
from services.intelligence_contract import GatewayError
from tests.intelligence_fixtures import IntelligenceApiTestCase, upstream
from tests.test_intelligence_policy import candidate


class IntelligenceMediaTests(IntelligenceApiTestCase):
    def media(self):
        self.seed(
            media={
                "transcriptions": {
                    "candidate": candidate("openai:transcribe", capabilities=["audio"]),
                    "max_input_bytes": 4096,
                    "daily_requests": 4,
                    "principal_daily_requests": 4,
                },
                "speech": {
                    "candidate": candidate("openai:speak", capabilities=["audio"]),
                    "voice": "pinned-voice",
                    "max_input_bytes": 4096,
                    "daily_requests": 4,
                    "principal_daily_requests": 4,
                },
                "embeddings": {
                    "candidate": candidate("openai:embed", capabilities=[]),
                    "dimensions": 3,
                    "max_input_bytes": 4096,
                    "daily_requests": 4,
                    "principal_daily_requests": 4,
                },
            }
        )

    def test_transcription_preserves_audio_and_returns_json_text(self):
        self.media()
        with self.requests(
            return_value=upstream({"text": "hello", "private": "secret"})
        ) as send:
            response = self.client.post(
                "/v1/audio/transcriptions",
                headers=self.headers,
                data={
                    "model": "openai:transcribe",
                    "file": (io.BytesIO(b"synthetic-audio"), "example.wav"),
                },
            )
        assert response.status_code == 200 and response.json == {"text": "hello"}
        assert send.call_count == 1 and send.call_args.kwargs["url"].endswith(
            "/v1/audio/transcriptions"
        )
        assert b"synthetic-audio" in send.call_args.kwargs["data"]
        assert b"openai:transcribe" not in send.call_args.kwargs["data"]

    def test_speech_is_binary_and_voice_and_model_are_pinned(self):
        self.media()
        with self.requests(
            return_value=upstream(
                b"synthetic-audio", headers={"Content-Type": "audio/mpeg"}
            )
        ) as send:
            response = self.client.post(
                "/v1/audio/speech",
                headers=self.headers,
                json={"model": "openai:speak", "input": "hello"},
            )
        assert response.status_code == 200 and response.data == b"synthetic-audio"
        assert json.loads(send.call_args.kwargs["data"])["voice"] == "pinned-voice"
        with self.requests() as send:
            response = self.client.post(
                "/v1/audio/speech",
                headers=self.headers,
                json={"model": "openai:speak", "input": "hello", "voice": "different"},
            )
        assert response.status_code == 400 and send.call_count == 0

    def test_speech_error_is_not_audio_even_with_a_binary_content_type(self):
        self.media()
        with self.requests(
            return_value=upstream(
                {"error": "private-provider-error"},
                headers={"Content-Type": "application/octet-stream"},
            )
        ) as send:
            response = self.client.post(
                "/v1/audio/speech",
                headers=self.headers,
                json={"model": "openai:speak", "input": "hello"},
            )
        assert response.status_code == 502 and send.call_count == 1
        assert response.json["error"]["code"] == "upstream_error"
        assert b"private-provider-error" not in response.data

    def test_speech_binary_content_type_matches_requested_format(self):
        self.media()
        with self.requests(
            return_value=upstream(
                b"synthetic-pcm", headers={"Content-Type": "application/octet-stream"}
            )
        ):
            response = self.client.post(
                "/v1/audio/speech",
                headers=self.headers,
                json={
                    "model": "openai:speak",
                    "input": "hello",
                    "response_format": "pcm",
                },
            )
        assert response.status_code == 200 and response.data == b"synthetic-pcm"
        assert response.content_type == "audio/pcm"

    def test_transcription_limit_includes_prompt_bytes(self):
        self.media()
        with self.requests() as send:
            response = self.client.post(
                "/v1/audio/transcriptions",
                headers=self.headers,
                data={
                    "model": "openai:transcribe",
                    "prompt": "x" * 4096,
                    "file": (io.BytesIO(b"synthetic-audio"), "example.wav"),
                },
            )
        assert response.status_code == 413 and send.call_count == 0

    def test_media_is_independently_configured_and_scoped(self):
        self.seed()
        # Intelligence principals always take the pinned path, which needs media settings.
        with self.requests() as send, patch.object(
            self.app_module.AuthService,
            "verify_api_key",
            return_value={"id": "integration:omni", "username": "integration:omni", "scopes": ["audio"],
                          "is_admin": False},
        ):
            response = self.client.post(
                "/v1/audio/speech",
                headers=self.headers,
                json={"model": "openai:small", "input": "hello"},
            )
        assert response.status_code == 503 and send.call_count == 0
        assert response.json["error"]["code"] == "media_not_configured"
        with patch.object(
            self.app_module.AuthService,
            "verify_api_key",
            return_value={"username": "limited", "scopes": ["chat"], "is_admin": False},
        ):
            response = self.client.post(
                "/v1/audio/speech", headers=self.headers, json={}
            )
        assert (
            response.status_code == 403
            and response.json["error"]["code"] == "insufficient_scope"
        )

    def test_pre_dispatch_capacity_failure_releases_the_allowance(self):
        self.media()
        with patch(
            "routes.intelligence_media.IntelligenceTransport.start",
            side_effect=GatewayError(
                "gateway_busy", "Transport capacity exhausted.", 503
            ),
        ):
            response = self.client.post(
                "/v1/audio/speech",
                headers=self.headers,
                json={"model": "openai:speak", "input": "hello"},
            )
        assert response.status_code == 503
        row = capture()["tables"]["intelligence_reservations"][0]
        assert row["state"] == "settled" and row["charged"] == 0

    def test_async_acceptance_is_single_submission_and_preserves_pending_status(self):
        self.media()
        with self.requests(
            return_value=upstream(
                {"id": "job-1", "status": "queued", "secret": "hidden"}, 202
            )
        ) as send:
            response = self.client.post(
                "/v1/audio/speech",
                headers=self.headers,
                json={"model": "openai:speak", "input": "hello"},
            )
        assert response.status_code == 202 and send.call_count == 1
        assert response.json == {
            "id": "job-1",
            "status": "queued",
            "model": "openai:speak",
        }

    def test_embeddings_require_exact_dimension_and_never_fallback(self):
        self.media()
        for vector, status in (([0.1, 0.2, 0.3], 200), ([0.1], 502)):
            with self.requests(
                return_value=upstream({"data": [{"index": 0, "embedding": vector}]})
            ) as send:
                response = self.client.post(
                    "/v1/embeddings",
                    headers=self.headers,
                    json={"model": "openai:embed", "input": "text", "dimensions": 3},
                )
            assert response.status_code == status and send.call_count == 1
        with self.requests() as send:
            response = self.client.post(
                "/v1/embeddings",
                headers=self.headers,
                json={"model": "openai:embed", "input": "text", "dimensions": 4},
            )
        assert response.status_code == 400 and send.call_count == 0

    def test_embedding_batches_preserve_indexes_and_reject_missing_vectors(self):
        self.media()
        vectors = [
            {"index": 1, "embedding": [1.0, 1.0, 1.0]},
            {"index": 0, "embedding": [0.0, 0.0, 0.0]},
        ]
        for data, status in (
            (vectors, 200),
            (vectors[:1], 502),
            ([vectors[0]] * 2, 502),
        ):
            with self.requests(return_value=upstream({"data": data})) as send:
                response = self.client.post(
                    "/v1/embeddings",
                    headers=self.headers,
                    json={"model": "openai:embed", "input": ["first", "second"]},
                )
            assert response.status_code == status and send.call_count == 1
            if status == 200:
                assert response.json["data"][0]["embedding"] == [0.0, 0.0, 0.0]
                assert response.json["data"][1]["embedding"] == [1.0, 1.0, 1.0]
