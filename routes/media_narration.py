"""Storyboard narration: one speech file per shot, timed to the shot.

`POST /v1/audio/narration` takes a storyboard's shots (text plus `seconds`, or `start`
and `end`) and returns one WAV or MP3 per shot. One voice must carry the whole film, so
the first shot that succeeds through the route fixes the model; every other shot uses
that model, and a rate-limited shot waits and tries the same model again rather than
moving to another voice. Each take is measured. A take longer than its shot is retaken
once, faster (up to `max_speed`); speech is never cut, so a take that still overruns is
reported with `fits: false`. Shorter takes are padded with trailing silence to the shot
length, so placing each file at its shot's start lines the narration up with the cut.
"""

from __future__ import annotations

import base64
import json
import logging
import math
import re
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from flask import Response, copy_current_request_context, jsonify

from error_handlers import APIError
from request_validation import json_object_body
from route_helpers import api_auth_required
from routes.media_audio import OPERATIONS, MediaRequest, run_media_request, validate_speech_fields
from services import audio_codec, gemini_audio, media_storage
from services.auto_route_service import AutoRouteService
from services.model_registry import ModelRegistry

logger = logging.getLogger(__name__)

DEFAULT_NARRATION_ROUTE = "auto:tts-narration"
MAX_SHOTS = 64
MAX_TOTAL_CHARS = 60000
MAX_SHOT_SECONDS = 600.0
SHOT_PARALLELISM = 4
DEFAULT_MAX_SPEED = 1.2
MAX_SPEED_LIMIT = 1.5
# A take this much longer than its shot still fits; below a frame at 24 fps.
FIT_TOLERANCE_SECONDS = 0.04
# A retake aims slightly under the shot, because speed changes length only roughly.
RETAKE_MARGIN = 1.03
RATE_LIMIT_RETRIES = 2
MAX_RETRY_WAIT_SECONDS = 20.0
# Without media storage, audio is returned as base64 up to this many bytes in total.
MAX_INLINE_AUDIO_BYTES = 48 * 1024 * 1024
CONTENT_TYPES = {"wav": "audio/wav", "mp3": "audio/mpeg"}
SHOT_ID = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
_BODY_FIELDS = frozenset({"model", "voice", "instructions", "speed", "max_speed", "pad", "response_format", "shots"})
_SHOT_FIELDS = frozenset({"id", "input", "voice", "instructions", "start", "end", "seconds"})


@dataclass(frozen=True)
class Shot:
    index: int
    id: str
    fields: dict
    start: float | None
    seconds: float | None


@dataclass(frozen=True)
class Narration:
    model: str
    speed: float
    max_speed: float
    pad: bool
    response_format: str
    shots: tuple[Shot, ...]


@dataclass(frozen=True)
class Take:
    status: int
    model: str
    speed: float
    pcm: audio_codec.Pcm | None = None
    error: str = ""


def _number(value: object, name: str, low: float, high: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) \
            or not low <= value <= high:
        raise APIError(f"{name} must be a number from {low:g} to {high:g}", status_code=400)
    return float(value)


def _voice(value: object, name: str) -> object:
    if isinstance(value, dict) and set(value) == {"id"}:
        value_id = value["id"]
    else:
        value_id = value
    if not isinstance(value_id, str) or not 1 <= len(value_id) <= 128:
        raise APIError(f"{name} must be a voice name or {{\"id\": ...}}", status_code=400)
    return value


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or len(value) > 4096:
        raise APIError(f"{name} must be a string of at most 4096 characters", status_code=400)
    return value


def parse_narration(body: dict) -> Narration:
    if set(body) - _BODY_FIELDS:
        raise APIError(f"Narration accepts {', '.join(sorted(_BODY_FIELDS))}", status_code=400)
    model = body.get("model") or DEFAULT_NARRATION_ROUTE
    if not isinstance(model, str):
        raise APIError("model must be a string", status_code=400)
    speed = _number(body.get("speed", 1.0), "speed", 0.25, 4.0)
    max_speed = _number(body.get("max_speed", DEFAULT_MAX_SPEED), "max_speed", 1.0, MAX_SPEED_LIMIT)
    pad = body.get("pad", True)
    if not isinstance(pad, bool):
        raise APIError("pad must be true or false", status_code=400)
    response_format = body.get("response_format", "wav")
    if response_format not in CONTENT_TYPES or (response_format == "mp3" and not audio_codec.mp3_available()):
        formats = [name for name in CONTENT_TYPES if name != "mp3" or audio_codec.mp3_available()]
        raise APIError(f"response_format must be one of: {', '.join(formats)}", status_code=400)
    defaults = {}
    if body.get("voice") is not None:
        defaults["voice"] = _voice(body["voice"], "voice")
    if body.get("instructions") is not None:
        defaults["instructions"] = _text(body["instructions"], "instructions")

    raw = body.get("shots")
    if not isinstance(raw, list) or not 1 <= len(raw) <= MAX_SHOTS:
        raise APIError(f"shots must be a list of 1 to {MAX_SHOTS} objects", status_code=400)
    shots, seen, characters = [], set(), 0
    for index, item in enumerate(raw):
        where = f"shots[{index}]"
        if not isinstance(item, dict) or set(item) - _SHOT_FIELDS:
            raise APIError(f"{where} must be an object with {', '.join(sorted(_SHOT_FIELDS))}", status_code=400)
        shot_id = item.get("id", str(index + 1))
        if not isinstance(shot_id, str) or not SHOT_ID.fullmatch(shot_id) or shot_id in seen:
            raise APIError(f"{where}.id must be unique: 1 to 64 of A-Z a-z 0-9 _ . : -", status_code=400)
        seen.add(shot_id)
        start = _number(item["start"], f"{where}.start", 0.0, 86400.0) if item.get("start") is not None else None
        seconds = item.get("seconds")
        if item.get("end") is not None:
            if start is None or seconds is not None:
                raise APIError(f"{where}.end needs start and replaces seconds", status_code=400)
            seconds = _number(item["end"], f"{where}.end", 0.0, 86400.0 + MAX_SHOT_SECONDS) - start
        if seconds is not None:
            seconds = _number(seconds, f"{where}.seconds (end minus start)", 0.1, MAX_SHOT_SECONDS)
        fields = {**defaults, "input": item.get("input"), "speed": speed, "response_format": "wav"}
        if item.get("voice") is not None:
            fields["voice"] = _voice(item["voice"], f"{where}.voice")
        if item.get("instructions") is not None:
            fields["instructions"] = _text(item["instructions"], f"{where}.instructions")
        try:
            validate_speech_fields(fields)
        except APIError as error:
            raise APIError(f"{where}: {error.message}", status_code=400) from error
        characters += len(fields["input"])
        shots.append(Shot(index, shot_id, fields, start, seconds))
    if characters > MAX_TOTAL_CHARS:
        raise APIError(f"shots may hold at most {MAX_TOTAL_CHARS} characters of input in total", status_code=400)
    return Narration(model, speed, max_speed, pad, response_format, tuple(shots))


def _error_message(body: bytes, status: int) -> str:
    try:
        parsed = json.loads(body)
    except ValueError:
        parsed = None
    error = parsed.get("error") if isinstance(parsed, dict) else None
    if isinstance(error, dict):
        message = error.get("message")
    elif isinstance(parsed, dict):
        message = parsed.get("message") or error
    else:
        message = None
    return (message if isinstance(message, str) and message else f"Speech failed with HTTP {status}")[:300]


def _retry_after(headers, attempt: int) -> float:
    try:
        wait = float(headers.get("Retry-After", ""))
    except ValueError:
        wait = 2.0 * (attempt + 1)
    return min(max(wait, 0.5), MAX_RETRY_WAIT_SECONDS)


class NarrationRun:
    """Synthesizes, fits, encodes and stores one narration request's shots."""

    def __init__(self, narration: Narration, dispatch: Callable[[MediaRequest], Response], owner: str,
                 sleep: Callable[[float], None] | None = None):
        self.narration, self.dispatch, self.owner = narration, dispatch, owner
        self.sleep = sleep or time.sleep

    def take(self, fields: dict, model: str) -> Take:
        """One synthesis; a pinned model that is rate limited waits and tries again."""
        media = MediaRequest(OPERATIONS["speech"], model, fields)
        pinned, attempt = not AutoRouteService.is_auto_route(model), 0
        while True:
            try:
                response = self.dispatch(media)
            except APIError as error:
                return Take(error.status_code, model, fields["speed"], error=error.message[:300])
            try:
                body = response.get_data()
            finally:
                response.close()
            if response.status_code == 429 and pinned and attempt < RATE_LIMIT_RETRIES:
                # A rate limit is a refusal, so the same model can be asked again.
                self.sleep(_retry_after(response.headers, attempt))
                attempt += 1
                continue
            served = response.headers.get("X-MultiLLM-Auto-Selected-Model") or model
            if response.status_code >= 400:
                return Take(response.status_code, served, fields["speed"], error=_error_message(body, response.status_code))
            try:
                return Take(200, served, fields["speed"], pcm=audio_codec.parse_wav(body))
            except audio_codec.AudioFormatError:
                return Take(502, served, fields["speed"], error=f"{served} did not return 16-bit WAV audio")

    def retake_speed(self, take: Take, speech: float, seconds: float) -> float | None:
        """A faster speed that should fit `speech` into the shot, or None when a retake cannot help."""
        provider, _ = ModelRegistry.parse_model_id(take.model)
        target = min(self.narration.max_speed, take.speed * speech / seconds * RETAKE_MARGIN)
        if provider == "cloudflare":
            return None  # Workers AI Aura ignores speed.
        if provider == "gemini":
            # Gemini takes pace as a spoken direction, so only a different direction changes anything.
            target = min(self.narration.max_speed, max(target, 1.1))
            return target if gemini_audio.pace(target) != gemini_audio.pace(take.speed) else None
        return round(target, 3) if target > take.speed + 0.01 else None

    def shot(self, shot: Shot, model: str) -> dict:
        try:
            return self.narrate(shot, model)
        except Exception as error:  # One failed shot must not discard the others.
            logger.warning("Narration shot failed (%s)", type(error).__name__)
            return {"index": shot.index, "id": shot.id, "status": "failed", "model": model,
                    "error": {"status": 502, "message": "The speech request failed"}}

    def narrate(self, shot: Shot, model: str) -> dict:
        entry = {"index": shot.index, "id": shot.id}
        take = self.take(shot.fields, model)
        takes = 1
        if take.pcm is not None and shot.seconds and take.pcm.seconds > shot.seconds + FIT_TOLERANCE_SECONDS:
            speed = self.retake_speed(take, take.pcm.seconds, shot.seconds)
            if speed is not None:
                takes = 2
                retake = self.take({**shot.fields, "speed": speed}, take.model)
                if retake.pcm is not None and retake.pcm.seconds < take.pcm.seconds:
                    take = retake
        if take.pcm is None:
            entry.update(status="failed", model=take.model, error={"status": take.status, "message": take.error})
            return entry
        audio = audio_codec.pad_to(take.pcm, shot.seconds) if self.narration.pad and shot.seconds else take.pcm
        data = (audio_codec.wav_bytes(audio) if self.narration.response_format == "wav"
                else audio_codec.encode_mp3(audio))
        speech = take.pcm.seconds
        entry.update(status="succeeded", model=take.model, speed=round(take.speed, 3), takes=takes,
                     speech_seconds=round(speech, 3), audio_seconds=round(audio.seconds, 3),
                     sample_rate=audio.rate, bytes=len(data))
        if shot.seconds:
            overrun = speech - shot.seconds
            entry["fits"] = overrun <= FIT_TOLERANCE_SECONDS
            if not entry["fits"]:
                entry["overrun_seconds"] = round(overrun, 3)
        entry["_data"] = data
        self.store(entry)
        return entry

    def store(self, entry: dict) -> None:
        if not media_storage.enabled():
            return
        file_id = media_storage.new_file_id()
        try:
            media_storage.put_bytes(file_id, entry["_data"], CONTENT_TYPES[self.narration.response_format],
                                    owner=self.owner, kind="audio", model=entry["model"])
        except media_storage.StorageError:
            return  # The audio is already generated; it is returned inline instead.
        del entry["_data"]
        entry.update(file_id=file_id, url=media_storage.file_url(file_id))

    def run(self) -> dict:
        model, shots = self.narration.model, list(self.narration.shots)
        entries = {}
        if AutoRouteService.is_auto_route(model):
            # The first shot that succeeds through the route fixes the voice for the rest.
            while shots:
                shot = shots.pop(0)
                entries[shot.index] = self.shot(shot, model)
                if entries[shot.index]["status"] == "succeeded":
                    model = entries[shot.index]["model"]
                    break
        if shots:
            with ThreadPoolExecutor(max_workers=min(SHOT_PARALLELISM, len(shots))) as pool:
                futures = [pool.submit(copy_current_request_context(lambda shot=shot: self.shot(shot, model)))
                           for shot in shots]
                for shot, future in zip(shots, futures, strict=True):
                    entries[shot.index] = future.result()
        return self.reply(model, [entries[index] for index in sorted(entries)])

    def reply(self, model: str, entries: list[dict]) -> dict:
        cursor, inline = 0.0, 0
        for shot, entry in zip(self.narration.shots, entries, strict=True):
            start = shot.start if shot.start is not None else cursor
            length = shot.seconds or (entry["audio_seconds"] if entry["status"] == "succeeded" else 0.0)
            entry["start"], entry["end"] = round(start, 3), round(start + length, 3)
            cursor = start + length
            data = entry.pop("_data", None)
            if data is not None:
                inline += len(data)
                if inline <= MAX_INLINE_AUDIO_BYTES:
                    entry["b64_audio"] = base64.b64encode(data).decode("ascii")
                else:
                    for name in ("fits", "overrun_seconds", "bytes"):
                        entry.pop(name, None)
                    entry.update(status="failed", error={
                        "status": 413, "message": "The audio could not be stored and is too large to return inline; "
                                                  "send fewer shots per request"})
        succeeded = [entry for entry in entries if entry["status"] == "succeeded"]
        return {"object": "audio.narration", "model": model, "response_format": self.narration.response_format,
                "data": entries,
                "summary": {"shots": len(entries), "succeeded": len(succeeded), "failed": len(entries) - len(succeeded),
                            "overruns": sum(1 for entry in succeeded if entry.get("fits") is False),
                            "seconds": round(cursor, 3)}}


def register_media_narration_routes(app, csrf, auth_service_cls, metrics_service_cls, proxy_service_cls,
                                    owner: Callable[[], str]) -> None:
    def dispatch(media: MediaRequest):
        return run_media_request(media, app, auth_service_cls, metrics_service_cls, proxy_service_cls)

    @app.route("/v1/audio/narration", methods=["POST", "OPTIONS"])
    @csrf.exempt
    @api_auth_required(required_scope="audio")
    def audio_narration():
        # Integration keys never reach this view: authentication limits them to the
        # intelligence gateway's routes (services/intelligence_route_policy.py).
        narration = parse_narration(json_object_body())
        return jsonify(NarrationRun(narration, dispatch, owner()).run())
