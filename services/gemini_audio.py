"""Gemini text-to-speech and transcription behind the OpenAI audio endpoints.

`/v1/audio/speech` and `/v1/audio/transcriptions` reach Gemini's native `generateContent`
(the OpenAI-compatible prefix serves neither). Speech models (`gemini-3.8-flash-tts`,
`gemini-3.8-flash-lite-tts`) take the text as a verbatim transcript, so OpenAI's
`instructions` and `speed` become the turn's `speech_metadata.style`; they return 24 kHz
16-bit PCM (as WAV on 3.8 models), which is sent back as WAV, PCM or MP3. Transcription
(`gemini-3.5-transcribe`) takes the audio inline and returns plain text.
"""

from __future__ import annotations

import base64
import binascii
import json
import re

import requests
from flask import Response

from error_handlers import APIError
from services import audio_codec

SPEECH_MODEL = re.compile(r"gemini-[a-z0-9.-]*-tts(?:-[a-z0-9.]+)*")
TRANSCRIBE_MODEL = re.compile(r"gemini-[a-z0-9.-]*-transcribe(?:-[a-z0-9.]+)*")
# Base64 inflates audio by a third; this keeps an inline request under 20 MB.
MAX_INLINE_AUDIO_BYTES = 14 * 1024 * 1024
MAX_REPLY_BYTES = 64 * 1024 * 1024
SAMPLE_RATE = 24000
DEFAULT_VOICE = "Kore"
PREBUILT_VOICES = {name.lower(): name for name in (
    "Zephyr", "Puck", "Charon", "Kore", "Fenrir", "Leda", "Orus", "Aoede", "Callirrhoe", "Autonoe", "Enceladus",
    "Iapetus", "Umbriel", "Algieba", "Despina", "Erinome", "Algenib", "Rasalgethi", "Laomedeia", "Achernar",
    "Alnilam", "Schedar", "Gacrux", "Pulcherrima", "Achird", "Zubenelgenubi", "Vindemiatrix", "Sadachbia",
    "Sadaltager", "Sulafat")}
OPENAI_VOICES = frozenset({"alloy", "ash", "ballad", "coral", "echo", "fable", "nova", "onyx", "sage", "shimmer",
                           "verse", "marin", "cedar"})
_VOICE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_AUDIO_TYPES = {"flac": "audio/flac", "m4a": "audio/m4a", "mp3": "audio/mp3", "mp4": "audio/m4a", "mpeg": "audio/mpeg",
                "mpga": "audio/mpeg", "oga": "audio/ogg", "ogg": "audio/ogg", "opus": "audio/opus", "wav": "audio/wav",
                "webm": "audio/webm"}
# The locales Gemini 3.5 Transcribe accepts, keyed by the ISO 639-1 code OpenAI clients send.
_LOCALES = {code.split("-", 1)[0]: code for code in (
    "af-ZA am-ET ar-EG hy-AM as-IN az-AZ be-BY bn-IN bs-BA bg-BG my-MM ca-ES km-KH hr-HR cs-CZ da-DK nl-NL en-US "
    "et-EE fa-IR fi-FI fr-FR gl-ES ka-GE de-DE el-GR gu-IN ha-NG he-IL hi-IN hu-HU is-IS id-ID it-IT ja-JP jv-ID "
    "kn-IN kk-KZ ko-KR ky-KG lv-LV ln-CD lt-LT mk-MK ms-MY ml-IN mt-MT mr-IN mn-MN ne-NP nb-NO or-IN pl-PL pt-BR "
    "pa-IN ro-RO ru-RU sr-RS sd-Arab-IN sk-SK sl-SI es-419 sw-KE sv-SE tg-TJ te-IN th-TH tr-TR uk-UA uz-UZ "
    "vi-VN").split()}
_LOCALES.update({"zh": "cmn-Hans-CN", "yue": "yue-Hant-HK", "tl": "fil-PH", "iw": "he-IL", "no": "nb-NO"})
_BCP47 = re.compile(r"[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8}){1,3}")
_RATE = re.compile(r"rate=(\d{4,6})")
MAX_VOCABULARY = 1000


def speech_formats() -> tuple[str, ...]:
    return ("wav", "pcm", "mp3") if audio_codec.mp3_available() else ("wav", "pcm")


def voice_config(value: object) -> dict:
    """A prebuilt voice by name; custom (`voice_…`) and Voice Library IDs pass through.
    OpenAI voice names, which Gemini does not have, use the default voice."""
    if isinstance(value, dict):
        value = value.get("id")
    if not isinstance(value, str) or not _VOICE_ID.fullmatch(value) or value.lower() in OPENAI_VOICES:
        value = DEFAULT_VOICE
    prebuilt = PREBUILT_VOICES.get(value.lower())
    return {"prebuiltVoiceConfig": {"voiceName": prebuilt}} if prebuilt else {"voice": value}


def pace(speed: object) -> str | None:
    """Gemini has no numeric speed; the nearest spoken direction instead."""
    if isinstance(speed, bool) or not isinstance(speed, (int, float)):
        return None
    if speed >= 1.3:
        return "speaking rapidly"
    if speed >= 1.08:
        return "speaking a little faster than usual"
    if speed <= 0.77:
        return "speaking slowly"
    if speed <= 0.93:
        return "speaking a little slower than usual"
    return None


def speech_body(fields: dict) -> dict:
    part = {"text": fields["input"]}
    instructions = fields.get("instructions")
    style = "; ".join(item for item in (instructions.strip() if isinstance(instructions, str) else "",
                                        pace(fields.get("speed"))) if item)
    if style:
        part["speech_metadata"] = {"style": style}
    return {"contents": [{"role": "user", "parts": [part]}],
            "generationConfig": {"responseModalities": ["AUDIO"],
                                 "speechConfig": {"voiceConfig": voice_config(fields.get("voice"))}}}


def locale(language: object) -> str | None:
    """A BCP-47 locale for an OpenAI `language`; None leaves detection to the model."""
    if not isinstance(language, str):
        return None
    language = language.strip()
    if _BCP47.fullmatch(language):
        return language
    return _LOCALES.get(language.lower())


def transcription_body(fields: dict, audio: bytes, filename: str) -> dict:
    config = {}
    code = locale(fields.get("language"))
    if code:
        config["languageCodes"] = [code]
    prompt = fields.get("prompt")
    if isinstance(prompt, str):
        # Gemini takes vocabulary terms rather than a free-text prompt.
        terms = [term.strip() for term in re.split(r"[,\n]", prompt) if term.strip()]
        if terms:
            config["customVocabulary"] = terms[:MAX_VOCABULARY]
    body = {"contents": [{"role": "user", "parts": [{"inlineData": {
        "mimeType": _AUDIO_TYPES[filename.rsplit(".", 1)[-1]], "data": base64.b64encode(audio).decode("ascii")}}]}]}
    if config:
        body["generationConfig"] = {"audioTranscriptionConfig": config}
    return body


def read_reply(upstream: requests.Response) -> dict:
    """The JSON of a successful generateContent reply, or a refusal raised as an error."""
    try:
        data = bytearray()
        for chunk in upstream.iter_content(65536):
            data += chunk
            if len(data) > MAX_REPLY_BYTES:
                raise APIError("Gemini's reply is too large", status_code=502)
    finally:
        upstream.close()
    try:
        payload = json.loads(data)
    except ValueError:
        payload = None
    if not isinstance(payload, dict):
        raise APIError("Gemini returned an unreadable reply", status_code=502)
    feedback = payload.get("promptFeedback")
    reason = feedback.get("blockReason") if isinstance(feedback, dict) else None
    if reason:
        # The input was refused before anything was generated.
        raise APIError(f"Gemini refused the input ({str(reason)[:64]})", status_code=400)
    return payload


def _parts(payload: dict) -> list[dict]:
    candidates = payload.get("candidates")
    candidate = candidates[0] if isinstance(candidates, list) and candidates and isinstance(candidates[0], dict) else {}
    content = candidate.get("content")
    parts = content.get("parts") if isinstance(content, dict) else None
    if not isinstance(parts, list) or not parts:
        finish = str(candidate.get("finishReason") or "no candidate")[:64]
        raise APIError(f"Gemini returned no output ({finish})", status_code=502)
    return [part for part in parts if isinstance(part, dict)]


def speech_pcm(payload: dict) -> audio_codec.Pcm:
    """The reply's audio as PCM: 3.8 models send WAV, earlier ones headerless 16-bit PCM."""
    samples, rate = b"", None
    for part in _parts(payload):
        inline = part.get("inlineData") or part.get("inline_data")
        if not isinstance(inline, dict) or not isinstance(inline.get("data"), str):
            continue
        try:
            data = base64.b64decode(inline["data"], validate=True)
        except (binascii.Error, ValueError):
            raise APIError("Gemini returned malformed audio", status_code=502) from None
        if data[:4] == b"RIFF":
            try:
                pcm = audio_codec.parse_wav(data)
            except audio_codec.AudioFormatError:
                raise APIError("Gemini returned unreadable audio", status_code=502) from None
            if pcm.channels != 1:
                raise APIError("Gemini returned unexpected audio", status_code=502)
            data, part_rate = pcm.samples, pcm.rate
        else:
            match = _RATE.search(str(inline.get("mimeType") or inline.get("mime_type") or ""))
            part_rate = int(match.group(1)) if match else SAMPLE_RATE
            data = data[:len(data) - len(data) % audio_codec.SAMPLE_WIDTH]
        if rate is not None and part_rate != rate:
            raise APIError("Gemini returned audio at mixed sample rates", status_code=502)
        samples, rate = samples + data, part_rate
    if not samples or rate is None:
        raise APIError("Gemini returned no audio", status_code=502)
    return audio_codec.Pcm(samples, rate)


def speech_response(payload: dict, response_format: str) -> Response:
    pcm = speech_pcm(payload)
    if response_format == "mp3":
        return Response(audio_codec.encode_mp3(pcm), content_type="audio/mpeg")
    if response_format == "pcm":
        return Response(pcm.samples, content_type="audio/pcm")
    return Response(audio_codec.wav_bytes(pcm), content_type="audio/wav")


def transcription_response(payload: dict, response_format: str) -> Response:
    text = "".join(part["text"] for part in _parts(payload) if isinstance(part.get("text"), str)).strip()
    if response_format == "text":
        return Response(text, content_type="text/plain; charset=utf-8")
    return Response(json.dumps({"text": text}, ensure_ascii=False), content_type="application/json")
