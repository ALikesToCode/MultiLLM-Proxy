"""WAV parsing, padding and MP3 encoding for speech audio."""

import struct

import pytest

from services import audio_codec
from services.audio_codec import AudioFormatError, Pcm


def chunk(name: bytes, body: bytes) -> bytes:
    return struct.pack("<4sI", name, len(body)) + body + (b"\x00" if len(body) % 2 else b"")


def wav(*chunks: bytes) -> bytes:
    body = b"WAVE" + b"".join(chunks)
    return struct.pack("<4sI", b"RIFF", len(body)) + body


def fmt(rate=24000, channels=1, bits=16, audio_format=1) -> bytes:
    block = channels * bits // 8
    return chunk(b"fmt ", struct.pack("<HHIIHH", audio_format, channels, rate, rate * block, block, bits))


def test_round_trip_and_extra_chunks_before_the_data():
    pcm = Pcm(b"\x01\x02" * 4800, 24000)
    assert audio_codec.parse_wav(audio_codec.wav_bytes(pcm)) == pcm
    assert pcm.seconds == 0.2
    data = wav(chunk(b"LIST", b"odd"), fmt(rate=48000, channels=2), chunk(b"data", b"\x00\x01" * 6 + b"\x09"))
    assert audio_codec.parse_wav(data) == Pcm(b"\x00\x01" * 6, 48000, 2), "a partial frame is dropped"


@pytest.mark.parametrize("data", [
    b"not audio",
    wav(fmt(bits=24), chunk(b"data", b"\x00" * 6)),
    wav(fmt(audio_format=3), chunk(b"data", b"\x00" * 4)),
    wav(chunk(b"data", b"\x00" * 4)),
    wav(fmt()),
])
def test_unsupported_or_broken_wav_is_refused(data):
    with pytest.raises(AudioFormatError):
        audio_codec.parse_wav(data)


def test_padding_adds_silence_up_to_the_length_and_never_cuts():
    pcm = Pcm(b"\x05\x00" * 12000, 24000)
    padded = audio_codec.pad_to(pcm, 1.25)
    assert (padded.seconds, padded.samples[:24000], set(padded.samples[24000:])) == (1.25, pcm.samples, {0})
    assert audio_codec.pad_to(pcm, 0.25) is pcm


def test_mp3_encoding_produces_frames():
    assert audio_codec.mp3_available()
    encoded = audio_codec.encode_mp3(Pcm(b"\x00\x10" * 24000, 24000))
    assert isinstance(encoded, bytes) and len(encoded) > 1000 and encoded[0] == 0xFF
