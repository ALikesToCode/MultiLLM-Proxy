"""16-bit PCM audio: WAV parsing and writing, durations, silence padding and MP3 encoding.

Speech providers return WAV, raw PCM or MP3. Narration measures and pads speech as PCM,
and Gemini text-to-speech, which only returns PCM, is encoded to MP3 here with LAME
(`lameenc`). Only 16-bit integer PCM is handled; that is what every speech model emits.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

SAMPLE_WIDTH = 2
MP3_BIT_RATE = 96
_UNKNOWN_SIZES = frozenset({0, 0xFFFFFFFF})
_PCM_FORMATS = frozenset({1, 0xFFFE})


class AudioFormatError(ValueError):
    """The bytes are not 16-bit PCM audio this module can read."""


@dataclass(frozen=True)
class Pcm:
    samples: bytes
    rate: int
    channels: int = 1

    @property
    def frames(self) -> int:
        return len(self.samples) // (SAMPLE_WIDTH * self.channels)

    @property
    def seconds(self) -> float:
        return self.frames / self.rate


def parse_wav(data: bytes) -> Pcm:
    """The PCM inside a WAV file.

    Streamed WAV replies (OpenAI's among them) carry 0 or 0xFFFFFFFF chunk sizes because
    the length was unknown when the header was sent; their data runs to the end of the file.
    """
    if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        raise AudioFormatError("not a WAV file")
    offset, rate, channels = 12, None, None
    while offset + 8 <= len(data):
        chunk, size = data[offset:offset + 4], struct.unpack_from("<I", data, offset + 4)[0]
        body = offset + 8
        if chunk == b"fmt ":
            if size < 16 or body + 16 > len(data):
                raise AudioFormatError("truncated fmt chunk")
            audio_format, channels, rate, _, _, bits = struct.unpack_from("<HHIIHH", data, body)
            if audio_format not in _PCM_FORMATS or bits != 16 or not 1 <= channels <= 2 or not 8000 <= rate <= 192000:
                raise AudioFormatError("only 16-bit PCM WAV is supported")
        elif chunk == b"data":
            if rate is None:
                raise AudioFormatError("data chunk before fmt chunk")
            end = len(data) if size in _UNKNOWN_SIZES else min(len(data), body + size)
            samples = data[body:end]
            return Pcm(samples[:len(samples) - len(samples) % (SAMPLE_WIDTH * channels)], rate, channels)
        if size == 0xFFFFFFFF:
            break
        offset = body + size + (size & 1)
    raise AudioFormatError("no data chunk")


def wav_bytes(pcm: Pcm) -> bytes:
    block = SAMPLE_WIDTH * pcm.channels
    header = struct.pack("<4sI4s4sIHHIIHH4sI", b"RIFF", 36 + len(pcm.samples), b"WAVE", b"fmt ", 16, 1,
                         pcm.channels, pcm.rate, pcm.rate * block, block, SAMPLE_WIDTH * 8, b"data", len(pcm.samples))
    return header + pcm.samples


def pad_to(pcm: Pcm, seconds: float) -> Pcm:
    """Append silence so the audio lasts `seconds`; longer audio is returned unchanged."""
    missing = round(seconds * pcm.rate) - pcm.frames
    if missing <= 0:
        return pcm
    return Pcm(pcm.samples + bytes(missing * SAMPLE_WIDTH * pcm.channels), pcm.rate, pcm.channels)


def mp3_available() -> bool:
    try:
        import lameenc  # noqa: F401, PLC0415
    except ImportError:
        return False
    return True


def encode_mp3(pcm: Pcm, bit_rate: int = MP3_BIT_RATE) -> bytes:
    import lameenc  # noqa: PLC0415

    encoder = lameenc.Encoder()
    encoder.set_bit_rate(bit_rate)
    encoder.set_in_sample_rate(pcm.rate)
    encoder.set_channels(pcm.channels)
    encoder.set_quality(2)
    return bytes(encoder.encode(pcm.samples) + encoder.flush())
