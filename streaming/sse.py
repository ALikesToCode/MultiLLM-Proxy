"""Small Server-Sent Events parser used by provider stream adapters."""

from __future__ import annotations

import codecs
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Optional, Union

Chunk = Union[bytes, str]

HIDDEN_REASONING_KEYS = {
    "reasoning",
    "reasoning_details",
    "thinking",
    "thought",
    "thoughts",
    "chain_of_thought",
    "chainOfThought",
}


@dataclass(frozen=True)
class SSEEvent:
    """Parsed SSE event."""

    data: str
    event: Optional[str] = None
    event_id: Optional[str] = None
    retry: Optional[int] = None
    comments: List[str] = field(default_factory=list)

    @property
    def is_done(self) -> bool:
        return self.data.strip() == "[DONE]"


def _decode_chunks(chunks: Iterable[Chunk]) -> Iterator[str]:
    decoder = codecs.getincrementaldecoder("utf-8")()
    for chunk in chunks:
        if chunk is None:
            continue
        if isinstance(chunk, bytes):
            text = decoder.decode(chunk, final=False)
        else:
            text = str(chunk)
        if text:
            yield text

    tail = decoder.decode(b"", final=True)
    if tail:
        yield tail


def iter_sse_events(chunks: Iterable[Chunk]) -> Iterator[SSEEvent]:
    """Yield parsed SSE events from arbitrary byte or text chunks."""

    buffer = ""
    data_lines: List[str] = []
    comments: List[str] = []
    event_name: Optional[str] = None
    event_id: Optional[str] = None
    retry: Optional[int] = None

    def dispatch() -> Optional[SSEEvent]:
        nonlocal data_lines, comments, event_name, event_id, retry
        if (
            not data_lines
            and not comments
            and event_name is None
            and event_id is None
            and retry is None
        ):
            return None

        event = SSEEvent(
            data="\n".join(data_lines),
            event=event_name,
            event_id=event_id,
            retry=retry,
            comments=list(comments),
        )
        data_lines = []
        comments = []
        event_name = None
        event_id = None
        retry = None
        return event

    for text in _decode_chunks(chunks):
        buffer += text.replace("\r\n", "\n").replace("\r", "\n")

        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)

            if line == "":
                event = dispatch()
                if event is not None:
                    yield event
                continue

            if line.startswith(":"):
                comments.append(line[1:].lstrip())
                continue

            field_name, separator, field_value = line.partition(":")
            if separator:
                field_value = field_value[1:] if field_value.startswith(" ") else field_value
            else:
                field_value = ""

            if field_name == "data":
                data_lines.append(field_value)
            elif field_name == "event":
                event_name = field_value
            elif field_name == "id":
                event_id = field_value
            elif field_name == "retry":
                try:
                    retry = int(field_value)
                except ValueError:
                    retry = None

    if buffer:
        if buffer.startswith(":"):
            comments.append(buffer[1:].lstrip())
        else:
            field_name, separator, field_value = buffer.partition(":")
            if separator and field_value.startswith(" "):
                field_value = field_value[1:]
            if field_name == "data":
                data_lines.append(field_value if separator else "")
            elif field_name == "event":
                event_name = field_value if separator else ""
            elif field_name == "id":
                event_id = field_value if separator else ""
            elif field_name == "retry":
                try:
                    retry = int(field_value)
                except ValueError:
                    retry = None

    event = dispatch()
    if event is not None:
        yield event


def iter_sse_data(chunks: Iterable[Chunk], *, include_empty: bool = False) -> Iterator[str]:
    """Yield data payloads, ignoring comment-only frames by default."""

    for event in iter_sse_events(chunks):
        if event.data or include_empty:
            yield event.data


def format_sse_data(data: str) -> str:
    """Format a data payload as an SSE frame."""

    return f"data: {data}\n\n"


def strip_hidden_reasoning_fields(value: Any) -> Any:
    """Remove provider reasoning internals from stream payload metadata."""

    if isinstance(value, dict):
        sanitized: Dict[str, Any] = {}
        for key, item in value.items():
            if key in HIDDEN_REASONING_KEYS:
                continue
            sanitized[key] = strip_hidden_reasoning_fields(item)
        return sanitized
    if isinstance(value, list):
        return [strip_hidden_reasoning_fields(item) for item in value]
    return value
