"""Bounded JSON/SSE restoration; token prefixes never escape unresolved."""

from __future__ import annotations

import json
import re
from collections import deque

from services.pii_redaction import PREFIX, TOKEN

MAX_FRAME_BYTES = 65536
MAX_BODY_BYTES = 1024 * 1024
_SEPARATOR = re.compile(rb"\r\n\r\n|\n\n|\r\r")


class PIIStreamError(ValueError):
    """Restoration cannot continue safely; close without granting replay."""


class TextCarry:
    def __init__(self, context):
        self.context = context
        self.pending: dict[tuple, str] = {}

    def text(self, value, lane):
        text = self.pending.pop(lane, "") + value
        output, index = [], 0
        while index < len(text):
            start = text.find("_", index)
            if start < 0:
                output.append(text[index:])
                break
            output.append(text[index:start])
            rest = text[start:start + 74]
            match = TOKEN.match(rest)
            if match:
                output.append(self.context.restore(match.group()))
                index = start + len(match.group())
                continue
            partial = PREFIX.startswith(rest) or (
                rest.startswith(PREFIX) and len(rest) < 74 and
                re.fullmatch(r"[0-9a-f]{0,64}_{0,2}", rest[len(PREFIX):]) is not None
            )
            if partial:
                if lane not in self.pending and len(self.pending) >= 16:
                    raise PIIStreamError("PII stream exceeds the text lane limit")
                self.pending[lane] = rest
                if sum(len(item.encode()) for item in self.pending.values()) > 128:
                    raise PIIStreamError("PII stream exceeds the prefix limit")
                break
            output.append("_")
            index = start + 1
        return "".join(output)

    def transform(self, value, path=(), depth=0, counter=None):
        counter = [0] if counter is None else counter
        counter[0] += 1
        if depth > 32 or counter[0] > 32768:
            raise PIIStreamError("PII stream exceeds the structure limit")
        if isinstance(value, str):
            return self.text(value, path)
        if isinstance(value, list):
            return [self.transform(item, (*path, i), depth + 1, counter) for i, item in enumerate(value)]
        if isinstance(value, dict):
            return {key: self.transform(item, (*path, key), depth + 1, counter) for key, item in value.items()}
        return value

    def finish(self):
        if self.pending:
            raise PIIStreamError("PII stream ended with an unresolved placeholder prefix")


class RehydratingIterator:
    """Own both the source iterator and ephemeral map, including unstarted close."""

    def __init__(self, source, context, *, event_stream):
        self.source = iter(source)
        self.context = context
        self.event_stream = event_stream
        self.buffer = b""
        self.ready: deque[bytes] = deque()
        self.ready_bytes = 0
        self.carry = TextCarry(context)
        self.closed = False

    def __iter__(self):
        return self

    def _enqueue(self, output):
        self.ready_bytes += len(output)
        if self.ready_bytes > MAX_BODY_BYTES:
            raise PIIStreamError("PII stream exceeds the output queue limit")
        self.ready.append(output)

    def _frame(self, frame):
        lines = frame.splitlines(keepends=True)
        indices = [i for i, line in enumerate(lines) if line.startswith(b"data:")]
        if not indices:
            return frame
        data = b"\n".join(lines[i][5:].strip() for i in indices)
        if data == b"[DONE]":
            self.carry.finish()
            return frame
        try:
            value = json.loads(data)
            restored = self.carry.transform(value)
        except (ValueError, UnicodeError, RecursionError) as error:
            if isinstance(error, PIIStreamError):
                raise
            raise PIIStreamError("PII stream contains invalid JSON data") from None
        if restored == value:
            return frame
        ending = b"\r\n" if lines[indices[0]].endswith(b"\r\n") else b"\n"
        lines[indices[0]] = b"data: " + json.dumps(restored, ensure_ascii=False, separators=(",", ":")).encode() + ending
        for i in indices[1:]:
            lines[i] = b""
        return b"".join(lines)

    def _feed(self, chunk):
        maximum = MAX_FRAME_BYTES if self.event_stream else MAX_BODY_BYTES
        for start in range(0, len(chunk), 4096):
            self.buffer += chunk[start:start + 4096]
            if self.event_stream:
                while match := _SEPARATOR.search(self.buffer):
                    if match.end() > maximum:
                        raise PIIStreamError("PII stream frame exceeds the parser limit")
                    frame, self.buffer = self.buffer[:match.end()], self.buffer[match.end():]
                    self._enqueue(self._frame(frame))
            if len(self.buffer) > maximum:
                raise PIIStreamError("PII response exceeds the parser limit")

    def __next__(self):
        if self.closed and not self.ready:
            raise StopIteration
        try:
            while not self.ready:
                try:
                    chunk = next(self.source)
                except StopIteration:
                    if self.event_stream:
                        if self.buffer:
                            self._enqueue(self._frame(self.buffer))
                        self.carry.finish()
                    elif self.buffer:
                        body = self.carry.transform(json.loads(self.buffer))
                        self.carry.finish()
                        self._enqueue(json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode())
                    self.buffer = b""
                    self.close(clear_ready=False)
                    if not self.ready:
                        raise
                    break
                self._feed(chunk.encode() if isinstance(chunk, str) else chunk)
            output = self.ready.popleft()
            self.ready_bytes -= len(output)
            return output
        except StopIteration:
            raise
        except BaseException:
            self.ready.clear()
            self.close()
            raise

    def close(self, *, clear_ready=True):
        if clear_ready:
            self.ready.clear()
            self.ready_bytes = 0
        if self.closed:
            return
        self.closed = True
        self.buffer = b""
        self.carry.pending.clear()
        self.context.close()
        close = getattr(self.source, "close", None)
        if close is not None:
            close()


def rehydrate_response(response, context, *, stream=False):
    if context.closed or getattr(response, "multillm_pii_rehydrated", False):
        return response
    response.multillm_pii_rehydrated = True
    if stream or response.is_streamed or response.mimetype == "text/event-stream":
        iterator = RehydratingIterator(response.response, context, event_stream=stream or response.mimetype == "text/event-stream")
        response.response = iterator
        response.call_on_close(iterator.close)
        from flask import g, has_request_context
        if has_request_context():
            g.pii_stream_owned = True
    else:
        try:
            body = response.get_data()
            if len(body) > MAX_BODY_BYTES:
                raise PIIStreamError("PII response exceeds the body limit")
            carry = TextCarry(context)
            restored = carry.transform(json.loads(body))
            carry.finish()
            response.set_data(json.dumps(restored, ensure_ascii=False, separators=(",", ":")).encode())
        except (ValueError, UnicodeError, RecursionError):
            response.status_code = 502
            response.content_type = "application/json"
            response.set_data(b'{"error":{"code":"pii_rehydration_failed","message":"Unable to restore provider response"}}')
        finally:
            context.close()
    response.headers.pop("Content-Length", None)
    return response
