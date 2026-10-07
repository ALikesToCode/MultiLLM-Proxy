"""Fail-safe, bounded capture after successful opted-in routed chat completions."""

import json
import logging
import queue
import random
import threading
import time

from flask import g, request

from services.shadow_eval_contract import ANSWER_BYTES, clean_usage, eligible, encoded, make_sample
from services.shadow_eval_store import ShadowEvalStore

logger = logging.getLogger(__name__)
_QUEUE = queue.Queue(maxsize=32)
_LOCK = threading.Lock()
_WORKER = None


def submit(sample):
    global _WORKER
    if sample is None:
        return
    with _LOCK:
        if _WORKER is None or not _WORKER.is_alive():
            _WORKER = threading.Thread(target=_persist, name="shadow-samples", daemon=True)
            _WORKER.start()
    try:
        _QUEUE.put_nowait(sample)
    except queue.Full:
        pass


def _persist():
    while True:
        sample = _QUEUE.get()
        try:
            ShadowEvalStore.put(sample)
        except Exception as error:
            logger.warning("Shadow sample not stored (%s)", type(error).__name__)
        finally:
            _QUEUE.task_done()


class SampleStream:
    """Forward identical chunks; keep only a bounded successful chat answer."""

    def __init__(self, iterable, complete, model):
        self.source = iterable
        self.iterator = iter(iterable)
        self.complete = complete
        self.model = model
        self.pending = b""
        self.answer = {"content": ""}
        self.calls = {}
        self.usage = {}
        self.bytes = 0
        self.done = False
        self.finished = False
        self.finish_reason = None
        self.failed = False

    def __iter__(self):
        return self

    def __next__(self):
        try:
            chunk = next(self.iterator)
        except StopIteration:
            self._complete()
            raise
        except Exception:
            self.failed = True
            raise
        if not self.failed:
            try:
                self._consume(chunk)
            except Exception:
                self.failed = True
                self.pending = b""
                self.answer = {}
                self.calls = {}
        return chunk

    def _consume(self, chunk):
        data = chunk.encode() if isinstance(chunk, str) else bytes(chunk)
        self.bytes += len(data)
        if self.bytes > 1048576 or len(self.pending) + len(data) > 131072:
            raise ValueError("Shadow stream limit")
        self.pending += data
        self.pending = self.pending.replace(b"\r\n", b"\n")
        while b"\n\n" in self.pending:
            event, self.pending = self.pending.split(b"\n\n", 1)
            lines = [line[5:].strip() for line in event.split(b"\n") if line.startswith(b"data:")]
            if not lines:
                continue
            data = b"\n".join(lines)
            if data == b"[DONE]":
                self.done = True
                continue
            value = json.loads(data)
            if value.get("error"):
                raise ValueError("Failed stream")
            self.usage.update(clean_usage(value.get("usage")))
            self.model = (value.get("multillm") or {}).get("selected_model") or self.model
            for choice in value.get("choices", [])[:1]:
                if choice.get("index", 0) != 0:
                    continue
                self.finished = self.finished or choice.get("finish_reason") in {"stop", "length", "tool_calls", "function_call"}
                self.finish_reason = choice.get("finish_reason") or self.finish_reason
                delta = choice.get("delta") or {}
                self.answer["content"] += delta.get("content") or ""
                for item in delta.get("tool_calls", [])[:128]:
                    index = item.get("index")
                    if type(index) is not int or not 0 <= index < 128:
                        raise ValueError("Invalid streamed tool call")
                    call = self.calls.setdefault(index, {"id": "", "type": "function", "function": {"name": "", "arguments": ""}})
                    if "id" in item:
                        call["id"] = item["id"]
                    for field in ("name", "arguments"):
                        call["function"][field] += (item.get("function") or {}).get(field) or ""
                answer = {**self.answer, "tool_calls": list(self.calls.values())}
                if len(encoded(answer).encode()) > ANSWER_BYTES:
                    raise ValueError("Shadow answer limit")

    def _complete(self):
        callback, self.complete = self.complete, None
        if callback and self.done and self.finished and not self.failed:
            if self.calls:
                self.answer["tool_calls"] = [self.calls[key] for key in sorted(self.calls)]
            try:
                callback(self.answer, self.model, self.usage, self.finish_reason)
            except Exception as error:
                logger.warning("Shadow stream not sampled (%s)", type(error).__name__)

    def close(self):
        try:
            close = getattr(self.source, "close", None)
            if close:
                close()
        finally:
            self._complete()


def sample_success(response, payload=None):
    try:
        if response.status_code >= 400 or request.method != "POST" or getattr(g, "shadow_eval_internal", False):
            return response
        payload = payload if payload is not None else request.get_json(silent=True)
        user = getattr(g, "authenticated_user", None) or {}
        if getattr(g, "shadow_eval_sampled", False):
            return response
        g.shadow_eval_sampled = True
        if not isinstance(payload, dict) or not eligible(payload, user, request.path, random_value=random.random()):
            return response
        original = request.get_json(silent=True)
        from services.secret_scan import scan_payload
        report = scan_payload(original)
        if report["high"] or report["truncated"]:
            return response
        # Freeze bounded request data before the request context is torn down.
        if len(encoded(payload).encode()) > 131072:
            return response
        payload = json.loads(encoded(payload))
        user = {"username": user.get("username"), "id": user.get("id")}
        route = "auto:intelligence" if "routing" in payload or request.path.startswith("/intelligence/") else payload["model"]
        started = g.shadow_eval_started
        model = response.headers.get("X-MultiLLM-Auto-Selected-Model") or getattr(g, "multillm_model", None)

        def capture(answer, selected, usage, finish_reason=None):
            sample = make_sample(payload, user, route, answer, selected,
                                 (time.monotonic() - started) * 1000, usage, finish_reason=finish_reason)
            submit(sample)

        if response.is_streamed:
            if response.mimetype == "text/event-stream":
                response.response = SampleStream(response.response, capture, model)
        else:
            if len(response.get_data()) > 131072:
                return response
            body = response.get_json(silent=True)
            if isinstance(body, dict) and not body.get("error"):
                selected = (body.get("multillm") or {}).get("selected_model") or model
                if isinstance(body.get("choices"), list) and body["choices"]:
                    capture(body["choices"][0]["message"], selected, body.get("usage"), body["choices"][0].get("finish_reason"))
    except Exception as error:
        logger.warning("Shadow sampling unavailable (%s)", type(error).__name__)
    return response


def sample_chat_dispatch(dispatch):
    from functools import wraps

    @wraps(dispatch)
    def sampled(app, auth, metrics, proxy, payload, **options):
        response = dispatch(app, auth, metrics, proxy, payload, **options)
        return sample_success(response, payload)
    return sampled


def init_shadow_sampling(app):
    @app.before_request
    def shadow_start_time():
        g.shadow_eval_started = time.monotonic()

    app.after_request(sample_success)
