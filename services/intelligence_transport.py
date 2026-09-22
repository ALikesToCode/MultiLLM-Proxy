"""Single-submission adapter transport with one deadline and bounded buffering."""

import logging
import queue
import threading
import time
from dataclasses import dataclass

from providers.base import CanonicalRequest
from providers.nanogpt import nanogpt_model_has_speed_suffix
from providers.opencode_go import build_opencode_model_url
from providers.registry import get_adapter
from services.intelligence_contract import GatewayError
from services.nanogpt_key_pool import NanoGPTUnifiedKeyPool
from services.upstream_transport import iter_stream_content

_TRANSPORT_SLOTS = threading.BoundedSemaphore(32)
logger = logging.getLogger(__name__)


def remaining(deadline, cancelled):
    if cancelled.is_set():
        raise GatewayError("cancelled", "The caller cancelled the request.", 499)
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise GatewayError(
            "deadline_exceeded",
            "The overall request deadline expired; execution may be incomplete.",
            504,
        )
    return seconds


@dataclass(frozen=True)
class ResponseHead:
    status_code: int
    headers: dict


class Exchange:
    """Bound the caller's wait even when an upstream dribbles response bytes.

    A cancelled worker never starts another submission. The socket read timeout
    bounds an already-running network call, whose outcome remains uncertain.
    """

    def __init__(
        self, send, deadline, cancelled, max_bytes, record=lambda status: None
    ):
        self.deadline, self.cancelled = deadline, cancelled
        self.events = queue.Queue(maxsize=4)
        self.stopped = threading.Event()
        self.response = None
        self.max_bytes = max_bytes
        self.send, self.record = send, record
        if not _TRANSPORT_SLOTS.acquire(blocking=False):
            raise GatewayError(
                "gateway_busy",
                "Gateway transport capacity is exhausted.",
                503,
                retryable=True,
            )
        threading.Thread(
            target=self._run, daemon=True, name="intelligence-transport"
        ).start()

    def _put(self, item):
        while not self.stopped.is_set() and not self.cancelled.is_set():
            if time.monotonic() >= self.deadline:
                return
            try:
                self.events.put(item, timeout=0.05)
                return
            except queue.Full:
                continue

    def _run(self):
        try:
            remaining(self.deadline, self.cancelled)
            if self.stopped.is_set():
                return
            response = self.response = self.send()
            self.record(response.status_code)
            # Upstream headers cannot impersonate a locally opened circuit and
            # turn an ambiguous 503 into permission to repeat a generation.
            headers = {
                name: response.headers[name]
                for name in ("Content-Type", "Retry-After")
                if name in response.headers
            }
            self._put(("head", ResponseHead(response.status_code, headers)))
            size = 0
            # Definite rejections need no error-body read, which could otherwise
            # disclose secrets or postpone a safe fallback.
            if response.status_code < 400:
                for chunk in iter_stream_content(response):
                    if self.stopped.is_set() or self.cancelled.is_set():
                        return
                    remaining(self.deadline, self.cancelled)
                    size += len(chunk)
                    if size > self.max_bytes:
                        raise GatewayError(
                            "response_too_large",
                            "The provider response exceeded the gateway limit.",
                            502,
                        )
                    self._put(("data", chunk))
            self._put(("done", None))
        except GatewayError as error:
            self._put(("error", error))
        except Exception:
            self._put(
                (
                    "error",
                    GatewayError(
                        "upstream_interrupted",
                        "The upstream outcome is uncertain; the request was not replayed.",
                        502,
                    ),
                )
            )
        finally:
            if self.response is not None:
                try:
                    self.response.close()
                except Exception as error:
                    logger.warning(
                        "Intelligence response cleanup failed type=%s",
                        type(error).__name__,
                    )
            _TRANSPORT_SLOTS.release()

    def next(self):
        while True:
            seconds = remaining(self.deadline, self.cancelled)
            try:
                kind, value = self.events.get(timeout=min(seconds, 0.1))
            except queue.Empty:
                continue
            if kind == "error":
                raise value
            return kind, value

    def head(self):
        kind, head = self.next()
        if kind != "head":
            raise GatewayError(
                "upstream_interrupted", "No upstream response was received.", 502
            )
        return head

    def chunks(self):
        while True:
            kind, chunk = self.next()
            if kind == "done":
                return
            if kind != "data":
                raise GatewayError(
                    "invalid_upstream_response",
                    "The upstream response was invalid.",
                    502,
                )
            yield chunk

    def read(self):
        return b"".join(self.chunks())

    def close(self):
        self.stopped.set()


class IntelligenceTransport:
    def __init__(self, config, auth, proxy):
        self.config, self.auth, self.proxy = config, auth, proxy

    def credential(self, candidate):
        provider = candidate["model"].split(":", 1)[0]
        if provider == "nanogpt":
            return NanoGPTUnifiedKeyPool.select_available_key(
                self.auth.get_api_keys(provider)
            )
        return self.auth.get_api_key(provider)

    def adapter(self, candidate, *, media=False):
        provider, model = candidate["model"].split(":", 1)
        bases = dict(self.config["API_BASE_URLS"])
        if provider == "nanogpt":
            subscription = candidate["billing"] == "subscription"
            if subscription and (media or nanogpt_model_has_speed_suffix(model)):
                raise GatewayError(
                    "billing_policy",
                    "This operation is not eligible for the configured subscription route.",
                    403,
                )
            bases[provider] = self.config[
                "NANOGPT_SUBSCRIPTION_BASE_URL"
                if subscription
                else "NANOGPT_STANDARD_BASE_URL"
            ]
        return get_adapter(provider, bases)

    def start(
        self,
        candidate,
        payload,
        token,
        deadline,
        cancelled,
        max_bytes,
        *,
        path=None,
        data=None,
        content_type=None,
    ):
        provider, model = candidate["model"].split(":", 1)
        adapter = self.adapter(candidate, media=path is not None)
        body = dict(payload, model=model)
        upstream = adapter.prepare_request(
            CanonicalRequest(provider=provider, model=model, raw=body)
        )
        upstream_path = path or adapter.chat_path
        url = upstream.url
        if path:
            url = f"{adapter.base_url.rstrip('/')}/{path}"
        elif provider == "opencode":
            url = build_opencode_model_url(
                adapter.base_url,
                self.config["OPENCODE_ZEN_BASE_URL"],
                model,
                upstream_path,
            )
        # Caller account, billing, payment and idempotency headers never reach an
        # upstream. Only this server's selected credential authorizes transport.
        headers = self.proxy.prepare_headers(
            {"Content-Type": content_type or "application/json"},
            provider,
            token,
            upstream_path=upstream_path,
        )
        if content_type:
            headers["Content-Type"] = content_type

        def send():
            seconds = remaining(deadline, cancelled)
            return self.proxy.make_request(
                method="POST",
                url=url,
                headers=headers,
                params={},
                data=upstream.data if data is None else data,
                api_provider=provider,
                use_cache=False,
                timeout_override=(min(5, seconds), seconds),
                force_raw_passthrough=True,
            )

        def record(status):
            if provider == "nanogpt":
                NanoGPTUnifiedKeyPool.record_result(token, status)

        return Exchange(send, deadline, cancelled, max_bytes, record)
