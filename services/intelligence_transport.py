"""Single-submission adapter transport with one deadline and bounded buffering."""

import logging
import os
import queue
import threading
import time
from dataclasses import dataclass

from providers.base import CanonicalRequest
from providers.codex_everywhere import with_codex_instructions
from providers.nanogpt import nanogpt_model_has_speed_suffix
from providers.opencode_go import build_opencode_model_url
from providers.registry import get_adapter
from services.credential_pool import CredentialPool
from services.credential_context import observation_context, selection_context
from services.model_cooldown import ModelCooldownCapacity, ModelCooldownExhausted
from services.request_cancellation import bind_cancellation
from services.intelligence_contract import GatewayError
from services.nanogpt_key_pool import NanoGPTUnifiedKeyPool
from services.reasoning_policy import (
    apply_gemini_reasoning_policy,
    apply_glm_5_reasoning_policy,
    apply_mimo_reasoning_policy,
    apply_sol_reasoning_policy,
)
from services.upstream_transport import iter_stream_content
from services.secret_firewall import protect_body

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
        self, send, deadline, cancelled, max_bytes, record=lambda status: None,
        *, record_response=None,
    ):
        self.deadline, self.cancelled = deadline, cancelled
        self.events = queue.Queue(maxsize=4)
        self.stopped = threading.Event()
        self.response = None
        self._response_lock = threading.Lock()
        self.max_bytes = max_bytes
        self.send, self.record = send, record
        self.record_response = record_response
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
            response = self.send()
            with self._response_lock:
                bind_cancellation(response)
                self.response = response
            if self.stopped.is_set() or self.cancelled.is_set():
                response.close()
                return
            if self.record_response is not None:
                self.record_response(response)
            else:
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
        except (GatewayError, ModelCooldownExhausted, ModelCooldownCapacity) as error:
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
        with self._response_lock:
            response = self.response
        if response is not None:
            response.close()


def without_thought_signatures(body):
    """Drop Gemini thought signatures from replayed tool calls before another provider sees them."""
    messages = body.get("messages")
    if not isinstance(messages, list) or not any(
        isinstance(message, dict)
        and isinstance(message.get("tool_calls"), list)
        and any(isinstance(call, dict) and "extra_content" in call for call in message["tool_calls"])
        for message in messages
    ):
        return body
    cleaned = []
    for message in messages:
        if isinstance(message, dict) and isinstance(message.get("tool_calls"), list):
            message = {
                **message,
                "tool_calls": [
                    {key: value for key, value in call.items() if key != "extra_content"}
                    if isinstance(call, dict)
                    else call
                    for call in message["tool_calls"]
                ],
            }
        cleaned.append(message)
    return {**body, "messages": cleaned}


# Google's documented stand-in for a function call Gemini did not write itself, such as one
# from an earlier fallback model (ai.google.dev/gemini-api/docs/thought-signatures). Gemini 3
# refuses a turn whose first call in a step has no signature; this value skips the check.
SKIP_THOUGHT_SIGNATURE = "skip_thought_signature_validator"


def _signed(call):
    extra = call.get("extra_content") if isinstance(call, dict) else None
    google = extra.get("google") if isinstance(extra, dict) else None
    return isinstance(google, dict) and bool(google.get("thought_signature"))


def with_thought_signatures(body):
    """Give Gemini a signature on each tool-call step another provider made.

    Gemini's own calls keep their signatures; a step with none gets the skip value on its
    first call, which is the only call Gemini itself would have signed.
    """
    messages = body.get("messages")
    if not isinstance(messages, list):
        return body
    unsigned = [
        index
        for index, message in enumerate(messages)
        if isinstance(message, dict)
        and isinstance(message.get("tool_calls"), list)
        and message["tool_calls"]
        and isinstance(message["tool_calls"][0], dict)
        and not any(_signed(call) for call in message["tool_calls"])
    ]
    if not unsigned:
        return body
    cleaned = list(messages)
    for index in unsigned:
        first, *rest = cleaned[index]["tool_calls"]
        extra = first.get("extra_content") if isinstance(first.get("extra_content"), dict) else {}
        google = extra.get("google") if isinstance(extra.get("google"), dict) else {}
        signed = {
            **first,
            "extra_content": {
                **extra,
                "google": {**google, "thought_signature": SKIP_THOUGHT_SIGNATURE},
            },
        }
        cleaned[index] = {**cleaned[index], "tool_calls": [signed, *rest]}
    return {**body, "messages": cleaned}


class IntelligenceTransport:
    def __init__(self, config, auth, proxy):
        self.config, self.auth, self.proxy = config, auth, proxy

    def credential(self, candidate):
        provider, model = candidate["model"].split(":", 1)
        scope = selection_context(provider, model, config=self.config)
        if provider == "nanogpt":
            # Reviewed subscription calls use only a configured isolated key, even
            # while it is rejected or rate limited. Shared-pool selection would
            # rotate to general keys and prune their cooldowns.
            pinned = os.environ.get("INTELLIGENCE_NANOGPT_SUBSCRIPTION_API_KEY")
            if pinned is not None and candidate["billing"] == "subscription":
                return pinned.strip() or None
            return NanoGPTUnifiedKeyPool.select_available_key(
                self.auth.get_api_keys(provider), **scope
            )
        return self.auth.get_api_key(provider, **scope)

    def credentials(self, candidate):
        """Keys to try for one candidate in order: every resting-free key of a pooled
        provider, otherwise the single selected credential."""
        provider, model = candidate["model"].split(":", 1)
        scope = selection_context(provider, model, config=self.config)
        if CredentialPool.pooled(provider):
            decision = {"require_eligible": True, **scope} if scope else {}
            return CredentialPool.available(provider, self.auth.get_api_keys(provider), **decision)
        token = self.credential(candidate)
        return [token] if token else []

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
        if provider == "gemini" and not media and bases.get(provider):
            # Gemini's Chat Completions endpoint, not the native API other routes convert to.
            bases[provider] = f"{bases[provider].rstrip('/')}/openai"
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
        if path is None:
            body = apply_glm_5_reasoning_policy(body, provider, model)
            body = apply_mimo_reasoning_policy(body, model)
            body = apply_gemini_reasoning_policy(body, provider, model)
            body = apply_sol_reasoning_policy(body, provider, model)
            if provider == "gemini":
                body = with_thought_signatures(body)
            else:
                body = without_thought_signatures(body)
            body = with_codex_instructions(body, provider, model)
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

        dispatch_data = protect_body(upstream.data if data is None else data, headers, provider=provider)

        scope = selection_context(provider, model, config=self.config)

        def send():
            seconds = remaining(deadline, cancelled)
            return self.proxy.make_request(
                method="POST",
                url=url,
                headers=headers,
                params={},
                data=dispatch_data,
                api_provider=provider,
                use_cache=False,
                timeout_override=(min(5, seconds), seconds),
                force_raw_passthrough=True,
                **({"cooldown_context": scope} if scope else {}),
            )

        def record_response(response):
            if provider == "nanogpt":
                NanoGPTUnifiedKeyPool.record_result(token, response.status_code, **scope,
                    **observation_context(response, cancelled=cancelled.is_set()))

        return Exchange(send, deadline, cancelled, max_bytes, record_response=record_response)
