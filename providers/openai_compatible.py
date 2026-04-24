from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable

from providers.base import (
    CanonicalRequest,
    CanonicalResponse,
    CanonicalStreamEvent,
    ModelInfo,
    ProviderCapabilities,
    UpstreamRequest,
)


@dataclass(frozen=True)
class OpenAICompatibleAdapter:
    name: str
    base_url: str
    chat_path: str = "v1/chat/completions"
    provider_capabilities: ProviderCapabilities = field(default_factory=ProviderCapabilities)

    def chat_completions_url(self) -> str:
        return f"{self.base_url.rstrip('/')}/{self.chat_path.lstrip('/')}"

    def capabilities(self) -> ProviderCapabilities:
        return self.provider_capabilities

    def prepare_request(self, canonical: CanonicalRequest) -> UpstreamRequest:
        payload: dict[str, Any] = dict(canonical.raw)
        if canonical.model and "model" not in payload:
            payload["model"] = canonical.model
        if canonical.messages and "messages" not in payload:
            payload["messages"] = canonical.messages
        if canonical.stream and "stream" not in payload:
            payload["stream"] = True

        return UpstreamRequest(
            method="POST",
            url=self.chat_completions_url(),
            headers={"Content-Type": "application/json"},
            data=json.dumps(payload).encode("utf-8"),
        )

    def parse_response(self, response: CanonicalResponse) -> CanonicalResponse:
        return response

    def parse_stream(self, byte_iter: Iterable[bytes]) -> Iterable[CanonicalStreamEvent]:
        for chunk in byte_iter:
            if not chunk:
                continue
            yield CanonicalStreamEvent(event=None, data=chunk.decode("utf-8", errors="replace"))

    def list_models(self) -> list[ModelInfo]:
        return []
