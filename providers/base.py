from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Iterable, Literal, Protocol


@dataclass(frozen=True)
class CanonicalRequest:
    provider: str
    model: str | None = None
    messages: list[dict[str, Any]] = field(default_factory=list)
    stream: bool = False
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class UpstreamRequest:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    params: dict[str, Any] = field(default_factory=dict)
    data: bytes | None = None


@dataclass(frozen=True)
class CanonicalResponse:
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes | None = None
    json: dict[str, Any] | None = None


@dataclass(frozen=True)
class CanonicalStreamEvent:
    event: str | None
    data: dict[str, Any] | str | None
    done: bool = False


@dataclass(frozen=True)
class ModelInfo:
    id: str
    provider: str
    display_name: str
    context_window: int | None = None
    max_output_tokens: int | None = None
    supports_streaming: bool = False
    supports_tools: bool = False
    supports_vision: bool = False
    supports_audio: bool = False
    supports_json_schema: bool = False
    input_cost_per_million: Decimal | None = None
    output_cost_per_million: Decimal | None = None
    status: Literal["available", "deprecated", "disabled"] = "available"


@dataclass(frozen=True)
class ProviderCapabilities:
    supports_chat: bool = True
    supports_streaming: bool = True
    supports_tools: bool = False
    supports_vision: bool = False
    supports_embeddings: bool = False
    supports_audio: bool = False
    supports_images: bool = False
    supports_json_schema: bool = False
    supports_token_count: bool = False


class ProviderAdapter(Protocol):
    name: str

    def chat_completions_url(self) -> str:
        ...

    def capabilities(self) -> ProviderCapabilities:
        ...

    def prepare_request(self, canonical: CanonicalRequest) -> UpstreamRequest:
        ...

    def parse_response(self, response: CanonicalResponse) -> CanonicalResponse:
        ...

    def parse_stream(self, byte_iter: Iterable[bytes]) -> Iterable[CanonicalStreamEvent]:
        ...

    def list_models(self) -> list[ModelInfo]:
        ...
