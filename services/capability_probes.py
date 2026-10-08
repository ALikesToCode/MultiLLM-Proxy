"""Bounded, configuration-bound observations. No catalog or routing mutations."""

from __future__ import annotations

import base64
import hashlib
import http.client
import ipaddress
import json
import re
import struct
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import urlsplit

MAX_RESPONSE_BYTES = 65536
MAX_REQUEST_BYTES = 32768
_CONFIG_FIELDS = {
    "runtime", "gateway_base_url", "provider", "model", "base_url", "headers",
    "credential_revision", "provider_header_revision", "policy_revision", "capability_config",
}
_SECRET_NAME = re.compile(r"authorization|cookie|secret|password|credential|api[-_]?key|(?:^|[-_])token(?:$|[-_])", re.I)
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}\Z")
_SCHEMA = {"type": "object", "properties": {"status": {"type": "string", "enum": ["ready"]}},
           "required": ["status"], "additionalProperties": False}


class ProbeRefused(ValueError):
    """An operator-facing reason containing no supplied values."""


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON member")
        result[key] = value
    return result


def _invalid_constant(value: str) -> Any:
    raise ValueError("Nonfinite JSON number")


def parse_probe_json(value: str | bytes) -> Any:
    return json.loads(value, object_pairs_hook=_json_object, parse_constant=_invalid_constant)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _label(value: Any) -> str:
    if not isinstance(value, str) or not _LABEL.fullmatch(value):
        raise ProbeRefused("Use bounded identifiers for configuration and fixture revisions")
    return value


def _url(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 2048 or any(ord(c) < 33 for c in value):
        raise ProbeRefused("Invalid base URL")
    parsed = urlsplit(value)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
        raise ProbeRefused("Base URLs must have no credentials, query or fragment")
    try:
        parsed.port
    except ValueError:
        raise ProbeRefused("Invalid base URL port") from None
    try:
        local = parsed.hostname == "localhost" or ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        local = parsed.hostname == "localhost"
    if parsed.scheme == "http" and not local:
        raise ProbeRefused("Plain HTTP is allowed only for a loopback gateway or provider")
    return value


def _safe_config(value: Any, depth: int = 0) -> None:
    if depth > 6:
        raise ProbeRefused("Capability configuration is too deeply nested")
    if isinstance(value, dict):
        if len(value) > 32:
            raise ProbeRefused("Capability configuration is too large")
        for name, item in value.items():
            if not isinstance(name, str) or len(name) > 128 or _SECRET_NAME.search(name):
                raise ProbeRefused("Use opaque revisions instead of credentials in configuration")
            _safe_config(item, depth + 1)
    elif isinstance(value, list):
        if len(value) > 32:
            raise ProbeRefused("Capability configuration is too large")
        for item in value:
            _safe_config(item, depth + 1)
    elif isinstance(value, str):
        if len(value) > 256 or "Bearer " in value or value.startswith(("sk-", "sk_live_")):
            raise ProbeRefused("Capability configuration must contain no credential material")
    elif value is not None and type(value) not in {bool, int, float}:
        raise ProbeRefused("Capability configuration must be JSON")


@dataclass(frozen=True)
class ProbeConfig:
    _canonical: str = field(repr=False)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> ProbeConfig:
        if not isinstance(raw, dict) or set(raw) != _CONFIG_FIELDS:
            raise ProbeRefused("Provide every effective configuration field and no extra fields")
        descriptor = dict(raw)
        if descriptor["runtime"] not in {"flask", "worker"}:
            raise ProbeRefused("Select the Flask or Worker adapter explicitly")
        for name in ("provider", "model", "credential_revision", "provider_header_revision", "policy_revision"):
            descriptor[name] = _label(descriptor[name])
        if descriptor["provider"] in {"auto", "intelligence", "free", "cascade"}:
            raise ProbeRefused("Probes require an explicit provider and model")
        for name in ("base_url", "gateway_base_url"):
            descriptor[name] = _url(descriptor[name])
        headers = descriptor["headers"]
        if not isinstance(headers, dict) or len(headers) > 16:
            raise ProbeRefused("Provide bounded non-credential headers")
        normalized = {}
        for name, value in headers.items():
            if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,128}", name) or _SECRET_NAME.search(name):
                raise ProbeRefused("Authentication headers must not be supplied in configuration")
            key = name.lower()
            # Transport and framing headers cannot override the adapter's bounded JSON request.
            if key in normalized or key in {"host", "content-length", "transfer-encoding", "connection", "content-type", "accept-encoding"}:
                raise ProbeRefused("Duplicate or transport-controlled header")
            if not isinstance(value, str) or len(value) > 256 or any(ord(c) < 32 or ord(c) > 126 for c in value) or "Bearer " in value or value.startswith("sk-"):
                raise ProbeRefused("Invalid non-credential header value")
            normalized[key] = value
        descriptor["headers"] = normalized
        if not isinstance(descriptor["capability_config"], dict):
            raise ProbeRefused("Provide the effective capability configuration object")
        _safe_config(descriptor["capability_config"])
        encoded = _canonical(descriptor)
        if len(encoded.encode()) > 16384:
            raise ProbeRefused("Configuration descriptor is too large")
        return cls(encoded)

    @property
    def descriptor(self) -> dict[str, Any]:
        return json.loads(self._canonical)

    @property
    def configuration_digest(self) -> str:
        return _digest(self._canonical)


def synthetic_image_data_url(color: str) -> str:
    """A canonical one-pixel fixture; arbitrary images are never sent."""
    rgb = {"red": b"\xff\x00\x00", "green": b"\x00\xff\x00", "blue": b"\x00\x00\xff"}
    if color not in rgb:
        raise ProbeRefused("Synthetic vision fixtures use red, green or blue")
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack("!I", len(data)) + kind + data + struct.pack("!I", zlib.crc32(kind + data))
    png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack("!2I5B", 1, 1, 8, 2, 0, 0, 0))
           + chunk(b"IDAT", zlib.compress(b"\x00" + rgb[color])) + chunk(b"IEND", b""))
    return "data:image/png;base64," + base64.b64encode(png).decode("ascii")


@dataclass(frozen=True)
class ProbeFixtures:
    _canonical: str = field(repr=False)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> ProbeFixtures:
        if not isinstance(raw, dict) or set(raw) - {"synthetic", "fixture_version", "tool_call", "json_schema", "vision"}:
            raise ProbeRefused("Only versioned synthetic fixture selectors are accepted")
        if raw.get("synthetic") is not True:
            raise ProbeRefused("Fixtures must explicitly declare synthetic=true")
        normalized = {"synthetic": True, "fixture_version": _label(raw.get("fixture_version"))}
        for capability in ("tool_call", "json_schema"):
            value = raw.get(capability, False)
            if type(value) is not bool:
                raise ProbeRefused("Fixture selectors must be booleans")
            normalized[capability] = value
        vision = raw.get("vision")
        if vision is not None:
            if not isinstance(vision, dict) or set(vision) != {"image_data_url", "expected"}:
                raise ProbeRefused("Provide only the synthetic image and expected color")
            if vision.get("expected") not in {"red", "green", "blue"} or vision.get("image_data_url") != synthetic_image_data_url(vision["expected"]):
                raise ProbeRefused("Vision accepts only canonical synthetic one-pixel fixtures")
            normalized["vision"] = dict(vision)
        if not any(normalized.get(name) for name in ("tool_call", "json_schema", "vision")):
            raise ProbeRefused("Select at least one synthetic fixture")
        return cls(_canonical(normalized))

    @property
    def descriptor(self) -> dict[str, Any]:
        return json.loads(self._canonical)

    @property
    def fixture_digest(self) -> str:
        return _digest(self._canonical)


def _money(value: Any) -> Decimal:
    if value is None or isinstance(value, bool):
        raise ProbeRefused("Known finite nonnegative prices and cost cap are required")
    text = str(value)
    if len(text) > 128:
        raise ProbeRefused("Monetary values are too large")
    try:
        result = Decimal(text)
    except (InvalidOperation, ValueError):
        raise ProbeRefused("Invalid monetary value") from None
    if not result.is_finite() or result < 0 or result > Decimal("1000000"):
        raise ProbeRefused("Invalid monetary value")
    if result == 0:
        return Decimal(0)
    if result.as_tuple().exponent < -12:
        raise ProbeRefused("Monetary values support at most twelve decimal places")
    return result


@dataclass(frozen=True)
class ProbePrice:
    input_usd_per_million: Any
    output_usd_per_million: Any

    def cost(self, input_tokens: int, output_tokens: int) -> Decimal:
        return (_money(self.input_usd_per_million) * input_tokens
                + _money(self.output_usd_per_million) * output_tokens) / Decimal(1000000)


@dataclass(frozen=True)
class ProbeLimits:
    max_requests: int = 4
    max_output_tokens: int = 64
    max_cost_usd: Any = "0.01"
    max_input_tokens: int = 4096
    timeout_seconds: float = 10

    def validate(self) -> None:
        for value, ceiling in ((self.max_requests, 32), (self.max_output_tokens, 1024), (self.max_input_tokens, 65536)):
            if type(value) is not int or not 1 <= value <= ceiling:
                raise ProbeRefused("Request and token limits must be within documented bounds")
        if type(self.timeout_seconds) not in {int, float} or not 0 < self.timeout_seconds <= 30:
            raise ProbeRefused("Timeout must be greater than zero and at most 30 seconds")
        _money(self.max_cost_usd)


@dataclass(frozen=True)
class ProbeResponse:
    status_code: int
    body: Any = field(repr=False)


class ProbeTransport(Protocol):
    def __call__(self, config: ProbeConfig, payload: dict[str, Any], timeout: float) -> ProbeResponse: ...


def _requests(config: ProbeConfig, fixtures: ProbeFixtures, limits: ProbeLimits) -> list[tuple[str, dict[str, Any]]]:
    cfg, fs = config.descriptor, fixtures.descriptor
    result = []
    for capability in ("tool_call", "json_schema", "vision"):
        if not fs.get(capability):
            continue
        payload: dict[str, Any] = {"model": f"{cfg['provider']}:{cfg['model']}", "stream": False,
                                  "n": 1, "max_tokens": limits.max_output_tokens}
        if capability == "vision":
            payload["messages"] = [{"role": "user", "content": [
                {"type": "text", "text": "Return only the pixel color: red, green or blue."},
                {"type": "image_url", "image_url": {"url": fs["vision"]["image_data_url"], "detail": "low"}},
            ]}]
        else:
            payload["messages"] = [{"role": "user", "content": "Return status ready using the required output contract."}]
            if capability == "tool_call":
                payload["tools"] = [{"type": "function", "function": {
                    "name": "report_status", "description": "Report the synthetic status", "parameters": _SCHEMA}}]
                payload["tool_choice"] = {"type": "function", "function": {"name": "report_status"}}
            else:
                payload["response_format"] = {"type": "json_schema", "json_schema": {
                    "name": "probe_status", "strict": True, "schema": _SCHEMA}}
        encoded = _canonical(payload).encode()
        if len(encoded) > MAX_REQUEST_BYTES or len(encoded) + 256 > limits.max_input_tokens:
            raise ProbeRefused("Fixture request exceeds the conservative input allowance")
        result.append((capability, payload))
    return result


def build_plan(config: ProbeConfig, fixtures: ProbeFixtures, *, limits: ProbeLimits = ProbeLimits(),
               price: ProbePrice | None = None) -> dict[str, Any]:
    limits.validate()
    requests = _requests(config, fixtures, limits)
    if len(requests) > limits.max_requests:
        raise ProbeRefused("Planned request count exceeds --max-requests")
    reserve = None if price is None else price.cost(limits.max_input_tokens, limits.max_output_tokens) * len(requests)
    if reserve is not None and reserve > _money(limits.max_cost_usd):
        raise ProbeRefused("Conservative planned cost exceeds --max-cost-usd")
    return {"planned_requests": len(requests), "capabilities": [name for name, _ in requests],
            "max_requests": limits.max_requests, "max_output_tokens": limits.max_output_tokens,
            "max_input_tokens": limits.max_input_tokens, "max_cost_usd": float(_money(limits.max_cost_usd)),
            "reserved_cost_usd": None if reserve is None else float(reserve),
            "pricing_known": price is not None, "timeout_seconds": limits.timeout_seconds,
            "price_usd_per_million": None if price is None else {
                "input": float(_money(price.input_usd_per_million)),
                "output": float(_money(price.output_usd_per_million))}}


def _observation(capability: str, response: ProbeResponse, fixtures: ProbeFixtures) -> dict[str, Any]:
    row = {"capability": capability, "status": "inconclusive", "http_status": response.status_code,
           "reason": "invalid_response"}
    body = response.body
    if not isinstance(body, dict):
        return row
    if not 200 <= response.status_code < 300:
        row["reason"] = "upstream_rejected"
        error = body.get("error")
        parameters = {"tool_call": {"tools", "tool_choice"}, "json_schema": {"response_format"},
                      "vision": {"image_url", "vision", "messages"}}
        if isinstance(error, dict) and response.status_code in {400, 422}:
            if error.get("code") in {"unsupported_parameter", "unsupported_feature", "unsupported_modality", "unsupported_response_format"} and error.get("param") in parameters[capability]:
                row.update(status="unsupported", reason="explicit_feature_rejection")
        return row
    try:
        choices = body["choices"]
        if not isinstance(choices, list) or len(choices) != 1 or choices[0].get("finish_reason") not in {"stop", "tool_calls"}:
            return row
        message = choices[0]["message"]
        if capability == "tool_call":
            calls = message["tool_calls"]
            valid = (len(calls) == 1 and calls[0]["type"] == "function" and isinstance(calls[0]["id"], str)
                     and bool(calls[0]["id"]) and calls[0]["function"]["name"] == "report_status"
                     and parse_probe_json(calls[0]["function"]["arguments"]) == {"status": "ready"})
        elif capability == "json_schema":
            valid = parse_probe_json(message["content"]) == {"status": "ready"}
        else:
            valid = message["content"].strip().lower() == fixtures.descriptor["vision"]["expected"]
        row["reason"] = "fixture_mismatch"
        if valid:
            row.update(status="supported", reason="output_contract_observed")
    except (KeyError, TypeError, ValueError, AttributeError, IndexError):
        row["reason"] = "malformed_output"
    return row


def _usage(response: ProbeResponse) -> tuple[int | None, int | None, str | None]:
    if not isinstance(response.body, dict) or response.body.get("usage") is None:
        return None, None, None
    usage = response.body["usage"]
    if not isinstance(usage, dict):
        return None, None, "invalid_usage"
    tokens = [usage.get(name) for name in ("prompt_tokens", "completion_tokens")]
    if any(token is not None and (type(token) is not int or token < 0) for token in tokens):
        return None, None, "invalid_usage"
    return tokens[0], tokens[1], None


@dataclass
class _Totals:
    requests: int = 0
    input_tokens: int | None = 0
    output_tokens: int | None = 0
    cost: Decimal | None = Decimal(0)
    reserved: Decimal = Decimal(0)

    def record(self, response: ProbeResponse, price: ProbePrice, limits: ProbeLimits) -> str | None:
        input_tokens, output_tokens, reason = _usage(response)
        self.input_tokens = None if self.input_tokens is None or input_tokens is None else self.input_tokens + input_tokens
        self.output_tokens = None if self.output_tokens is None or output_tokens is None else self.output_tokens + output_tokens
        self.cost = None if self.cost is None or input_tokens is None or output_tokens is None else self.cost + price.cost(input_tokens, output_tokens)
        if reason:
            return reason
        if (input_tokens is not None and input_tokens > limits.max_input_tokens) or (output_tokens is not None and output_tokens > limits.max_output_tokens):
            return "usage_exceeds_budget"
        if self.cost is not None and self.cost > _money(limits.max_cost_usd):
            return "cost_exceeds_budget"
        if response.status_code in {401, 402, 403, 429} or response.status_code >= 500 or 300 <= response.status_code < 400:
            return "upstream_rejected"
        return None


def _dispatch(config: ProbeConfig, fixtures: ProbeFixtures, limits: ProbeLimits, price: ProbePrice,
              transport: ProbeTransport) -> tuple[_Totals, list[dict[str, Any]], str | None]:
    totals, observations, stop = _Totals(), [], None
    reservation = price.cost(limits.max_input_tokens, limits.max_output_tokens)
    for capability, payload in _requests(config, fixtures, limits):
        totals.requests += 1
        totals.reserved += reservation
        try:
            response = transport(config, payload, limits.timeout_seconds)
            observation = _observation(capability, response, fixtures)
            stop = totals.record(response, price, limits)
            if stop in {"usage_exceeds_budget", "invalid_usage", "cost_exceeds_budget"}:
                observation.update(status="inconclusive", reason=stop)
            observations.append(observation)
        except Exception:  # Transports vary; never expose their URL, key or response content.
            observations.append({"capability": capability, "status": "inconclusive", "reason": "transport_error"})
            totals.input_tokens = totals.output_tokens = totals.cost = None
            stop = "transport_error"
        if stop:
            break
    return totals, observations, stop


def run_probes(config: ProbeConfig, fixtures: ProbeFixtures, *, limits: ProbeLimits = ProbeLimits(),
               price: ProbePrice | None = None, execute: bool = False, allow_generation: bool = False,
               transport: ProbeTransport | None = None, clock: Callable[[], str] | None = None) -> dict[str, Any]:
    if execute != allow_generation:
        raise ProbeRefused("Generation requires both --execute and --allow-generation")
    plan = build_plan(config, fixtures, limits=limits, price=price)
    if execute and (price is None or transport is None):
        raise ProbeRefused("Generation requires known input/output prices and an explicit transport")
    totals, observations, stop = _Totals(), [], None
    if execute and price is not None and transport is not None:
        totals, observations, stop = _dispatch(config, fixtures, limits, price, transport)
    cfg, fs = config.descriptor, fixtures.descriptor
    return {"receipt_version": 1, "dry_run": not execute, "runtime": cfg["runtime"],
            "provider": cfg["provider"], "model": cfg["model"],
            "configuration_digest": config.configuration_digest, "policy_revision": cfg["policy_revision"],
            "fixture_version": fs["fixture_version"], "fixture_digest": fixtures.fixture_digest,
            "timestamp": clock() if clock else datetime.now(timezone.utc).isoformat(), "plan": plan,
            "request_count": totals.requests, "input_tokens": totals.input_tokens, "output_tokens": totals.output_tokens,
            "cost_usd": None if totals.cost is None else float(totals.cost),
            "reserved_cost_usd": float(totals.reserved), "stop_reason": stop, "observations": observations}


def receipt_is_current(receipt: Mapping[str, Any], config: ProbeConfig, fixtures: ProbeFixtures) -> bool:
    """Compare measurement bindings, not authenticity or routing eligibility."""
    cfg = config.descriptor
    count = receipt.get("request_count")
    return (receipt.get("receipt_version") == 1 and receipt.get("dry_run") is False
            and type(count) is int and 0 < count <= 32
            and all(receipt.get(name) == cfg[name] for name in ("provider", "model", "runtime"))
            and receipt.get("configuration_digest") == config.configuration_digest
            and receipt.get("fixture_version") == fixtures.descriptor["fixture_version"]
            and receipt.get("fixture_digest") == fixtures.fixture_digest
            and receipt.get("policy_revision") == config.descriptor["policy_revision"])


class _GatewayAdapter:
    runtime = ""

    def __init__(self, key: str):
        if not key or any(ord(c) < 33 or ord(c) > 126 for c in key):
            raise ProbeRefused("Set a gateway key using the selected environment variable")
        self._key = key

    def __call__(self, config: ProbeConfig, payload: dict[str, Any], timeout: float) -> ProbeResponse:
        cfg = config.descriptor
        if cfg["runtime"] != self.runtime:
            raise ProbeRefused("Adapter runtime does not match the measured configuration")
        body = _canonical(payload).encode()
        if len(body) > MAX_REQUEST_BYTES:
            raise ProbeRefused("Request exceeds the diagnostic size bound")
        target = urlsplit(cfg["gateway_base_url"])
        factory = http.client.HTTPSConnection if target.scheme == "https" else http.client.HTTPConnection
        connection = factory(target.hostname, target.port, timeout=timeout)
        headers = {**cfg["headers"], "Content-Type": "application/json", "Authorization": f"Bearer {self._key}"}
        try:
            connection.request("POST", target.path.rstrip("/") + "/v1/chat/completions", body=body, headers=headers)
            response = connection.getresponse()
            data = response.read(MAX_RESPONSE_BYTES + 1)
            if len(data) > MAX_RESPONSE_BYTES:
                raise ProbeRefused("Response exceeds the diagnostic size bound")
            try:
                parsed = parse_probe_json(data)
            except (ValueError, UnicodeError):
                parsed = None
            return ProbeResponse(response.status, parsed)
        finally:
            connection.close()


class FlaskGatewayAdapter(_GatewayAdapter):
    runtime = "flask"


class WorkerGatewayAdapter(_GatewayAdapter):
    runtime = "worker"
