"""Bounded, content-free observations of explicit Chat protocol conformance."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import secrets
import time
from collections.abc import Callable
from typing import Any, Protocol
from urllib.parse import unquote, urlsplit

import requests
from requests.adapters import HTTPAdapter

MAX_RESPONSE_BYTES = 256 * 1024
REQUEST_TIMEOUT = 10
MAX_TOKENS = 64


class ConfigError(ValueError):
    """A configuration error whose reason is safe to print."""


class Transport(Protocol):
    def request(self, method: str, url: str, **kwargs: Any) -> Any: ...


def new_nonce() -> str:
    return secrets.token_hex(16)


def validate_target(base_url: str, model: str, *, allow_loopback_http: bool = False) -> str:
    """Validate without resolving hosts or importing gateway configuration."""
    if not isinstance(model, str) or not re.fullmatch(r"[a-z][a-z0-9_-]*:[^\s\x00-\x1f\x7f]+", model):
        raise ConfigError("explicit_provider_model_required")
    try:
        model.encode("utf-8")
    except UnicodeError:
        raise ConfigError("invalid_model_text") from None
    provider, local_model = model.split(":", 1)
    if provider in {"auto", "free", "intelligence", "cascade"} or local_model.startswith(
        ("auto:", "free:", "intelligence:", "cascade:")
    ):
        raise ConfigError("routing_model_not_allowed")
    if not isinstance(base_url, str) or any(char in base_url for char in "?#\\") or any(
        char.isspace() or ord(char) < 32 or ord(char) == 127 for char in base_url
    ):
        raise ConfigError("invalid_base_url")
    try:
        parsed = urlsplit(base_url)
        host, port = parsed.hostname, parsed.port
        path = unquote(parsed.path)
        invalid = (
            not host or parsed.username is not None or parsed.password is not None
            or parsed.scheme not in {"https", "http"}
            or (port is not None and not 1 <= port <= 65535)
            or any(segment in {".", ".."} for segment in path.split("/"))
            or any(char in path for char in "\\?#")
            or any(ord(char) < 32 or ord(char) == 127 for char in path)
        )
        loopback = host == "localhost"
        if host and not loopback:
            try:
                loopback = ipaddress.ip_address(host).is_loopback
            except ValueError:
                loopback = False
        if parsed.scheme == "http" and not (allow_loopback_http and loopback):
            invalid = True
        if invalid:
            raise ConfigError("invalid_base_url")
    except ValueError:
        raise ConfigError("invalid_base_url") from None
    return base_url.rstrip("/")


def diagnostic_plan(*, allow_generation: bool = False) -> dict[str, Any]:
    return {
        "phase": "plan",
        "request_budget": 3 if allow_generation else 1,
        "generation_request_budget": 2 if allow_generation else 0,
        "max_tokens_per_request": MAX_TOKENS if allow_generation else 0,
        "max_output_tokens": 2 * MAX_TOKENS if allow_generation else 0,
        "timeout_seconds": REQUEST_TIMEOUT,
        "max_response_bytes": MAX_RESPONSE_BYTES,
        "retries": 0,
        "redirects": False,
        "projected_cost": None,
    }


class RequestsTransport:
    """One request per call, without ambient netrc credentials or proxy settings."""

    def __init__(self) -> None:
        self._session = requests.Session()
        self._session.trust_env = False
        self._session.mount("https://", HTTPAdapter(max_retries=0))
        self._session.mount("http://", HTTPAdapter(max_retries=0))

    def request(self, method: str, url: str, **kwargs: Any) -> Any:
        self._session.cookies.clear()
        return self._session.request(method, url, **kwargs)

    def close(self) -> None:
        self._session.close()


def _exchange(client: Transport, method: str, url: str, api_key: str,
              payload: dict[str, Any] | None = None) -> tuple[Any, int | None, str | None]:
    response, body, status, reason = None, None, None, None
    started = time.monotonic()
    try:
        kwargs: dict[str, Any] = {
            "headers": {"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
            "timeout": REQUEST_TIMEOUT, "allow_redirects": False, "stream": True,
        }
        if payload is not None:
            kwargs["json"] = payload
        response = client.request(method, url, **kwargs)
        raw_status = response.status_code
        if type(raw_status) is not int or not 100 <= raw_status <= 599:
            reason = "invalid_http_status"
        else:
            status = raw_status
            if not 200 <= status < 300:
                reason = f"http_{status}"
            else:
                raw = bytearray()
                for chunk in response.iter_content(chunk_size=8192):
                    if time.monotonic() - started > REQUEST_TIMEOUT:
                        reason = "timeout"
                        break
                    if not isinstance(chunk, bytes):
                        reason = "invalid_response_bytes"
                        break
                    if len(raw) + len(chunk) > MAX_RESPONSE_BYTES:
                        reason = "response_too_large"
                        break
                    raw.extend(chunk)
                if reason is None:
                    try:
                        body = json.loads(raw)
                    except (ValueError, UnicodeError, RecursionError):
                        reason = "invalid_json"
    except requests.Timeout:
        reason = "timeout"
    except requests.RequestException:
        reason = "transport_error"
    except Exception:  # Collaborators must not leak request or exception contents.
        reason = "response_error"
    finally:
        if response is not None:
            try:
                response.close()
            except Exception:
                reason = "response_close_failed"
    return body, status, reason


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _count(value: Any) -> bool:
    return type(value) is int and value >= 0


def _usage_signal(usage: Any, *, output_present: bool = False) -> dict[str, Any]:
    fields = ("prompt_tokens", "completion_tokens", "total_tokens")
    if usage is None:
        return {"usage": {}, "usage_verdict": "unknown", "usage_reason": "usage_incomplete"}
    if not isinstance(usage, dict):
        return {"usage": {}, "usage_verdict": "contradicted", "usage_reason": "usage_not_object"}
    observed = {field: usage[field] for field in fields if field in usage and _count(usage[field])}
    invalid = any(field in usage and not _count(usage[field]) for field in fields)
    invalid = invalid or observed.get("completion_tokens", 0) > MAX_TOKENS
    invalid = invalid or observed.get("prompt_tokens") == 0
    invalid = invalid or (output_present and observed.get("completion_tokens") == 0)
    if len(observed) == 3:
        invalid = invalid or observed["total_tokens"] != observed["prompt_tokens"] + observed["completion_tokens"]
    verdict = "contradicted" if invalid else "supported" if len(observed) == 3 else "unknown"
    reason = {"contradicted": "invalid_usage_counts", "supported": "counts_plausible",
              "unknown": "usage_incomplete"}[verdict]
    return {"usage": observed, "usage_verdict": verdict, "usage_reason": reason}


def evaluate_chat(payload: Any, nonce: str, request_index: int) -> dict[str, Any]:
    """Evaluate only the fields needed by the synthetic, nonstreaming contract."""
    observation: dict[str, Any] = {"request_index": request_index, "kind": "chat"}
    body = payload if isinstance(payload, dict) else {}
    choices = body.get("choices")
    choice = choices[0] if isinstance(choices, list) and len(choices) == 1 and isinstance(choices[0], dict) else {}
    message = choice.get("message")
    message = message if isinstance(message, dict) else {}
    content, model, finish = message.get("content"), body.get("model"), choice.get("finish_reason")
    schema = {
        "id": isinstance(body.get("id"), str) and bool(body["id"]),
        "object": body.get("object") == "chat.completion",
        "created": _count(body.get("created")),
        "model": isinstance(model, str) and bool(model),
        "choices": bool(choice),
        "index": type(choice.get("index")) is int and choice["index"] == 0,
        "message_role": message.get("role") == "assistant",
        "message_content": isinstance(content, str),
        "finish_reason": isinstance(finish, str) and finish in {"stop", "length", "content_filter"},
        "no_error": "error" not in body,
    }
    observation.update({"schema": schema, "schema_valid": all(schema.values()),
                        "model_claim_hash": _digest(model) if isinstance(model, str) else None,
                        "completion_hash": _digest(content) if isinstance(content, str) else None,
                        "nonce_matches": content.strip() == nonce if isinstance(content, str) else False,
                        "output_complete": finish == "stop"})
    observation.update(_usage_signal(body.get("usage"), output_present=isinstance(content, str) and bool(content)))
    return observation


def _catalog_observation(payload: Any, model: str) -> dict[str, Any]:
    entries = payload.get("data") if isinstance(payload, dict) else None
    valid = isinstance(entries, list) and all(
        isinstance(entry, dict) and isinstance(entry.get("id"), str) and bool(entry["id"])
        for entry in entries
    )
    present = valid and isinstance(entries, list) and any(entry["id"] == model for entry in entries)
    return {"request_index": 1, "kind": "catalog", "schema_valid": bool(valid),
            "model_listed": bool(present)}


def _add_unique(values: list[str], value: str) -> None:
    if value not in values:
        values.append(value)


def _record_chat(report: dict[str, Any], observation: dict[str, Any], model: str) -> None:
    report["observations"].append(observation)
    for signal in ("chat_envelope_schema", "response_model_claim", "usage_plausibility", "synthetic_nonce_echo"):
        _add_unique(report["coverage"], signal)
    if not observation["schema_valid"]:
        _add_unique(report["contradictions"], "chat_envelope_schema")
    if observation["usage_verdict"] == "contradicted":
        _add_unique(report["contradictions"], "usage_plausibility")
    elif observation["usage_verdict"] == "unknown":
        _add_unique(report["limitations"], "usage_incomplete")
    if observation["schema_valid"]:
        if not observation["output_complete"]:
            _add_unique(report["limitations"], "output_incomplete")
        elif not observation["nonce_matches"]:
            _add_unique(report["contradictions"], "synthetic_nonce_echo")
    if observation["model_claim_hash"] not in {_digest(model), _digest(model.split(":", 1)[1])}:
        _add_unique(report["limitations"], "model_claim_differs")


def _record_consistency(report: dict[str, Any]) -> None:
    first, second = report["observations"][-2:]
    _add_unique(report["coverage"], "repeated_envelope_consistency")
    second["envelope_consistent"] = first["schema"] == second["schema"]
    second["model_claim_consistent"] = first["model_claim_hash"] == second["model_claim_hash"]
    second["independent_nonce_handling"] = first["nonce_matches"] and second["nonce_matches"]
    if not second["envelope_consistent"]:
        _add_unique(report["contradictions"], "repeated_envelope_consistency")
    if not second["model_claim_consistent"]:
        _add_unique(report["contradictions"], "repeated_model_claim_consistency")
    if set(first["usage"]) != set(second["usage"]):
        _add_unique(report["limitations"], "repeated_usage_shape_differs")


def _synthetic_nonces(nonce_factory: Callable[[], str]) -> list[str]:
    try:
        nonces = [nonce_factory(), nonce_factory()]
        if any(not isinstance(nonce, str) or not re.fullmatch(r"[a-zA-Z0-9]{16,64}", nonce)
               for nonce in nonces) or nonces[0] == nonces[1]:
            raise ValueError
    except Exception:
        raise ConfigError("independent_nonces_required") from None
    return nonces


def _run_probes(report: dict[str, Any], base_url: str, model: str, client: Transport,
                api_key: str, nonces: list[str]) -> dict[str, Any]:
    for index, nonce in enumerate(nonces, start=2):
        payload = {"model": model, "max_tokens": MAX_TOKENS, "stream": False,
                   "messages": [{"role": "user", "content": "Reply with exactly this nonce and no other text: " + nonce}]}
        report["requests"] += 1
        report["generation_requests"] += 1
        body, status, reason = _exchange(client, "POST", base_url + "/v1/chat/completions", api_key, payload)
        if reason:
            report["observations"].append({"request_index": index, "kind": "chat", "http_status": status,
                                           "reason": reason})
            if reason == "invalid_json":
                _add_unique(report["coverage"], "chat_json_envelope")
                report["contradictions"].append("chat_json_envelope")
                report["verdict"] = "contradicted"
            else:
                report["limitations"].extend(["probes_insufficient", reason])
            return report
        try:
            observation = evaluate_chat(body, nonce, index)
        except UnicodeError:
            report["observations"].append({"request_index": index, "kind": "chat",
                                           "http_status": status, "reason": "invalid_response_text"})
            report["limitations"].extend(["probes_insufficient", "invalid_response_text"])
            return report
        observation["http_status"] = status
        _record_chat(report, observation, model)
        if index == 3:
            _record_consistency(report)
        if report["contradictions"]:
            report["verdict"] = "contradicted"
            if index == 2:
                report["limitations"].append("repeated_probe_not_observed")
            return report
    measured = report["observations"][1:]
    if all(item["schema_valid"] and item["output_complete"] and item["nonce_matches"]
           and item["usage_verdict"] == "supported" for item in measured):
        report["verdict"] = "supported"
    else:
        report["limitations"].append("probes_insufficient")
    return report


def run_diagnostics(base_url: str, model: str, *, client: Transport, api_key: str,
                    allow_generation: bool = False, allow_loopback_http: bool = False,
                    nonce_factory: Callable[[], str] = new_nonce) -> dict[str, Any]:
    """Inspect a catalog, then optionally send two independent synthetic prompts."""
    base_url = validate_target(base_url, model, allow_loopback_http=allow_loopback_http)
    if not isinstance(api_key, str) or not api_key.strip() or any(
        ord(char) < 32 or ord(char) == 127 for char in api_key
    ):
        raise ConfigError("operator_key_required")
    nonces = _synthetic_nonces(nonce_factory) if allow_generation else []
    report: dict[str, Any] = {
        "verdict": "unknown", "claim": "chat_protocol_conformance" if allow_generation else "model_identity",
        "requests": 1, "generation_requests": 0, "coverage": [], "contradictions": [],
        "limitations": ["identity_not_verified", "billing_not_verified"], "observations": [],
    }
    body, status, reason = _exchange(client, "GET", base_url + "/v1/models", api_key)
    if reason:
        report["observations"].append({"request_index": 1, "kind": "catalog", "http_status": status,
                                       "reason": reason})
        report["limitations"].extend(["metadata_unavailable", reason])
        return report
    catalog = _catalog_observation(body, model)
    catalog["http_status"] = status
    report["observations"].append(catalog)
    if not catalog["schema_valid"]:
        report["limitations"].append("catalog_schema_invalid")
        return report
    report["coverage"].append("catalog_claim")
    if not catalog["model_listed"]:
        report["limitations"].append("model_not_in_catalog")
        return report
    if not allow_generation:
        return report
    return _run_probes(report, base_url, model, client, api_key, nonces)
