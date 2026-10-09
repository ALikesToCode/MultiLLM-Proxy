"""Batch admission, validation and single-submission private storage transport."""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import secrets
from decimal import Decimal, ROUND_CEILING
from functools import lru_cache

import requests
from requests.adapters import HTTPAdapter

from services.cost_service import CostService

ENDPOINT = "http://intelligence.internal/v1/gateway-batches"
ENDPOINTS = frozenset({"/v1/chat/completions", "/v1/responses"})
MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_RESPONSE_BYTES = 24 * 1024 * 1024
MONEY_SCALE = 10_000_000_000
logger = logging.getLogger(__name__)


class BatchError(Exception):
    def __init__(self, status: int, code: str, message: str, line: int | None = None):
        super().__init__(code)
        self.status, self.code, self.message, self.line = status, code, message, line


@lru_cache(maxsize=2)
def _warn_once(name: str):
    logger.warning("Invalid %s; gateway batch setting disabled", name)


def flag(name: str) -> bool:
    value = os.environ.get(name, "").strip().lower()
    if value in {"", "0", "false", "off", "no"}:
        return False
    if value in {"1", "true", "on", "yes"}:
        return True
    _warn_once(name)
    return False


def enabled() -> bool:
    return flag("GATEWAY_BATCHES_ENABLED")


def validate_jsonl(data: bytes) -> list[dict]:
    def bad(number, message):
        raise BatchError(400, "invalid_file", message, number)
    if len(data) > MAX_FILE_BYTES:
        bad(1, "Batch input exceeds 10 MiB.")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        bad(data[:error.start].count(b"\n") + 1, "Batch input must be UTF-8 JSONL.")
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    if not lines:
        bad(1, "Batch input is empty.")
    items, seen = [], set()
    for number, line in enumerate(lines, 1):
        if number > 1000:
            bad(number, "Batch input exceeds 1,000 lines.")
        try:
            item = json.loads(line, parse_constant=lambda _: bad(number, "Non-finite JSON number."))
        except (ValueError, RecursionError):
            bad(number, "Invalid JSON object.")
        if not isinstance(item, dict):
            bad(number, "Each line must contain a JSON object.")
        custom_id, body = item.get("custom_id"), item.get("body")
        if (not isinstance(custom_id, str) or not re.fullmatch(r"[^\x00-\x1f\x7f]{1,64}", custom_id)
                or custom_id in seen or item.get("method") != "POST" or item.get("url") not in ENDPOINTS
                or not isinstance(body, dict) or not isinstance(body.get("model"), str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,255}", body["model"])
                or ("stream" in body and body["stream"] is not False)):
            bad(number, "Invalid batch item or duplicate custom_id.")
        for name in ("max_tokens", "max_completion_tokens", "max_output_tokens"):
            if name in body and (type(body[name]) is not int or not 1 <= body[name] <= 262144):
                bad(number, "Output token limit must be between 1 and 262144.")
        if "n" in body and (type(body["n"]) is not int or not 1 <= body["n"] <= 16):
            bad(number, "Completion count must be between 1 and 16.")
        seen.add(custom_id)
        items.append(item)
    return items


def budget_units(value) -> int:
    if (not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,6}(?:\.[0-9]{1,10})?", value)
            or not Decimal(0) < Decimal(value) <= Decimal(100_000)):
        raise BatchError(400, "invalid_budget", "metadata.multillm_budget_usd must be a positive decimal string, at most 100000 USD and 10 fractional digits.")
    return int(Decimal(value) * MONEY_SCALE)


def cost_units(value) -> int | None:
    if value is None:
        return None
    amount = Decimal(str(value))
    if not amount.is_finite() or amount < 0 or amount > 100_000:
        return None
    return int((amount * MONEY_SCALE).to_integral_value(rounding=ROUND_CEILING))


def estimate_item(item: dict) -> int:
    from services.request_accounting import _candidates
    body = item["body"]
    # Byte count is a conservative input estimate. Output exposure uses the caller's
    # bound when supplied and a conservative 262144-token bound otherwise.
    input_tokens = len(json.dumps(body, ensure_ascii=False).encode())
    output_tokens = max((body[name] for name in ("max_tokens", "max_completion_tokens", "max_output_tokens") if name in body), default=262144) * body.get("n", 1)
    candidates = _candidates(body["model"])
    prices = [CostService.estimate(model, input_tokens, output_tokens) for model in candidates]
    if "routing" in body or not prices or any(price is None for price in prices):
        raise BatchError(400, "unknown_price", "Every batch item and route candidate must have a known model price.")
    estimates = [cost_units(price) for price in prices]
    if any(value is None for value in estimates):
        raise BatchError(400, "invalid_price", "The estimated item cost exceeds the batch monetary bound.")
    return max(value for value in estimates if value is not None)


def call(operation: str, **fields) -> dict:
    """No HTTP retries or redirects: an uncertain write is never resubmitted."""
    data = json.dumps({"version": 1, "operation": operation, **fields}, separators=(",", ":")).encode()
    if len(data) > 16 * 1024 * 1024:
        raise BatchError(400, "request_too_large", "Batch operation exceeds its size bound.")
    try:
        with requests.Session() as session:
            session.trust_env = False
            session.mount("http://", HTTPAdapter(max_retries=0))
            with session.post(ENDPOINT, data=data, timeout=(3, 30), allow_redirects=False, stream=True,
                              headers={"Content-Type": "application/json"}) as response:
                content = bytearray()
                for chunk in response.iter_content(65536):
                    content.extend(chunk)
                    if len(content) > MAX_RESPONSE_BYTES:
                        raise BatchError(503, "gateway_batches_unavailable", "Batch storage returned an oversized reply.")
                status = response.status_code
    except requests.exceptions.RequestException:
        raise BatchError(503, "gateway_batches_unavailable", "Batch storage could not be reached.") from None
    try:
        payload = json.loads(content)
        if not isinstance(payload, dict) or payload.get("version") != 1:
            raise ValueError()
    except (ValueError, RecursionError):
        raise BatchError(503, "gateway_batches_unavailable", "Batch storage returned an invalid reply.") from None
    if status != 200:
        error = payload.get("error") or {}
        raise BatchError(status, error.get("code", "gateway_batches_unavailable"),
                         error.get("message", "Batch operation failed."), error.get("line"))
    return payload


def create_batch(body: dict, user: dict, *, client_ip: str, key_hash: str, key_prefix: str) -> dict:
    from services import key_controls
    from services.media_signing import issue_principal
    if not isinstance(body, dict) or body.get("endpoint") not in ENDPOINTS or body.get("completion_window") != "24h":
        raise BatchError(400, "invalid_batch", "Send an input_file_id, supported endpoint and completion_window of 24h.")
    if not isinstance(body.get("input_file_id"), str) or not re.fullmatch(r"file_[A-Za-z0-9_]{1,128}", body["input_file_id"]):
        raise BatchError(400, "invalid_batch", "Send a valid input_file_id.")
    metadata = body.get("metadata")
    if (not isinstance(metadata, dict) or len(metadata) > 16
            or any(not isinstance(k, str) or len(k) > 64 or not isinstance(v, str) or len(v) > 512 for k, v in metadata.items())):
        raise BatchError(400, "invalid_batch", "metadata accepts at most 16 bounded string values, including multillm_budget_usd.")
    budget = budget_units(metadata.get("multillm_budget_usd"))
    owner = user["username"]
    content = call("file_content", id=body.get("input_file_id"), owner=owner)["content"]
    items = validate_jsonl(base64.b64decode(content, validate=True))
    require_item_retention(items, user, key_hash)
    estimates = []
    for item in items:
        if item["url"] != body["endpoint"]:
            raise BatchError(400, "endpoint_mismatch", "Every item must match the batch endpoint.")
        if not key_controls.model_allowed(user, item["body"]["model"]):
            raise BatchError(403, "model_not_allowed", "A batch item is outside this key's model permissions.")
        estimates.append({"custom_id": item["custom_id"], "estimate_units": estimate_item(item)})
    batch_id = "batch_" + secrets.token_hex(16)
    return call("batch_create", id=batch_id, owner=owner, input_file_id=body["input_file_id"], endpoint=body["endpoint"],
                completion_window="24h", metadata=metadata, budget_units=budget, estimates=estimates,
                principal=issue_principal("gateway_batch", batch_id, owner, 86500), client_ip=client_ip,
                key_hash=key_hash, key_prefix=key_prefix)["batch"]


def request_identity() -> dict:
    from flask import g, request
    from route_helpers import request_api_key
    from services.key_controls import client_ip
    key = request_api_key() or ""
    return {"client_ip": client_ip(request) or "", "key_hash": hashlib.sha256(key.encode()).hexdigest() if key else "",
            "key_prefix": (g.authenticated_user or {}).get("api_key_prefix") or ""}


def require_item_retention(items: list[dict], user: dict, key_hash: str) -> None:
    from services.retention_policy import resolve_policy
    for endpoint in {item["url"] for item in items}:
        if not resolve_policy(key_id=str(user.get("id") or user["username"]), key_hash=key_hash,
                              route=endpoint).allows_content:
            raise BatchError(400, "retention_conflict", "Zero-content retention cannot persist batch items for this endpoint.")
