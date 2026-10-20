"""Opt-in per-key stream caps, bucket bounds and protocol-aware cleanup."""
from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, ROUND_CEILING
from typing import Any

from error_handlers import APIError
from services.cost_service import CostService
from services.prompt_cache_cost import CacheObservation, buckets_from, COST_FIELDS

logger = logging.getLogger(__name__)
CAP_FIELD = "max_stream_cost_microusd"
MAX_CAP = 1_000_000_000_000
FRAME_LIMIT = 65536
_warned: set[str] = set()
FRAME_END = re.compile(br"\r\n\r\n|\n\n|\r\r")
FALSE = {"", "false", "0", "no", "off"}

def enabled() -> bool:
    flag = os.environ.get("STREAM_COST_BREAKER_ENABLED", "").strip().lower()
    if flag in FALSE:
        return False
    if flag in {"true", "1", "yes", "on"}:
        return True
    if "flag" not in _warned:
        _warned.add("flag")
        logger.warning("Invalid STREAM_COST_BREAKER_ENABLED; stream cost breaker disabled")
    return False

def failure(code: str, status: int = 503) -> APIError:
    return APIError("Stream cost enforcement could not admit this request", status, {"error": code})

def valid_cap(value: Any) -> bool:
    return value is None or (type(value) is int and 0 <= value <= MAX_CAP)

def validate_cap(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        number = Decimal(str(value)) * 1_000_000
    except (InvalidOperation, ValueError, TypeError):
        raise APIError("max_stream_cost_usd must be a nonnegative whole number of micro-USD", 400) from None
    if isinstance(value, bool) or not number.is_finite() or number < 0 or number > MAX_CAP or number != number.to_integral_value():
        raise APIError("max_stream_cost_usd must be a nonnegative whole number of micro-USD", 400)
    return int(number)

def storage_control(row) -> dict:
    if not enabled():
        return {}
    try:
        cap = row[CAP_FIELD]
    except (KeyError, IndexError):
        return {}
    if not valid_cap(cap):
        raise failure("stream_cost_storage_unavailable")
    return {CAP_FIELD: cap} if cap is not None else {}

def cap_for(user):
    if CAP_FIELD in user:
        return user[CAP_FIELD]
    if user.get("max_stream_cost_usd") is None:
        return None
    try:
        return validate_cap(user["max_stream_cost_usd"])
    except APIError:
        raise failure("stream_cost_storage_unavailable") from None

def public_control(row) -> dict:
    cap = row.get(CAP_FIELD)
    return {"max_stream_cost_usd": cap / 1_000_000} if enabled() and cap is not None else {}

def validated_control(payload) -> dict:
    return {CAP_FIELD: validate_cap(payload["max_stream_cost_usd"])} if enabled() and "max_stream_cost_usd" in payload else {}

def sql_select(query: str) -> str:
    return query.replace("shadow_eval_rate\n", "shadow_eval_rate, max_stream_cost_microusd\n") if enabled() else query

def ensure_sql_cap(connection) -> None:
    if enabled() and CAP_FIELD not in {row["name"] for row in connection.execute("PRAGMA table_info(users)")}:
        connection.execute("ALTER TABLE users ADD COLUMN max_stream_cost_microusd INTEGER CHECK (max_stream_cost_microusd BETWEEN 0 AND 1000000000000)")

def persist_sql_cap(connection, username, controls) -> None:
    if enabled() and CAP_FIELD in controls:
        cap = controls[CAP_FIELD]
        if not valid_cap(cap):
            raise failure("stream_cost_storage_unavailable")
        connection.execute("UPDATE users SET max_stream_cost_microusd=? WHERE username=?", (cap, username))

def d1_row(value):
    from services import user_store
    if not enabled():
        return user_store._row(value)
    if not isinstance(value, dict) or CAP_FIELD not in value or not valid_cap(value[CAP_FIELD]):
        raise failure("stream_cost_storage_unavailable")
    base = user_store._row({name: item for name, item in value.items() if name != CAP_FIELD})
    return {**base, CAP_FIELD: value[CAP_FIELD]}

def d1_read(operation, **values):
    from services import user_store
    response = user_store._call(operation, **values)
    if operation == "get":
        if "user" not in response:
            raise failure("stream_cost_storage_unavailable")
        return None if response["user"] is None else d1_row(response["user"])
    rows = response.get("users")
    if not isinstance(rows, list) or len(rows) > user_store.PAGE_SIZE:
        raise failure("stream_cost_storage_unavailable")
    return [d1_row(row) for row in rows]

def list_users():
    from services import user_store
    if not enabled():
        return user_store.list_users()
    rows, after = [], None
    while True:
        page = d1_read("list", after=after, limit=user_store.PAGE_SIZE)
        rows.extend(page)
        if len(page) < user_store.PAGE_SIZE:
            return rows
        after = page[-1]["username"]

def get_user(username):
    from services import user_store
    return d1_read("get", username=username) if enabled() else user_store.get_user(username)

def users_by_prefix(prefix):
    from services import user_store
    return d1_read("by_prefix", prefix=prefix) if enabled() else user_store.users_by_prefix(prefix)

def upsert_user(user):
    from services import user_store
    if not enabled():
        return user_store.upsert_user(user)
    fields = {name: user[name] for name in user_store.USER_FIELDS}
    if CAP_FIELD in user:
        if not valid_cap(user[CAP_FIELD]):
            raise failure("stream_cost_storage_unavailable")
        fields[CAP_FIELD] = user[CAP_FIELD]
    if user_store._call("upsert", user=fields).get("stored") is not True:
        raise failure("stream_cost_storage_unavailable")

def input_bound(payload) -> int:
    values = [payload[name] for name in ("messages", "input", "prompt", "contents", "system",
        "instructions", "tools", "functions", "tool_choice", "response_format", "response_schema") if name in payload]
    return len(json.dumps(values, ensure_ascii=False).encode("utf-8")) if values else 0

@dataclass(frozen=True)
class Prices:
    model: str
    bound_input: Decimal
    output: Decimal
    flat: Decimal
    rates: tuple[Decimal, ...]

def prices_for(model: str) -> Prices:
    probe = CacheObservation(3, 1, "provider", ("provider",), 1, 1, 1, "anthropic")
    result = CostService.price_buckets(model, probe)
    if result["cost_usd"] is None or any(result[name] is None for name in COST_FIELDS):
        raise failure("stream_cost_unpriced")
    rates = [Decimal(str(result[name])) for name in COST_FIELDS]
    catalog = CostService.pricing_for(model) or {}
    flat = catalog.get("request", Decimal(0)) * 1_000_000
    return Prices(model, max(rates[:3]), rates[3], flat, tuple(rates))

def _strings(value) -> int:
    if isinstance(value, str):
        return len(value.encode("utf-8"))
    if isinstance(value, dict):
        return sum(_strings(v) for v in value.values())
    if isinstance(value, list):
        return sum(_strings(v) for v in value)
    return 0

def _output_bytes(value) -> int:
    choices = value.get("choices")
    if isinstance(choices, list):
        return sum(_strings(choice.get("delta", {})) for choice in choices if isinstance(choice, dict))
    delta = value.get("delta")
    if isinstance(delta, (str, dict)):
        return _strings(delta)
    return 0

def _terminal(value) -> bool:
    return value.get("type") in {"message_stop", "response.completed", "response.failed", "response.incomplete"} or (
        isinstance(value.get("choices"), list) and any(isinstance(c, dict) and c.get("finish_reason") is not None for c in value["choices"]))

class StreamCostState:
    def __init__(self, cap, prices, input_tokens, protocol):
        self.cap, self.prices, self.input_tokens, self.protocol = cap, prices, input_tokens, protocol
        self.running_microusd = 0
        self.basis = "conservative_estimate"
        self.exceeded = False
        self.observation = None
        self.final_usage = None
        self.output_bound = 0
        self.output_at_measurement = 0
        self.cancel = None
        self.terminal = False
        self._cost()

    def _cost(self):
        measured = self.observation
        additional = self.output_bound - self.output_at_measurement
        costs, fully_measured = [], measured is not None and additional == 0
        counts = buckets_from(measured)
        amounts = [counts[name] for name in (
            "ordinary_input_tokens", "cache_read_input_tokens", "cache_write_input_tokens", "output_tokens")]
        for price in self.prices:
            if all(amount is not None or rate == 0 for amount, rate in zip(amounts, price.rates)):
                amount = price.flat + sum((Decimal(value or 0) * rate for value, rate in zip(amounts, price.rates)), Decimal(0))
                amount += additional * price.output
            else:
                fully_measured = False
                known_input = sum(v for v in amounts[:3] if v is not None)
                output = measured.output_tokens if measured is not None and measured.output_tokens is not None else 0
                amount = price.flat + max(self.input_tokens, known_input) * price.bound_input + max(output + additional, self.output_bound) * price.output
            costs.append(amount)
        self.running_microusd = int(max(costs).to_integral_value(rounding=ROUND_CEILING))
        self.basis = "measured" if fully_measured else "conservative_estimate"

    def observe(self, frame: bytes) -> bool:
        try:
            text = frame.decode("utf-8")
            data = "\n".join(line[5:].lstrip(" ") for line in text.splitlines() if line.startswith("data:"))
            if not data:
                return True
            if data == "[DONE]":
                self.terminal = True
                if self.basis == "measured":
                    self.final_usage = self.observation
                return True
            value = json.loads(data)
            if not isinstance(value, dict):
                raise ValueError
        except (UnicodeError, ValueError, RecursionError):
            self.exceeded = True
            return False
        self.output_bound += _output_bytes(value)
        usage = CacheObservation.from_body(value)
        if usage is not None:
            self.observation = self.observation.merge(usage) if self.observation is not None else usage
            if usage.output_tokens is not None:
                self.output_at_measurement = self.output_bound
        self._cost()
        if _terminal(value):
            self.terminal = True
        if self.terminal and self.basis == "measured":
            self.final_usage = self.observation
        elif self.basis != "measured":
            self.final_usage = None
        if self.running_microusd > self.cap:
            self.exceeded = True
            return False
        return True

    def error_frame(self) -> bytes:
        error = {"code": "stream_cost_cap_exceeded", "type": "stream_cost_cap_exceeded",
                 "message": "The stream cost cap was exceeded.", "cost_basis": self.basis}
        if self.protocol == "anthropic":
            value, prefix = {"type": "error", "error": error}, "event: error\n"
        elif self.protocol == "responses":
            value, prefix = {"type": "response.failed", "response": {"object": "response", "status": "failed", "error": error}}, "event: response.failed\n"
        else:
            value, prefix = {"error": error}, ""
        return (prefix + "data: " + json.dumps(value) + "\n\n").encode()

def prepare(user, models, input_tokens, protocol):
    if not enabled():
        return None
    cap = cap_for(user)
    if cap is None:
        return None
    if not valid_cap(cap):
        raise failure("stream_cost_storage_unavailable")
    if not models:
        raise failure("stream_cost_unpriced")
    state = StreamCostState(cap, [prices_for(model) for model in models], input_tokens, protocol)
    if state.running_microusd > cap:
        raise failure("stream_cost_cap_exceeded", 429)
    return state

def bind_upstream(context):
    from flask import g, has_request_context
    if has_request_context():
        usage = getattr(g, "usage_context", None)
        state = getattr(usage, "stream_cost", None)
        if state is not None:
            owner = getattr(g, "gateway_cancellation", None)
            state.cancel = owner.cancel if owner is not None else context.cancel

class CostStream:
    """Buffer one bounded SSE frame; close even before the first read."""
    def __init__(self, source, state):
        self.source, self.iterator, self.state = source, iter(source), state
        self.pending = b""
        self.stopped = self.closed = False
        self.trailer = b""

    def __iter__(self):
        return self

    def _close_source(self):
        if self.closed:
            return
        self.closed = True
        try:
            if self.state.cancel is not None:
                self.state.cancel()
        finally:
            close = getattr(self.source, "close", None)
            if callable(close):
                try:
                    close()
                except Exception as error:
                    logger.warning("Stream cost cleanup failed type=%s", type(error).__name__)

    def _reject(self, keep_usage=False):
        self.state.exceeded = True
        if not keep_usage:
            self.state.final_usage = None
        self.stopped = True
        self.pending = self.trailer = b""
        self._close_source()
        return self.state.error_frame()

    def __next__(self):
        if self.stopped:
            raise StopIteration
        while True:
            match = FRAME_END.search(self.pending)
            if match:
                frame, self.pending = self.pending[:match.end()], self.pending[match.end():]
                if len(frame) > FRAME_LIMIT:
                    return self._reject()
                if not self.state.observe(frame):
                    return self._reject(keep_usage=self.state.running_microusd > self.state.cap)
                if self.state.terminal:
                    self.trailer += frame
                    if len(self.trailer) > FRAME_LIMIT:
                        return self._reject()
                    continue
                return frame
            if len(self.pending) > FRAME_LIMIT:
                return self._reject()
            try:
                chunk = next(self.iterator)
            except StopIteration:
                if self.pending:
                    return self._reject()
                self.stopped = True
                self._close_source()
                if self.trailer:
                    trailer, self.trailer = self.trailer, b""
                    return trailer
                raise
            except BaseException:
                self.close()
                raise
            self.pending += chunk.encode("utf-8") if isinstance(chunk, str) else bytes(chunk)

    def close(self):
        self.stopped = True
        self.pending = b""
        self._close_source()

def wrap_stream(source, state):
    return CostStream(source, state) if state is not None else source
