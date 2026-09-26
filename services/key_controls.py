"""Per-key controls: dollar budgets, model allowlists, expiry and client address ranges.

Every control is optional. ``None`` keeps the previous behavior: no budget, every model,
no expiry and every address. Lists are stored comma-separated in ``control_users`` (D1)
or ``users`` (SQLite/PostgreSQL); the Worker validates the same formats.
"""

from __future__ import annotations

import ipaddress
import os
import re
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from error_handlers import APIError

CONTROL_FIELDS = ("daily_budget_usd", "monthly_budget_usd", "allowed_models", "allowed_ips", "expires_at")
MAX_BUDGET_USD = 1_000_000_000
MAX_PATTERNS = 64
MAX_RANGES = 64
MAX_LIST_LENGTH = 4096
MODEL_PATTERN = re.compile(r"[A-Za-z0-9._:/+@*-]{1,256}\Z")


def empty() -> dict[str, Any]:
    return dict.fromkeys(CONTROL_FIELDS)


def _parse_time(value: Any) -> Optional[datetime]:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and len(value) <= 64:
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            raise APIError("expires_at must be an ISO 8601 date and time", 400) from None
    else:
        raise APIError("expires_at must be an ISO 8601 date and time", 400)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _budget(value: Any, name: str) -> Optional[float]:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise APIError(f"{name} must be a non-negative number of US dollars", 400)
    try:
        amount = float(value)
    except (TypeError, ValueError):
        raise APIError(f"{name} must be a non-negative number of US dollars", 400) from None
    if not 0 <= amount <= MAX_BUDGET_USD or amount != amount:
        raise APIError(f"{name} must be between 0 and {MAX_BUDGET_USD} US dollars", 400)
    return round(amount, 6)


def _entries(value: Any, name: str) -> list[str]:
    if value is None or value == "":
        return []
    if isinstance(value, str):
        items = re.split(r"[\s,]+", value)
    elif isinstance(value, (list, tuple)) and all(isinstance(item, str) for item in value):
        items = list(value)
    else:
        raise APIError(f"{name} must be a list of strings", 400)
    return list(dict.fromkeys(item.strip() for item in items if item and item.strip()))


def _models(value: Any) -> Optional[str]:
    patterns = [item.lower() for item in _entries(value, "allowed_models")]
    if not patterns:
        return None
    if len(patterns) > MAX_PATTERNS or any(not MODEL_PATTERN.fullmatch(item) for item in patterns):
        raise APIError(
            f"allowed_models takes up to {MAX_PATTERNS} model IDs or patterns such as auto:*, free:* or openai:gpt-4.1",
            400,
        )
    return _bounded(",".join(dict.fromkeys(patterns)), "allowed_models")


def _ranges(value: Any) -> Optional[str]:
    entries = _entries(value, "allowed_ips")
    if not entries:
        return None
    if len(entries) > MAX_RANGES:
        raise APIError(f"allowed_ips takes up to {MAX_RANGES} addresses or CIDR ranges", 400)
    networks = []
    for entry in entries:
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            raise APIError(f"allowed_ips entry is not an IP address or CIDR range: {entry[:64]}", 400) from None
        mapped = network.network_address.ipv4_mapped if isinstance(network, ipaddress.IPv6Network) else None
        if mapped is not None and network.prefixlen >= 96:
            # Clients arrive as IPv4; store an IPv4-mapped range in the form they match.
            network = ipaddress.ip_network(f"{mapped}/{network.prefixlen - 96}")
        networks.append(str(network))
    return _bounded(",".join(dict.fromkeys(networks)), "allowed_ips")


def _bounded(value: str, name: str) -> str:
    if len(value) > MAX_LIST_LENGTH:
        raise APIError(f"{name} is longer than {MAX_LIST_LENGTH} characters", 400)
    return value


def validate(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize an administrator's controls; unknown fields are refused."""
    if not isinstance(payload, Mapping):
        raise APIError("Key controls must be a JSON object", 400)
    unknown = set(payload) - set(CONTROL_FIELDS)
    if unknown:
        raise APIError(f"Unknown key control: {sorted(unknown)[0][:64]}", 400)
    expires_at = _parse_time(payload.get("expires_at"))
    return {
        "daily_budget_usd": _budget(payload.get("daily_budget_usd"), "daily_budget_usd"),
        "monthly_budget_usd": _budget(payload.get("monthly_budget_usd"), "monthly_budget_usd"),
        "allowed_models": _models(payload.get("allowed_models")),
        "allowed_ips": _ranges(payload.get("allowed_ips")),
        "expires_at": expires_at.isoformat() if expires_at else None,
    }


def from_storage(row: Mapping[str, Any]) -> dict[str, Any]:
    """Controls from a stored row; malformed values are dropped, never widened."""
    controls = empty()
    for name in ("daily_budget_usd", "monthly_budget_usd"):
        value = row.get(name) if hasattr(row, "get") else row[name]
        if isinstance(value, (int, float)) and not isinstance(value, bool) and 0 <= value <= MAX_BUDGET_USD:
            controls[name] = float(value)
    for name in ("allowed_models", "allowed_ips", "expires_at"):
        value = row.get(name) if hasattr(row, "get") else row[name]
        controls[name] = value if isinstance(value, str) and value else None
    return controls


def row_value(row: Any, name: str) -> Any:
    """A control column from a sqlite3.Row or dict that may predate the column."""
    try:
        return row[name]
    except (IndexError, KeyError):
        return None


def public(controls: Mapping[str, Any]) -> dict[str, Any]:
    """Controls as the dashboard and /v1/usage show them: lists as arrays."""
    return {
        "daily_budget_usd": controls.get("daily_budget_usd"),
        "monthly_budget_usd": controls.get("monthly_budget_usd"),
        "allowed_models": model_patterns(controls),
        "allowed_ips": ip_ranges(controls),
        "expires_at": controls.get("expires_at"),
    }


def model_patterns(user: Mapping[str, Any]) -> Optional[list[str]]:
    value = user.get("allowed_models")
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value] or None
    return [item for item in value.split(",") if item] if isinstance(value, str) and value else None


def ip_ranges(user: Mapping[str, Any]) -> Optional[list[str]]:
    value = user.get("allowed_ips")
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value] or None
    return [item for item in value.split(",") if item] if isinstance(value, str) and value else None


def _glob(pattern: str) -> re.Pattern:
    return re.compile("".join(".*" if part == "*" else re.escape(part) for part in re.split(r"(\*)", pattern)) + r"\Z")


def model_allowed(user: Mapping[str, Any], model: Any) -> bool:
    """Whether a model ID matches the key's allowlist; ``*`` matches any characters."""
    patterns = model_patterns(user)
    if patterns is None:
        return True
    if not isinstance(model, str) or not model.strip():
        return False
    candidate = model.strip().lower()
    return any(_glob(pattern.lower()).match(candidate) for pattern in patterns)


def provider_allowed(user: Mapping[str, Any], provider: str) -> bool:
    """Whether a request that names no model may reach a provider namespace."""
    patterns = model_patterns(user)
    if patterns is None:
        return True
    provider = provider.strip().lower()
    return any(pattern in {"*", f"{provider}:*"} for pattern in patterns)


def expires_at(user: Mapping[str, Any]) -> Optional[datetime]:
    try:
        return _parse_time(user.get("expires_at"))
    except APIError:
        # A stored value that cannot be read must not leave the key open forever.
        return datetime.min.replace(tzinfo=timezone.utc)


def expired(user: Mapping[str, Any], now: Optional[datetime] = None) -> bool:
    moment = expires_at(user)
    return moment is not None and moment <= (now or datetime.now(timezone.utc))


def ip_allowed(user: Mapping[str, Any], address: Optional[str]) -> bool:
    ranges = ip_ranges(user)
    if ranges is None:
        return True
    try:
        client = ipaddress.ip_address((address or "").strip())
    except ValueError:
        return False
    if isinstance(client, ipaddress.IPv6Address) and client.ipv4_mapped:
        client = client.ipv4_mapped
    for entry in ranges:
        try:
            if client in ipaddress.ip_network(entry, strict=False):
                return True
        except (ValueError, TypeError):
            continue
    return False


def _trust_proxy_headers() -> bool:
    return os.environ.get("MULTILLM_TRUST_PROXY_HEADERS", "").strip().lower() in {"1", "true", "yes", "on"}


def client_ip(request) -> Optional[str]:
    """The caller's address: CF-Connecting-IP behind the Worker, else the socket peer.

    The Worker forwards Cloudflare's CF-Connecting-IP, which clients cannot set through
    Cloudflare. It is trusted only when the deployment trusts proxy headers.
    """
    if _trust_proxy_headers():
        forwarded = (request.headers.get("CF-Connecting-IP") or "").strip()
        try:
            return str(ipaddress.ip_address(forwarded))
        except ValueError:
            pass
    return request.remote_addr
