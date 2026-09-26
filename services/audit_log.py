"""The dashboard audit trail in the Worker's D1 database, through the private users handler.

The Worker appends every account write to control_user_audit itself. This module records
security events in control_audit_events (sign-ins, sign-outs, refused single sign-on and
administrator setting changes) and reads both tables back, newest first, one bounded page
at a time. Recording is best effort: a failure is logged and never undoes the action.
Without D1 account storage there is no audit trail to read or write.
"""

import logging
import re
import time
from typing import Any, Mapping, Optional

from error_handlers import APIError
from services import user_store
from services.intelligence_d1_store import PrivateIntelligenceError, request_private_intelligence

logger = logging.getLogger(__name__)

EVENT_ACTIONS = ("sign_in", "sign_out", "setting_change")
ACCOUNT_ACTIONS = ("upsert", "delete")
ACTIONS = ACCOUNT_ACTIONS + EVENT_ACTIONS
OUTCOMES = frozenset({"succeeded", "refused"})
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 100
MAX_FILTER_LENGTH = 256
MAX_DETAIL_LENGTH = 512
READ_RETRY_DELAY_SECONDS = 0.25
ENTRY_FIELDS = frozenset({
    "source", "id", "at", "actor", "action", "outcome", "target", "detail",
    "is_admin", "scopes", "api_key_prefix", "revoked_at",
})
_TEXT_FIELDS = ("actor", "target", "detail", "scopes", "api_key_prefix", "revoked_at")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_CURSOR = re.compile(r"(\d{0,15}):(\d{0,15})\Z")


def available() -> bool:
    return user_store.using_d1()


def _text(value: Any, maximum: int) -> Optional[str]:
    """A bounded single-line value, or None."""
    if not isinstance(value, str):
        return None
    cleaned = _CONTROL.sub(" ", value).strip()
    return cleaned[:maximum] or None


def record(action: str, outcome: str, *, actor: Any = None, target: Any = None, detail: Any = None) -> bool:
    """Append one security event; returns whether it was stored."""
    if action not in EVENT_ACTIONS or outcome not in OUTCOMES:
        raise ValueError("Unsupported audit event")
    if not available():
        return False
    payload = {
        "operation": "audit_record", "action": action, "outcome": outcome,
        "actor": _text(actor, MAX_FILTER_LENGTH), "target": _text(target, MAX_FILTER_LENGTH),
        "detail": _text(detail, MAX_DETAIL_LENGTH),
    }
    try:
        response = request_private_intelligence(payload, endpoint="users")
    except Exception as error:
        cause = (f"{error.status} {error.code}" if isinstance(error, PrivateIntelligenceError)
                 else getattr(error, "code", None) or type(error).__name__)
        logger.warning("Could not record the %s audit event (%s)", action, cause)
        return False
    return response.get("recorded") is True


def _filter(args: Mapping[str, str], name: str) -> Optional[str]:
    value = (args.get(name) or "").strip()
    if not value:
        return None
    if len(value) > MAX_FILTER_LENGTH or _CONTROL.search(value):
        raise APIError(f"The {name} filter must be at most {MAX_FILTER_LENGTH} printable characters", 400)
    return value


def parse_cursor(value: Optional[str]) -> tuple[Optional[int], Optional[int]]:
    """``account:event`` ids from a previous page; an empty side starts at the newest row."""
    if not value:
        return None, None
    match = _CURSOR.fullmatch(value)
    if not match or value == ":":
        raise APIError("The page cursor is invalid", 400)
    return tuple(int(part) if part else None for part in match.groups())  # type: ignore[return-value]


def format_cursor(value: Optional[Mapping[str, Any]]) -> Optional[str]:
    if value is None:
        return None
    return ":".join("" if value[side] is None else str(value[side]) for side in ("account", "event"))


def parse_query(args: Mapping[str, str]) -> dict[str, Any]:
    """Validated filters, cursor and page size from query parameters."""
    action = _filter(args, "action")
    if action is not None and action not in ACTIONS:
        raise APIError("Unknown audit action", 400)
    limit_value = (args.get("limit") or "").strip()
    if not limit_value:
        limit = DEFAULT_PAGE_SIZE
    elif limit_value.isdecimal() and 1 <= int(limit_value) <= MAX_PAGE_SIZE:
        limit = int(limit_value)
    else:
        raise APIError(f"The page size must be between 1 and {MAX_PAGE_SIZE}", 400)
    return {"actor": _filter(args, "actor"), "target": _filter(args, "target"), "action": action,
            "before": parse_cursor((args.get("before") or "").strip()), "limit": limit}


def _cursor_side(value: Any) -> bool:
    return value is None or (type(value) is int and value >= 0)


def _entry(value: Any) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != ENTRY_FIELDS
        or value["source"] not in {"account", "event"}
        or type(value["id"]) is not int
        or not isinstance(value["at"], str)
        or not isinstance(value["action"], str)
        or not isinstance(value["outcome"], str)
        or not (value["is_admin"] is None or (type(value["is_admin"]) is int and value["is_admin"] in (0, 1)))
        or any(value[name] is not None and not isinstance(value[name], str) for name in _TEXT_FIELDS)
    ):
        raise user_store.unavailable()
    return value


def page(*, actor=None, target=None, action=None, before=(None, None), limit=DEFAULT_PAGE_SIZE) -> dict[str, Any]:
    """One page of entries, newest first, and the cursor of the next page (or None)."""
    payload = {"operation": "audit_list", "actor": actor, "target": target, "action": action,
               "before_account": before[0], "before_event": before[1], "limit": limit}
    for attempt in (1, 2):
        try:
            response = request_private_intelligence(payload, endpoint="users")
            break
        except Exception as error:
            # A 4xx means the request itself was refused; retrying cannot change that.
            transient = not isinstance(error, PrivateIntelligenceError) or error.status >= 500
            logger.warning("Audit log read failed (%s)", type(error).__name__)
            if attempt == 2 or not transient:
                raise user_store.unavailable() from None
            time.sleep(READ_RETRY_DELAY_SECONDS)
    entries, following = response.get("entries"), response.get("next")
    if not isinstance(entries, list) or len(entries) > limit or not (
        following is None
        or (isinstance(following, dict) and set(following) == {"account", "event"}
            and all(_cursor_side(following[side]) for side in following))
    ):
        raise user_store.unavailable()
    return {"entries": [_entry(item) for item in entries], "next": format_cursor(following)}
