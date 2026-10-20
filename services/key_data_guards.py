"""Provider eligibility and administrator-owned request preferences."""

import json
from copy import deepcopy
from pathlib import Path

from flask import current_app, g, has_app_context, has_request_context

from error_handlers import APIError

DATA_CLASSES = json.loads((Path(__file__).parent.parent / "providers/data-classes.json").read_text())
MAX_PREFERENCES_BYTES = 4096


def preferences(value):
    """Decode storage or API values, rejecting malformed policy rather than dropping it."""
    if value is None:
        return None
    try:
        parsed = json.loads(value) if isinstance(value, str) else value
        encoded = json.dumps(parsed, allow_nan=False)
        if not isinstance(parsed, dict) or len(encoded.encode()) > MAX_PREFERENCES_BYTES:
            raise ValueError()
        if parsed.get("data_collection", "deny") not in {"allow", "deny"}:
            raise ValueError()
        return parsed
    except (ValueError, TypeError, RecursionError):
        raise APIError("forced_provider_preferences must be a bounded JSON object", 400) from None


def validate_controls(payload):
    official = payload.get("official_only")
    if official is not None and type(official) is not bool:
        raise APIError("official_only must be a boolean", 400)
    raw = payload.get("forced_provider_preferences")
    if raw is not None and not isinstance(raw, dict):
        raise APIError("forced_provider_preferences must be a JSON object", 400)
    forced = preferences(raw)
    return {"official_only": int(official) if official is not None else None,
            "forced_provider_preferences": json.dumps(forced, separators=(",", ":")) if forced is not None else None}


def stored_controls(row):
    def value(name):
        try:
            return row[name]
        except (KeyError, IndexError, TypeError):
            raise APIError("Stored key data controls are incomplete", 503) from None
    official = value("official_only")
    if official is not None and (type(official) not in (bool, int) or official not in (0, 1)):
        raise APIError("Stored key data controls are invalid", 503)
    raw = value("forced_provider_preferences")
    try:
        forced = preferences(raw)
    except APIError:
        raise APIError("Stored key data controls are invalid", 503) from None
    return {"official_only": official,
            "forced_provider_preferences": json.dumps(forced, separators=(",", ":")) if forced is not None else None}


def provider_data_class(provider, config=None):
    config = config if config is not None else (current_app.config if has_app_context() else {})
    provider = str(provider).strip().lower()
    free = str(config.get("FREE_ROUTE_FREE_TIER_PROVIDERS", "")).replace(",", " ").split()
    if provider in free or provider == "free":
        return "free"
    if provider == "gemini":
        return "official" if config.get("GEMINI_DATA_TIER", "free") == "paid" else "free"
    return DATA_CLASSES.get(provider, "subscription" if provider.startswith("ce-") else "reseller")


def account_controls(user):
    """Resolve the canonical envelope, or validate an explicit stored row."""
    from services.dispatch_policy import verify, unavailable
    if not isinstance(user, dict):
        raise unavailable()
    if "data_policy" in user:
        return verify(user["data_policy"])
    if "version" in user:
        return verify(user)
    return stored_controls(user)


def has_data_controls(user):
    """Any stored non-NULL value represents an administrator-owned data policy."""
    from services.key_controls_capability import policy_present
    policy = account_controls(user) if "data_policy" in user or "version" in user else user
    return policy_present(policy)


def allows_shadow_sampling(user):
    """Unverifiable authority cannot authorize retaining request content."""
    try:
        return not has_data_controls(account_controls(user))
    except APIError:
        return False


def model_permitted(user, model, config=None):
    from services.key_controls_capability import expansion_fence
    policy = account_controls(user) if "data_policy" in user else user
    expansion_fence(policy)
    if policy.get("official_only") not in (1, True):
        return True
    provider = str(model or "").split(":", 1)[0].lower()
    if provider in {"auto", "cascade", "intelligence"}:
        return True  # Each concrete candidate is checked before dispatch.
    return provider_data_class(provider, config) == "official"


def eligible_models(models, user):
    """Filter route candidates and refuse before dispatch if none remain."""
    eligible = [model for model in models if model_permitted(user, model)]
    if not eligible:
        raise APIError("No eligible provider data class remains", 403, {"error": "provider_class_not_allowed"})
    return eligible


def require_provider(provider, user=None):
    user = user if user is not None else (getattr(g, "authenticated_user", None) or {} if has_request_context() else {})
    if not model_permitted(user, provider + ":*"):
        raise APIError("This API key cannot use this provider data class", 403,
                       {"error": "provider_class_not_allowed"})
    from services.gemini_credentials import reject_caller_credentials
    reject_caller_credentials(provider)


def merge_preferences(caller, forced):
    result = deepcopy(caller) if isinstance(caller, dict) else {}
    for name, value in forced.items():
        if name == "data_collection" and result.get(name) == "deny":
            continue
        result[name] = merge_preferences(result.get(name), value) if isinstance(value, dict) else deepcopy(value)
    return result


def guard_request(provider, data):
    """Final transport boundary covers raw, unified, routed and internal requests."""
    require_provider(provider)
    user = getattr(g, "authenticated_user", None) or {} if has_request_context() else {}
    policy = account_controls(user) if "data_policy" in user else user
    forced = preferences(policy.get("forced_provider_preferences"))
    if provider != "openrouter" or forced is None or data is None:
        return data
    try:
        payload = json.loads(data)
        if not isinstance(payload, dict):
            raise ValueError()
    except (ValueError, TypeError):
        raise APIError("A JSON object is required for enforced provider preferences", 400) from None
    payload["provider"] = merge_preferences(payload.get("provider"), forced)
    return json.dumps(payload).encode()
