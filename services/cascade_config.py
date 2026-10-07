"""Bounded, transport-independent configuration for verification-gated routes."""

import math
import re

PREFIX = "cascade:"
MAX_CASCADES = 200
CHECK_ORDER = ("complete", "json", "tools", "no_refusal", "agreement", "judge")
NAME = re.compile(r"cascade:[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,255}\Z")
DEFAULT_CASCADES = {}  # Operators choose their own cost order; no paid defaults.


def is_cascade(model):
    return isinstance(model, str) and model.startswith(PREFIX)


def model_id(value, *, auxiliary=False):
    if not isinstance(value, str) or not MODEL.fullmatch(value) or ":" not in value:
        raise ValueError("Cascade models must use provider:model or auto:<name>")
    provider, name = value.split(":", 1)
    if not name or provider == "cascade" or (provider == "free" and not auxiliary):
        raise ValueError("Cascade tiers cannot contain cascades or free pools")
    if provider == "auto" and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", name):
        raise ValueError("Invalid automatic route name")
    return value


def normalize_config(value):
    if not isinstance(value, dict) or set(value) - {"name", "tiers", "checks", "judge", "agreement", "updated_at"}:
        raise ValueError("Invalid cascade configuration fields")
    name = value.get("name")
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise ValueError("Cascade name must use cascade:<name> with letters, numbers, dots, underscores, or hyphens")
    tiers = value.get("tiers")
    if not isinstance(tiers, list) or not 2 <= len(tiers) <= 4:
        raise ValueError("Cascade requires 2 to 4 tiers")
    result = {"name": name, "tiers": [], "checks": []}
    for tier in tiers:
        if not isinstance(tier, dict) or set(tier) - {"model", "max_output_tokens"}:
            raise ValueError("Invalid cascade tier fields")
        clean = {"model": model_id(tier.get("model"))}
        if "max_output_tokens" in tier:
            limit = tier["max_output_tokens"]
            if type(limit) is not int or not 1 <= limit <= 1048576:
                raise ValueError("max_output_tokens must be an integer from 1 to 1048576")
            clean["max_output_tokens"] = limit
        result["tiers"].append(clean)
    checks = value.get("checks")
    if (not isinstance(checks, list) or len(checks) > len(CHECK_ORDER)
            or any(not isinstance(check, str) or check not in CHECK_ORDER for check in checks)
            or len(set(checks)) != len(checks)):
        raise ValueError("Invalid or duplicate cascade checks")
    result["checks"] = [check for check in CHECK_ORDER if check in checks]
    for field in ("judge", "agreement"):
        if field not in value:
            continue
        options = value[field]
        allowed = {"model", "min_score"} if field == "judge" else {"model"}
        if not isinstance(options, dict) or set(options) - allowed:
            raise ValueError(f"Invalid {field} configuration")
        clean = {}
        if "model" in options or field == "judge":
            clean["model"] = model_id(options.get("model"), auxiliary=True)
        if field == "judge":
            score = options.get("min_score", 7)
            if type(score) not in (int, float) or not math.isfinite(score) or not 0 <= score <= 10:
                raise ValueError("Judge min_score must be from 0 to 10")
            clean["min_score"] = score
        result[field] = clean
    if "judge" in checks and "judge" not in result:
        raise ValueError("The judge check requires a judge model")
    if "updated_at" in value:
        timestamp = value["updated_at"]
        if not isinstance(timestamp, str) or not re.fullmatch(r"[0-9T:.+\-Z]{10,40}", timestamp):
            raise ValueError("Invalid cascade timestamp")
        result["updated_at"] = timestamp
    return result
