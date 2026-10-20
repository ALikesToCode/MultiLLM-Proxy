"""Versioned, explicit data policy carried by verified account records."""

from error_handlers import APIError
from services.key_data_guards import stored_controls

VERSION = 1
FIELDS = frozenset({"version", "official_only", "forced_provider_preferences"})


def unavailable():
    return APIError("Current key data controls could not be verified", 503,
                    {"error": "key_data_controls_unavailable"})


def envelope(row):
    controls = stored_controls(row)
    return {"version": VERSION, **controls}


def verify(value):
    if not isinstance(value, dict) or set(value) != FIELDS or type(value.get("version")) is not int or value["version"] != VERSION:
        raise unavailable()
    return envelope(value)
