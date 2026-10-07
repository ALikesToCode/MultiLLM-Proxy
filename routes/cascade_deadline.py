"""Cascade request limits shared by concrete and routed dispatch paths."""

import time

from flask import g

from error_handlers import APIError
from services import key_controls


def bounded_timeout(timeout):
    deadline = getattr(g, "cascade_deadline", None)
    if deadline is None:
        return timeout
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise APIError("Cascade request deadline exceeded", 504)
    return (min(5, remaining / 2), remaining / 2)


def check_candidate(model):
    if getattr(g, "cascade_deadline", None) is not None:
        bounded_timeout(None)
        if not key_controls.model_allowed(getattr(g, "authenticated_user", {}) or {}, model):
            raise APIError("This API key is not allowed to use the cascade candidate", 403,
                           {"error": "model_not_allowed"})
