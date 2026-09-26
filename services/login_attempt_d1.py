"""Login throttling shared through D1, with this Container's own record as a floor.

Every sign-in attempt is recorded in the local store (SQLite or PostgreSQL) and, when
the Worker provides D1, in the shared control_login_attempts table through one atomic
Worker statement, so failures made against any instance count toward the same lockout
and survive Container restarts. A decision uses the stricter of the two records. If D1
cannot be reached, the local record still throttles and a warning is logged: an outage
never switches throttling off and never blocks sign-in on its own.
"""

import logging

from services import control_state_d1

logger = logging.getLogger(__name__)

ENDPOINT = "login_attempts"
_STATE_FIELDS = {"failures", "window_started", "locked_until"}


def using_d1():
    return control_state_d1.using_d1()


def _number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _locked_until(response, field):
    if not isinstance(response, dict) or set(response) != {"version", field}:
        raise ValueError("Invalid login throttling response")
    state = response[field]
    if state is None:
        return 0.0
    if (not isinstance(state, dict) or set(state) != _STATE_FIELDS or type(state["failures"]) is not int
            or not all(_number(state[name]) for name in ("window_started", "locked_until"))):
        raise ValueError("Invalid login throttling state")
    return float(state["locked_until"])


def _shared(operation, **values):
    """When the shared lock ends (0 when there is none), or None if D1 cannot be used."""
    try:
        return _locked_until(control_state_d1.call(ENDPOINT, operation, **values), "state")
    except Exception as error:
        logger.warning("Login throttling could not use D1 for %s (%s); this Container's record still applies",
                       operation, control_state_d1.cause(error))
        return None


def locked_until(identity_hash):
    return _shared("check", identity=identity_hash)


def record_failure(identity_hash, now, *, max_attempts, window_seconds, lockout_seconds, retention_seconds):
    """Count a failure atomically in D1 and return the resulting lock end, or None if D1 cannot be used."""
    return _shared("failure", identity=identity_hash, now=now, max_attempts=max_attempts, window_seconds=window_seconds,
                   lockout_seconds=lockout_seconds, retention_seconds=retention_seconds)


def record_success(identity_hash):
    try:
        response = control_state_d1.call(ENDPOINT, "success", identity=identity_hash)
        if not isinstance(response, dict) or set(response) != {"version", "deleted"}:
            raise ValueError("Invalid login throttling response")
    except Exception as error:
        # The shared record then expires with its window instead.
        logger.warning("Login throttling could not clear the D1 record (%s)", control_state_d1.cause(error))
