"""Route health rows and the public status snapshot in the Worker's D1 database.

Reached only through the private outbound handler, like services.auto_route_d1. Callers are
the background writer and the scheduled health checks, never the request path.
"""

import re

from services import intelligence_d1_store

MAX_ROWS_PER_PUT = 64
_TARGET = re.compile(r"(?:provider:[a-z0-9][a-z0-9._-]{0,63}|[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,255})\Z")
_TIMESTAMP = re.compile(r"[0-9T:.+\-Z]{10,40}\Z")


def using_d1():
    return intelligence_d1_store.using_d1()


def _call(payload):
    return intelligence_d1_store.request_private_intelligence(payload, endpoint="route_health")


def list_rows():
    """Every stored row as {target, state, updated_at}; raises when D1 cannot be read."""
    response = _call({"operation": "list"})
    if not isinstance(response, dict) or set(response) != {"version", "rows"} or not isinstance(response["rows"], list):
        raise ValueError("Invalid route health response")
    rows = []
    for row in response["rows"]:
        if (isinstance(row, dict) and set(row) == {"target", "state", "updated_at"}
                and isinstance(row["target"], str) and _TARGET.fullmatch(row["target"])
                and isinstance(row["state"], dict) and isinstance(row["updated_at"], str)):
            rows.append(row)
    return rows


def put_rows(rows):
    """Store up to MAX_ROWS_PER_PUT rows; an older row never replaces a newer one."""
    body = [{"target": row["target"], "state": row["state"], "updated_at": row["updated_at"]}
            for row in rows[:MAX_ROWS_PER_PUT]
            if _TARGET.fullmatch(row["target"]) and _TIMESTAMP.fullmatch(row["updated_at"])]
    if not body:
        return
    response = _call({"operation": "put", "rows": body})
    if response != {"version": 1, "stored": len(body)}:
        raise ValueError("Route health rows were not stored")


def put_snapshot(snapshot, updated_at):
    """Store the public status document the Worker serves while the Container sleeps."""
    response = _call({"operation": "snapshot", "body": snapshot, "updated_at": updated_at})
    if response != {"version": 1, "stored": True}:
        raise ValueError("Status snapshot was not stored")
