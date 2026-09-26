"""The Worker's fixed /v1/state operations held in memory, for control-state unit tests.

It follows worker/control-state-d1.mjs closely enough for the Container code to be tested
without a Worker; tests/test_control_state_worker.mjs covers the real statements.
"""

import time

from services import intelligence_d1_store
from services.intelligence_d1_store import PrivateIntelligenceError


class FakeControlState:
    def __init__(self, clock=time.time):
        self.clock = clock
        self.calls, self.payloads = [], []
        self.down = set()  # endpoints that answer 503
        self.lose_reply = False  # apply the operation, then time out as the transport would
        self.refuse = False  # answer 400, as the Worker does for an invalid request
        self.usage, self.flushes = {}, set()
        self.login, self.overrides, self.cooldowns = {}, {}, {}
        self.profiles, self.reports, self.catalog = [], [], {}

    def __call__(self, payload, *, endpoint):
        self.calls.append((endpoint, payload["operation"]))
        self.payloads.append((endpoint, payload))
        if endpoint in self.down:
            raise PrivateIntelligenceError(503, "storage_unavailable")
        if self.refuse:
            raise PrivateIntelligenceError(400, "invalid_request")
        result = getattr(self, "_" + endpoint)(payload)
        if self.lose_reply:
            raise intelligence_d1_store.storage_unavailable()
        return {"version": 1, **result}

    def count(self, endpoint, operation=None):
        return sum(1 for called, name in self.calls if called == endpoint and operation in (None, name))

    def _rate_limits(self, payload):
        now = self.clock()
        minute, hour = int(now // 60), int(now // 3600)
        if payload["flush_id"] is not None and payload["flush_id"] not in self.flushes:
            for item in payload["increments"]:
                for span, bucket in ((60, item["minute"]), (3600, item["minute"] // 60)):
                    row = self.usage.setdefault((item["identity"], item["provider"], span, bucket, payload["instance"]), [0, 0])
                    row[0] += item["requests"]
                    row[1] += item["tokens"]
            self.flushes.add(payload["flush_id"])
        usage = []
        for key in payload["read"]:
            figures = dict.fromkeys(("current_requests", "current_tokens", "previous_requests", "previous_tokens", "day_requests"), 0)
            for (identity, provider, span, bucket, instance), (requests, tokens) in self.usage.items():
                if (identity, provider) != (key["identity"], key["provider"]) or instance == payload["instance"]:
                    continue
                if span == 60 and bucket in (minute, minute - 1):
                    prefix = "current" if bucket == minute else "previous"
                    figures[prefix + "_requests"] += requests
                    figures[prefix + "_tokens"] += tokens
                elif span == 3600 and bucket > hour - 24:
                    figures["day_requests"] += requests
            usage.append({**key, **figures})
        return {"minute": minute, "usage": usage}

    def _login_attempts(self, payload):
        identity = payload["identity"]
        if payload["operation"] == "check":
            return {"state": dict(self.login[identity]) if identity in self.login else None}
        if payload["operation"] == "success":
            return {"deleted": self.login.pop(identity, None) is not None}
        now, row = payload["now"], self.login.get(identity)
        if row is None or (row["locked_until"] <= now and now - row["window_started"] >= payload["window_seconds"]):
            row = {"failures": 1, "window_started": now, "locked_until": 0}
        elif row["locked_until"] <= now:
            row = {**row, "failures": row["failures"] + 1}
        if row["locked_until"] <= now and row["failures"] >= payload["max_attempts"]:
            row["locked_until"] = now + payload["lockout_seconds"]
        self.login[identity] = row
        return {"state": dict(row)}

    def _model_overrides(self, payload):
        if payload["operation"] == "list":
            return {"overrides": [{"model_id": model_id, "status": status} for model_id, status in sorted(self.overrides.items())]}
        self.overrides[payload["model_id"]] = payload["status"]
        return {"stored": True}

    def _free_quotas(self, payload):
        if payload["operation"] == "list":
            now = self.clock()
            return {"cooldowns": [{"scope": scope, "blocked_until": until}
                                  for scope, until in self.cooldowns.items() if until > now]}
        for item in payload["cooldowns"]:
            self.cooldowns[item["scope"]] = max(self.cooldowns.get(item["scope"], 0), item["blocked_until"])
        return {"stored": len(payload["cooldowns"])}

    def _workbench(self, payload):
        operation, owner = payload["operation"], payload["owner"]
        records, limit, field, content = ((self.profiles, 50, "profiles", "settings") if "profile" in operation
                                          else (self.reports, 100, "reports", "data"))
        if operation in ("profiles", "reports"):
            rows = sorted((row for row in records if row["owner"] == owner), key=lambda row: -row["created_at"])
            return {field: [{"id": row["id"], "created_at": row["created_at"], content: row[content]} for row in rows[:limit]]}
        if sum(row["owner"] == owner for row in records) >= limit:
            raise PrivateIntelligenceError(409, "limit_reached")
        records.append({"owner": owner, "id": payload["id"], "created_at": payload["created_at"], content: payload[content]})
        return {"stored": True}

    def _provider_catalog(self, payload):
        if payload["operation"] == "list":
            return {"snapshots": [{"provider": provider, "updated_at": updated_at}
                                  for provider, (updated_at, _) in sorted(self.catalog.items())]}
        if payload["operation"] == "get":
            stored = self.catalog.get(payload["provider"])
            return {"snapshot": None if stored is None else
                    {"provider": payload["provider"], "updated_at": stored[0], "data": stored[1]}}
        self.catalog[payload["provider"]] = (payload["updated_at"], payload["data"])
        return {"stored": True}
