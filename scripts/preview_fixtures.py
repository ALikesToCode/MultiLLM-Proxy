"""Synthetic fixtures for `preview_ui.py`. The application never imports this module.

Every value here is invented for interface review. Provider boundaries are
replaced in-process so journeys can be exercised without network or billing.
"""

from __future__ import annotations

import json
import random
import time
import uuid
from datetime import datetime, timedelta, timezone

from markupsafe import Markup

SEED = 20260923
BADGE = Markup(
    '<p style="position:fixed;left:.75rem;bottom:.75rem;z-index:90;margin:0;padding:.3rem .55rem;'
    'border-radius:999px;background:#07131f;color:#fff;font:600 11px/1.4 ui-monospace,monospace;'
    'letter-spacing:.04em;pointer-events:none;opacity:.86">UI preview · synthetic data</p>'
)


def _iso(seconds_ago: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)).isoformat()


def install(app, *, knowledge_mode: str, badge: bool) -> None:
    seed_accounts()
    seed_traffic()
    install_knowledge(knowledge_mode)
    install_workbench()
    install_openrouter()
    if badge:
        @app.after_request
        def preview_badge(response):
            if response.mimetype == "text/html" and not response.direct_passthrough:
                body = response.get_data(as_text=True)
                response.set_data(body.replace("</body>", f"{BADGE}</body>", 1))
            return response


def seed_accounts() -> None:
    from services.auth_primitives import default_scopes
    from services.auth_service import AuthService

    now = datetime.now(timezone.utc)
    for username, is_admin, scopes, last_login in (
        ("release-bot", True, default_scopes(True), now - timedelta(hours=3)),
        ("support-desk", False, ("chat", "models"), now - timedelta(days=2)),
        ("docs-agent", False, ("knowledge:read",), None),
        ("knowledge-curator", False, ("knowledge:manage", "knowledge:read"), now - timedelta(minutes=40)),
    ):
        AuthService._persist_user_with_api_key(
            username=username, api_key=AuthService._generate_api_key(), is_admin=is_admin,
            created_at=now - timedelta(days=12), last_login=last_login, scopes=scopes,
            created_by="admin",
        )


TRAFFIC = {
    "openrouter": (("openai/gpt-4.1-mini", "anthropic/claude-sonnet-4"), (380, 1900), 0.03, 0.00042),
    "nanogpt": (("glm-5.2", "kimi-k3"), (650, 2800), 0.07, None),
    "opencode": (("glm-5.3-flash",), (280, 1300), 0.02, 0.00018),
    "groq": (("llama-3.3-70b-versatile",), (110, 640), 0.16, None),
}


def seed_traffic() -> None:
    from services.metrics_service import MetricsService
    from services.resilience_service import ResilienceService

    metrics = MetricsService.get_instance()
    rng = random.Random(SEED)
    now = time.time()
    for hour in range(24):
        volume = int(14 + 10 * abs(12 - hour) / 12 + rng.randint(0, 6))
        for _ in range(volume):
            provider = rng.choice(list(TRAFFIC))
            models, (fast, slow), error_rate, unit_cost = TRAFFIC[provider]
            failed = rng.random() < error_rate
            status = rng.choice((429, 502, 401, 500)) if failed else 200
            auto = provider in {"nanogpt", "opencode"} and rng.random() < 0.4
            metrics.track_request(
                provider=provider, status_code=status, response_time=rng.uniform(fast, slow),
                timestamp=now - hour * 3600 - rng.uniform(0, 3500),
                request_id=f"req_{uuid.UUID(int=rng.getrandbits(128)).hex[:20]}",
                user_id=rng.choice(("support-desk", "release-bot", "admin")),
                api_key_prefix="mllm_prev", model=rng.choice(models),
                estimated_cost=round(unit_cost * rng.uniform(0.6, 3.2), 6) if unit_cost and not failed else None,
                endpoint="/v1/chat/completions",
                circuit_state="closed" if status < 500 else "degraded",
                route_decision=f"auto:glm-5.2 → {provider}" if auto else "explicit provider:model",
            )
    for _ in range(6):
        ResilienceService.record_result("groq", 503)


PROVIDERS = (
    ("context7", "Context7", "CONTEXT7_API_KEY", ["library_context"], "discovery", 1),
    ("firecrawl", "Firecrawl", "FIRECRAWL_API_KEY", ["source_acquisition"], "source_excerpt", 2),
    ("exa", "Exa", "EXA_API_KEY", ["search", "source_acquisition"], "source_excerpt", 0),
    ("mintlify", "Mintlify Index", None, ["context"], "derived_context", 0),
    ("deepwiki", "DeepWiki", None, ["repository_context"], "derived_context", 0),
    ("alexandria", "Firecrawl Alexandria", "FIRECRAWL_API_KEY", ["capability_discovery", "structured_data"], "catalogue", 2),
    ("ai_search", "Cloudflare AI Search + storage", None, ["index", "storage"], "corpus", 0),
)
TOOLS = (
    {"name": "Podcast episode transcripts", "provider": "preview-media", "capability": "episodes",
     "description": "Synthetic catalogue entry: episode metadata and transcript excerpts by topic.",
     "whenToUse": "Find spoken discussion about a topic with timestamps.", "creditsCost": 3, "perRecord": True},
    {"name": "Company filings summary", "provider": "preview-finance", "capability": "filings",
     "description": "Synthetic catalogue entry: structured summaries of public filings.",
     "whenToUse": "Retrieve a fixed-price structured summary for one company.", "creditsCost": 15, "perRecord": False},
)


class KnowledgeFixture:
    """In-memory Knowledge service with the private Worker's response shapes."""

    def __init__(self):
        providers = {pid: {"enabled": pid != "exa", "limit": 500 if pid == "alexandria" else 200,
                           "background_limit": 80, "interactive_reserve": 40, "units_per_call": 1,
                           "hard_limit_confirmed": pid != "exa", "retention_allowed": pid in {"firecrawl", "ai_search"}}
                     for pid, *_ in PROVIDERS}
        self.policy = {"revision": 7, "enabled": True, "cache_ttl_seconds": 300, "retention_hours": 168,
                       "allowed_hosts": ["flask.palletsprojects.com", "developers.cloudflare.com", "docs.python.org"],
                       "providers": providers}
        self.sources = [
            {"id": "src_flask", "product": "flask", "version": "3.1.3", "provider": "firecrawl",
             "url": "https://flask.palletsprojects.com/en/stable/", "enabled": True, "pinned": True,
             "refresh_hours": 24, "revision": 4, "last_checked_at": _iso(5400), "current_artifact": "art_flask_0923"},
            {"id": "src_workers", "product": "cloudflare-workers", "version": None, "provider": "firecrawl",
             "url": "https://developers.cloudflare.com/workers/", "enabled": True, "pinned": False,
             "refresh_hours": 72, "revision": 2, "last_checked_at": _iso(900), "current_artifact": None},
            {"id": "src_python", "product": "python", "version": "3.13", "provider": "exa",
             "url": "https://docs.python.org/3.13/", "enabled": False, "pinned": False,
             "refresh_hours": 168, "revision": 1, "last_checked_at": None, "current_artifact": None},
        ]
        self.jobs = [
            {"id": "job_workers_3", "source_id": "src_workers", "status": "pending_index",
             "reason": "Snapshot uploaded; waiting for AI Search to finish indexing.", "updated_at": _iso(600)},
            {"id": "job_flask_7", "source_id": "src_flask", "status": "completed", "reason": None,
             "artifact_id": "art_flask_0923", "updated_at": _iso(5400)},
            {"id": "job_python_1", "source_id": "src_python", "status": "failed",
             "reason": "The Exa credential is not configured.", "updated_at": _iso(86000)},
        ]
        self.receipts = {}

    def status(self):
        setup = [
            {"id": "catalogue", "label": "Durable catalogue and allowances", "configured": True, "detail": "SQLite-backed Durable Object binding"},
            {"id": "snapshots", "label": "Immutable source snapshots", "configured": True, "detail": "Private R2 bucket with a reviewed lifecycle policy"},
            {"id": "index", "label": "Search index", "configured": True, "detail": "AI Search instance with built-in storage and hybrid indexing"},
            {"id": "ingestion", "label": "Background indexing", "configured": True, "detail": "Durable ingestion Workflow"},
        ]
        providers = [{"id": pid, "label": label, "credential_env": env, "capabilities": caps, "kind": kind,
                      "configured": env is None or keys > 0, "configured_key_count": keys,
                      "enabled": self.policy["providers"][pid]["enabled"], "connectivity": "not_checked"}
                     for pid, label, env, caps, kind, keys in PROVIDERS]
        usage = [
            {"provider": "context7", "confirmed": 12, "pending": 0, "unknown": 0, "background": 0, "total": 12, "limit": 200},
            {"provider": "firecrawl", "confirmed": 34, "pending": 2, "unknown": 1, "background": 20, "total": 37, "limit": 200},
            {"provider": "alexandria", "confirmed": 45, "pending": 0, "unknown": 15, "background": 0, "total": 60, "limit": 500},
        ]
        return {"enabled": self.policy["enabled"], "ready": True, "setup": setup, "providers": providers,
                "policy": self.policy, "sources": self.sources, "jobs": self.jobs, "usage": usage}

    def context(self, payload):
        return {"status": "partial", "path": "corpus", "elapsed_ms": 1840, "token_count": 1210,
                "token_counting_method": "estimate", "providers_used": ["ai_search", "context7"],
                "gaps": [{"code": "version_unverified", "message": f"No retained evidence proves version {payload.get('version') or 'unspecified'}; related versions are listed separately."}],
                "excerpts": [{"title": "Configuration handling · MAX_CONTENT_LENGTH (synthetic excerpt)",
                              "url": "https://flask.palletsprojects.com/en/stable/config/",
                              "text": "MAX_CONTENT_LENGTH caps how many bytes of an incoming request body are read. Larger bodies are rejected with 413 Request Entity Too Large.",
                              "artifact_id": "art_flask_0923", "target_match": "exact",
                              "version": {"kind": "exact", "version": "3.1.3", "proof_url": "https://flask.palletsprojects.com/en/stable/changes/"},
                              "locator": {"start_byte": 18234, "end_byte": 18402}}],
                "related_evidence": [{"title": "Request limits in 3.0 (synthetic excerpt)", "url": "https://flask.palletsprojects.com/en/3.0.x/config/",
                                      "text": "Earlier releases documented the same limit without per-request overrides.",
                                      "version": {"kind": "exact", "version": "3.0.3"}}],
                "freshness": {"checked_at": _iso(5400), "stale": False},
                "usage": [{"provider": "context7", "state": "confirmed", "units": 1}]}

    def alexandria(self, operation, payload):
        if operation == "alexandria.search":
            expires = _iso(-900)
            tools = [{**tool, "quote_id": f"quote_{index}", "expires_at": expires} for index, tool in enumerate(TOOLS)]
            return {"tools": tools, "cost": {"state": "confirmed", "credits": 0}}
        if operation == "alexandria.inspect":
            return {"details": {"input": {"type": "object", "properties": {"topic": {"type": "string"}, "limit": {"type": "integer", "maximum": 25}}},
                                "output": {"type": "array", "items": {"title": "string", "published_at": "date"}}},
                    "cost": {"state": "confirmed", "credits": 0}}
        request_id = payload.get("request_id", "")
        if operation == "alexandria.execute":
            tool = TOOLS[int(str(payload.get("quote_id", "quote_0")).rsplit("_", 1)[-1])]
            credits = tool["creditsCost"] * (6 if tool["perRecord"] else 1)
            self.receipts[request_id] = credits
            if tool["perRecord"]:
                return {"request_id": request_id, "cost": {"state": "pending", "credits": None},
                        "records": [{"title": "Synthetic episode", "published_at": "2026-09-01"}]}
            return {"request_id": request_id, "cost": {"state": "confirmed", "credits": credits},
                    "records": [{"company": "Synthetic Holdings", "period": "2026-Q2"}]}
        credits = self.receipts.get(request_id)
        return {"request_id": request_id, "call_cost": {"credits": 0},
                "cost": {"state": "confirmed", "credits": credits} if credits is not None else {"state": "unknown", "credits": None}}

    def dispatch(self, operation, user, payload=None):
        payload = payload or {}
        if operation == "status":
            return self.status()
        if operation in {"context", "search"}:
            return self.context(payload)
        if operation.startswith("alexandria."):
            return self.alexandria(operation, payload)
        if operation == "sources.create":
            source = {"id": f"src_{len(self.sources) + 1}", "enabled": True, "revision": 1, "last_checked_at": None,
                      "current_artifact": None, "version": None, **payload}
            self.sources.append(source)
            return {"source": source}
        if operation == "policy.update":
            self.policy = {**self.policy, **{key: value for key, value in payload.items() if key != "expected_revision"},
                           "revision": self.policy["revision"] + 1}
            return {"policy": self.policy}
        if operation == "sources.refresh":
            job = {"id": f"job_{len(self.jobs) + 1}", "source_id": payload.get("id"), "status": "queued",
                   "reason": "Waiting for the ingestion Workflow.", "updated_at": _iso(0)}
            self.jobs.insert(0, job)
            return {"job": job}
        return {"ok": True}


def install_knowledge(mode: str) -> None:
    import routes.knowledge as knowledge_routes
    from services.knowledge_client import KnowledgeError, setup_status

    fixture = KnowledgeFixture()

    def dispatch(operation, user, payload=None):
        if mode == "setup":
            if operation == "status":
                return setup_status()
            raise KnowledgeError("setup_needed", "The private Knowledge service has not been connected.")
        if mode == "unavailable":
            raise KnowledgeError("knowledge_unavailable", "The Knowledge service is unavailable. No automatic retry was started.")
        return fixture.dispatch(operation, user, payload)

    knowledge_routes.dispatch = dispatch


def install_workbench() -> None:
    import routes.workbench as workbench_routes

    original = workbench_routes.worker_json
    catalog = {"models": [
        {"provider": "nanogpt", "model": "glm-5.2", "billing_mode": "subscription"},
        {"provider": "opencode", "model": "glm-5.3-flash", "billing_mode": "configured"},
        {"provider": "openrouter", "model": "z-ai/glm-5.3-flash", "billing_mode": "configured"},
        {"provider": "navyai", "model": "kimi-k3", "billing_mode": "configured"},
    ]}

    def worker_json(path, **kwargs):
        return catalog if path == "/v1/roleplay/models" else original(path, **kwargs)

    workbench_routes.worker_json = worker_json


class _SyntheticUpstream:
    """The subset of `requests.Response` used by the dashboard relay helpers."""

    def __init__(self, body, *, content_type="application/json", chunks=None):
        self.status_code, self.ok, self.content = 200, True, body
        self.headers = {"Content-Type": content_type}
        self.raw = object() if chunks else None
        self._chunks = chunks or []

    def iter_content(self, chunk_size=None):
        for chunk in self._chunks:
            time.sleep(0.12)
            yield chunk

    def close(self):
        return None


def install_openrouter() -> None:
    from services.proxy_service import ProxyService

    original = ProxyService.make_request.__func__

    def make_request(cls, method, url, *args, **kwargs):
        if url == "https://openrouter.ai/api/v1/key":
            return _SyntheticUpstream(json.dumps({"data": {"usage": 3.42, "limit": 25, "limit_remaining": 21.58}}).encode())
        if url == "https://openrouter.ai/api/v1/chat/completions":
            words = "This is a synthetic streamed reply from the UI preview. No provider was called.".split()
            events = [f"data: {json.dumps({'choices': [{'delta': {'content': word + ' '}}]})}\n\n".encode() for word in words]
            events.append(b'data: {"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":12,"completion_tokens":15,"total_tokens":27}}\n\n')
            events.append(b"data: [DONE]\n\n")
            payload = json.loads(kwargs.get("data") or b"{}")
            if payload.get("stream"):
                return _SyntheticUpstream(b"", content_type="text/event-stream", chunks=events)
            reply = {"choices": [{"message": {"content": " ".join(words)}}], "usage": {"prompt_tokens": 12, "completion_tokens": 15, "total_tokens": 27}}
            return _SyntheticUpstream(json.dumps(reply).encode())
        return original(cls, method, url, *args, **kwargs)

    ProxyService.make_request = classmethod(make_request)
