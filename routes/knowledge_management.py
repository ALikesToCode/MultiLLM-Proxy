"""MCP contracts for retained artifacts and scoped Knowledge administration."""

_ID = {"type": "string", "pattern": "^[A-Za-z0-9_-]{1,80}$"}
_REVISION = {"type": "integer", "minimum": 1, "maximum": 9007199254740990}
_BOOLEAN = {"type": "boolean"}
_ALLOCATION = {
    "type": "object", "additionalProperties": False,
    "required": ["enabled", "limit", "background_limit", "interactive_reserve",
                 "units_per_call", "hard_limit_confirmed", "retention_allowed"],
    "properties": {
        "enabled": _BOOLEAN, "hard_limit_confirmed": _BOOLEAN, "retention_allowed": _BOOLEAN,
        "limit": {"type": "integer", "minimum": 0, "maximum": 100000},
        "background_limit": {"type": "integer", "minimum": 0, "maximum": 100000},
        "interactive_reserve": {"type": "integer", "minimum": 0, "maximum": 100000},
        "units_per_call": {"type": "integer", "minimum": 1, "maximum": 100000},
    },
}
_PROVIDERS = ("context7", "firecrawl", "exa", "mintlify", "deepwiki", "ai_search", "alexandria")


def _tool(name, description, properties, required=(), *, read_only=False):
    return {
        "name": name, "description": description,
        "inputSchema": {"type": "object", "additionalProperties": False,
                        "properties": properties, "required": list(required)},
        "annotations": {"readOnlyHint": read_only, "openWorldHint": True},
    }


TOOLS = [
    _tool("knowledge_artifact", "Read a retained source snapshot and immutable citation manifest. Requires knowledge:read.",
          {"id": _ID}, ("id",), read_only=True),
    _tool("knowledge_status", "Inspect source, job, allowance and configuration status. Requires knowledge:manage; configuration is not a connectivity test.",
          {}, read_only=True),
    _tool("knowledge_source_register", "Register an approved public documentation URL without fetching it. Requires knowledge:manage.", {
        "url": {"type": "string", "maxLength": 2048},
        "title": {"type": "string", "maxLength": 200},
        "product": {"type": "string", "minLength": 1, "maxLength": 100},
        "version": {"type": "string", "maxLength": 80},
        "provider": {"type": "string", "enum": ["firecrawl", "exa"], "default": "firecrawl"},
        "refresh_hours": {"type": "integer", "minimum": 1, "maximum": 720, "default": 24},
        "pinned": _BOOLEAN,
    }, ("url", "product")),
    _tool("knowledge_source_update", "Enable, disable, pin or change a source refresh interval using its current revision. Requires knowledge:manage.", {
        "id": _ID, "expected_revision": _REVISION, "enabled": _BOOLEAN,
        "pinned": _BOOLEAN, "refresh_hours": {"type": "integer", "minimum": 1, "maximum": 720},
    }, ("id", "expected_revision")),
    _tool("knowledge_source_refresh", "Start or reconcile the source's durable indexing job. Can spend provider and platform allowances. Reuse the existing source after uncertainty. Requires knowledge:manage.",
          {"id": _ID}, ("id",)),
    _tool("knowledge_job_cancel", "Fence future job work. Accepted upstream work and charges may still complete. Requires knowledge:manage.",
          {"id": _ID}, ("id",)),
    _tool("knowledge_policy_update", "Save the complete allowance and retention policy with its current revision. Requires knowledge:manage. Obtain operator confirmation of billing controls and retention rights; never invent acknowledgements or raise limits to retry unknown work.", {
        "expected_revision": _REVISION, "enabled": _BOOLEAN,
        "cache_ttl_seconds": {"type": "integer", "minimum": 0, "maximum": 3600},
        "retention_hours": {"type": "integer", "minimum": 1, "maximum": 720},
        "unreviewed_retention_hours": {"type": "integer", "minimum": 1, "maximum": 720, "default": 24,
                                       "description": "Retention for discoveries from hosts that only * admits."},
        "allowed_hosts": {"type": "array", "minItems": 1, "maxItems": 100, "uniqueItems": True,
                          "items": {"type": "string"}},
        "providers": {"type": "object", "additionalProperties": False,
                      "required": list(_PROVIDERS),
                      "properties": {name: _ALLOCATION for name in _PROVIDERS}},
    }, ("expected_revision", "enabled", "cache_ttl_seconds", "retention_hours", "allowed_hosts", "providers")),
]

OPERATIONS = dict(zip((tool["name"] for tool in TOOLS), (
    "artifact", "status", "sources.create", "sources.update", "sources.refresh", "jobs.cancel", "policy.update",
)))


def required_scope(tool_name):
    return "knowledge:manage" if tool_name in OPERATIONS and tool_name != "knowledge_artifact" else "knowledge:read"


def permits(user, scope):
    scopes = user.get("scopes") or []
    return bool(user.get("is_admin") or "admin" in scopes or scope in scopes)
