"""Skills tool contracts and strict REST query parsing."""

from services.knowledge_client import KnowledgeError

ROOTS = ["claude", "claude-library", "codex", "agents"]
_ID = {"type": "string", "maxLength": 100, "pattern": "^[a-z0-9]+(?:-[a-z0-9]+)*$"}
_PATH = {"type": "string", "minLength": 1, "maxLength": 240}
_FILE = {"type": "object", "additionalProperties": False, "required": ["path", "sha256"],
         "properties": {"path": _PATH, "sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
                        "content": {"type": "string", "maxLength": 262144},
                        "content_base64": {"type": "string", "maxLength": 349528}},
         "oneOf": [{"required": ["content"]}, {"required": ["content_base64"]}]}
_SKILL = {"type": "object", "additionalProperties": False,
          "required": ["root", "skill_id", "name", "description", "files"],
          "properties": {"root": {"type": "string", "enum": ROOTS}, "skill_id": _ID,
                         "name": {"type": "string", "minLength": 1, "maxLength": 100},
                         "description": {"type": "string", "minLength": 1, "maxLength": 2000},
                         "files": {"type": "array", "minItems": 1, "maxItems": 40, "items": _FILE}}}


def _tool(action, description, properties, required):
    return {"name": "knowledge_skills_" + action, "description": description,
            "inputSchema": {"type": "object", "additionalProperties": False,
                            "properties": properties, "required": required},
            "annotations": {"readOnlyHint": action != "sync", "openWorldHint": False}}


TOOLS = [
    _tool("find", "Find relevant operator skills. Requires knowledge:read.", {
        "query": {"type": "string", "minLength": 1, "maxLength": 2000},
        "limit": {"type": "integer", "minimum": 1, "maximum": 5, "default": 3},
        "mode": {"type": "string", "enum": ["fast", "hybrid"], "default": "hybrid"},
        "min_confidence": {"type": "string", "enum": ["high"]},
        "roots": {"type": "array", "minItems": 1, "maxItems": 4, "uniqueItems": True,
                  "items": {"type": "string", "enum": ROOTS}}}, ["query"]),
    _tool("get", "Load operator skill instructions or a referenced file. Requires knowledge:read.",
          {"skill_id": _ID, "path": _PATH}, ["skill_id"]),
    _tool("sync", "Sync operator skills; reject secrets per skill. Requires knowledge:manage.", {
        "skills": {"type": "array", "maxItems": 16, "items": _SKILL},
        "delete": {"type": "array", "maxItems": 2000, "uniqueItems": True, "items": _ID},
        "dry_run": {"type": "boolean"}}, ["skills"]),
]
OPERATIONS = {tool["name"]: "skills." + tool["name"].removeprefix("knowledge_skills_") for tool in TOOLS}


def query(args, skill_id=None):
    payload = {}
    allowed = {"path"} if skill_id is not None else {"query", "limit", "mode", "roots", "min_confidence"}
    for key, value in args.items(multi=True):
        if key not in allowed or key in payload:
            raise KnowledgeError("invalid_request", "Unsupported or duplicate skills query fields.", 400)
        if key == "limit":
            if not value.isascii() or not value.isdecimal():
                raise KnowledgeError("invalid_request", "limit must be an integer.", 400)
            value = int(value)
        elif key == "roots":
            value = value.split(",")
        payload[key] = value
    if skill_id is not None:
        payload["skill_id"] = skill_id
    return payload
