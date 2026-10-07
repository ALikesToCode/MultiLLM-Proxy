"""Handoff tool contracts and REST ingress; storage validation belongs to the Worker."""
from flask import g, jsonify, request
from route_helpers import api_authenticate_only
from services.knowledge_client import KnowledgeError


def _text(maximum, *, required=False):
    return {"type": "string", "maxLength": maximum, **({"minLength": 1} if required else {})}


def _object(properties, required=()):
    return {"type": "object", "additionalProperties": False, "properties": properties, "required": list(required)}


SECTIONS = _object({
    "goal": _text(500), "state": _text(500),
    **{name: {"type": "array", "maxItems": count, "items": item} for name, count, item in (
        ("files", 100, _object({"path": _text(500), "change": _text(500)}, ("path", "change"))),
        ("commands", 30, _object({"command": _text(500), "outcome": _text(500)}, ("command", "outcome"))),
        ("decisions", 30, _text(500)), ("failed_attempts", 30, _text(500)),
        ("next_steps", 30, _text(500)), ("open_questions", 20, _text(500)),
    )},
})
_ID = {"type": "string", "pattern": "^[A-Za-z0-9_-]{1,80}$"}
PROJECT = {**_text(200, required=True),
           "description": "owner/name from the git origin URL (for example acme/widgets), otherwise the directory name"}
BRANCH = {**_text(200), "description": "current git branch (git branch --show-current)"}
CONTRACTS = {
    "save": _object({"project": PROJECT, "branch": BRANCH, "title": _text(200),
                     "summary": _text(4000), "sections": SECTIONS,
                     "source": _object({"agent": {"type": "string", "enum": ["claude", "codex", "opencode", "other"]},
                                        "thread_id": _text(200)}, ("agent",)),
                     "ttl_days": {"type": "integer", "minimum": 1, "maximum": 90, "default": 14}},
                    ("project", "title", "sections", "source")),
    "get": {**_object({"project": PROJECT, "branch": BRANCH, "id": _ID}),
            "anyOf": [{"required": ["project"]}, {"required": ["id"]}]},
    "list": _object({"project": PROJECT, "limit": {"type": "integer", "minimum": 1, "maximum": 20, "default": 20}}),
    "delete": _object({"id": _ID}, ("id",)),
}
DESCRIPTIONS = {
    "save": "Save an operator handoff for this principal; rejects secrets and records over 32 KB. Requires knowledge:read.",
    "get": "Load the newest unexpired project/branch handoff with project fallback, or by id (optional project must match). Requires knowledge:read.",
    "list": "List up to 20 unexpired handoffs belonging to this principal. Requires knowledge:read.",
    "delete": "Delete this principal’s handoff by id. Requires knowledge:read.",
}
TOOLS = [{"name": "knowledge_handoff_" + name, "description": DESCRIPTIONS[name], "inputSchema": schema,
          "annotations": {"readOnlyHint": name in {"get", "list"}, "openWorldHint": False,
                          **({"destructiveHint": True} if name == "delete" else {})}}
         for name, schema in CONTRACTS.items()]


def query_payload(args, allowed):
    result = {}
    for key, value in args.items(multi=True):
        if key not in allowed or key in result:
            raise KnowledgeError("invalid_request", "Unsupported or duplicate handoff query fields.", 400)
        if key == "limit":
            if not value.isascii() or not value.isdecimal() or len(value) > 2:
                raise KnowledgeError("invalid_request", "limit must be an integer from 1 to 20.", 400)
            value = int(value)
        result[key] = value
    return result


def register_handoff_routes(app, csrf, dispatch, body):
    def handle(identifier=None):
        if request.method == "POST":
            if request.args:
                raise KnowledgeError("invalid_request", "Save accepts no query fields.", 400)
            operation, payload = "save", body()
        else:
            if request.content_length or request.stream.read(1):
                raise KnowledgeError("invalid_request", "Use query parameters for handoff reads and deletes.", 400)
            operation = "delete" if request.method == "DELETE" else "get" if identifier is not None else "list"
            allowed = () if operation == "delete" else ("project", "branch") if operation == "get" else ("project", "limit")
            payload = query_payload(request.args, allowed)
            if identifier is not None and (identifier != "latest" or operation == "delete"):
                payload["id"] = identifier
        return jsonify(dispatch("handoffs." + operation, g.authenticated_user, payload))

    secured = csrf.exempt(api_authenticate_only(required_scope="knowledge:read")(handle))
    app.add_url_rule("/v1/knowledge/handoffs", "knowledge_handoffs", secured, methods=["GET", "POST", "OPTIONS"])
    app.add_url_rule("/v1/knowledge/handoffs/<identifier>", "knowledge_handoff", secured, methods=["GET", "DELETE", "OPTIONS"])
