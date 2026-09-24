"""Scoped Knowledge REST/MCP and session-authenticated operator routes."""

import json
import re
from urllib.parse import urlsplit

from flask import Response, g, jsonify, render_template, request

from route_helpers import api_authenticate_only, login_required
from routes import knowledge_alexandria as alexandria
from routes import knowledge_management as management
from routes import knowledge_mcp as mcp
from routes.knowledge_onboarding import register_knowledge_onboarding_routes
from routes.core import require_admin_dashboard_user
from services.knowledge_client import MAX_REQUEST_BYTES, KnowledgeError, dispatch

_IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,80}\Z")
_CATALOGUE = mcp.catalogue()
_TOOLS = {entry["definition"]["name"]: entry for entry in _CATALOGUE["tools"]}


def _error(code, message, status=400):
    return jsonify({"error": {"code": code, "message": message}}), status


def _strict_fields(pairs):
    fields = {}
    for key, value in pairs:
        if key in fields:
            raise ValueError("Duplicate field")
        fields[key] = value
    return fields


def _invalid_number(_value):
    raise ValueError("Invalid JSON number")


def _body():
    if not request.is_json:
        raise KnowledgeError("invalid_request", "Use an application/json request body.", 415)
    if request.content_length is not None and request.content_length > MAX_REQUEST_BYTES:
        raise KnowledgeError("request_too_large", "The Knowledge request exceeds 64 KiB.", 413)
    raw = request.stream.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise KnowledgeError("request_too_large", "The Knowledge request exceeds 64 KiB.", 413)
    try:
        payload = json.loads(raw, object_pairs_hook=_strict_fields, parse_constant=_invalid_number)
    except (ValueError, UnicodeDecodeError):
        raise KnowledgeError("invalid_json", "The request body is not valid JSON.", 400) from None
    if not isinstance(payload, dict):
        raise KnowledgeError("invalid_request", "The request body must be an object.", 400)
    return payload


def _query(payload):
    allowed = mcp.QUERY_SCHEMA["properties"]
    if any(key not in allowed for key in payload):
        raise KnowledgeError("invalid_request", "The query contains unsupported fields.", 400)
    query = payload.get("query")
    if not isinstance(query, str) or not 1 <= len(query.strip()) <= 500:
        raise KnowledgeError("invalid_query", "Provide a question of 1–500 characters.", 400)
    for field, maximum in (("product", 100), ("version", 80), ("repository", 200)):
        if field in payload and (not isinstance(payload[field], str) or len(payload[field]) > maximum):
            raise KnowledgeError("invalid_request", f"Invalid {field}.", 400)
    if any(re.search(r"[\x00-\x1f\x7f]", value) for key, value in payload.items()
           if key in {"query", "product", "version", "repository"}):
        raise KnowledgeError("invalid_request", "Query fields must not contain control characters.", 400)
    if payload.get("version") and not payload.get("product", "").strip():
        raise KnowledgeError("invalid_request", "A version requires a product.", 400)
    if payload.get("repository") and not re.fullmatch(r"[\w.-]+/[\w.-]+", payload["repository"]):
        raise KnowledgeError("invalid_request", "Repository must be owner/name.", 400)
    if payload.get("mode", "smart") not in ("economy", "smart", "deep"):
        raise KnowledgeError("invalid_mode", "Choose economy, smart, or deep mode.", 400)
    if payload.get("freshness", "normal") not in ("normal", "fresh"):
        raise KnowledgeError("invalid_freshness", "Choose normal or fresh evidence.", 400)
    budget = payload.get("token_budget", 6000)
    if type(budget) is not int or not 256 <= budget <= 16000:
        raise KnowledgeError("invalid_budget", "Token budget must be an integer from 256 to 16,000.", 400)
    return {**payload, "query": query.strip()}


def _identifier(value):
    if not _IDENTIFIER.fullmatch(value):
        raise KnowledgeError("invalid_identifier", "Invalid Knowledge identifier.", 400)
    return value


def _rpc_error(identifier, code, message, status=200):
    return jsonify({"jsonrpc": "2.0", "id": identifier,
                    "error": {"code": code, "message": message}}), status


def _rpc_result(identifier, result):
    return jsonify({"jsonrpc": "2.0", "id": identifier, "result": result})


def _valid_origin():
    origin = request.headers.get("Origin")
    if origin is None:
        return True
    try:
        supplied = urlsplit(origin)
        expected = urlsplit(request.host_url)
        return (supplied.scheme in {"http", "https"} and supplied.hostname
                and not supplied.username and not supplied.password
                and supplied.path in {"", "/"} and not supplied.query and not supplied.fragment
                and (supplied.scheme, supplied.hostname, supplied.port)
                == (expected.scheme, expected.hostname, expected.port))
    except ValueError:
        return False


def _mcp_initialize(identifier, params):
    # Clients differ in optional initialize fields; only the offered version is required.
    if (not isinstance(params.get("protocolVersion"), str)
            or not isinstance(params.get("capabilities", {}), dict)
            or not isinstance(params.get("clientInfo", {}), dict)):
        return _rpc_error(identifier, -32602, "Initialize requires a protocolVersion string.")
    versions = mcp.PROTOCOL_VERSIONS
    version = params["protocolVersion"] if params["protocolVersion"] in versions else versions[0]
    return _rpc_result(identifier, {"protocolVersion": version,
                       "capabilities": {"tools": {}},
                       "serverInfo": mcp.SERVER_INFO,
                       "instructions": mcp.INSTRUCTIONS})


def _mcp_tool(identifier, params, protocol):
    tool_name = params.get("name")
    entry = _TOOLS.get(tool_name) if isinstance(tool_name, str) else None
    if entry is None:
        return _rpc_error(identifier, -32602, "Unknown Knowledge tool.")
    operation = entry["operation"]
    if not management.permits(g.authenticated_user, entry["scope"]):
        return _rpc_result(identifier, {"isError": True, "content": [{"type": "text", "text": json.dumps({
            "error": {"code": "insufficient_scope", "message": "The key is not authorized for this Knowledge tool."},
        })}]})
    arguments = params.get("arguments", {})
    if not isinstance(arguments, dict):
        return _rpc_error(identifier, -32602, "Tool arguments must be an object.")
    try:
        if operation in alexandria.OPERATIONS:
            payload = alexandria.parse_request(operation, arguments)
        elif operation in mcp.NATIVE_OPERATIONS:
            # The Knowledge service validates provider tools against their shared contract.
            payload = arguments
        elif tool_name in management.OPERATIONS:
            # The private service validates management contracts identically for REST and MCP.
            payload = arguments
        else:
            payload = _query(arguments)
        result = dispatch(operation, g.authenticated_user, payload)
        tool_result = {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}], "isError": bool(result.get("error"))}
        if protocol == "2025-06-18":
            tool_result["structuredContent"] = result
        return _rpc_result(identifier, tool_result)
    except KnowledgeError as error:
        return _rpc_result(identifier, {"isError": True, "content": [{"type": "text",
                           "text": json.dumps({"error": {"code": error.code, "message": error.message}})}]})


def _mcp():
    if not _valid_origin():
        return _error("invalid_origin", "MCP requests must use the gateway origin.", 403)
    if request.method != "POST":
        return Response(status=405, headers={"Allow": "POST"})
    # Responses are always JSON, so a client that omits text/event-stream still works.
    if request.headers.get("Accept") and not request.accept_mimetypes["application/json"]:
        return _rpc_error(None, -32600, "Accept must include application/json.", 406)
    protocol = request.headers.get("MCP-Protocol-Version")
    if protocol is not None and protocol not in mcp.PROTOCOL_VERSIONS:
        return _rpc_error(None, -32600, "Unsupported MCP protocol version.", 400)
    try:
        body = _body()
    except KnowledgeError as error:
        return _rpc_error(None, -32700 if error.code == "invalid_json" else -32600,
                          error.message, error.status)
    identifier = body.get("id")
    method, params = body.get("method"), body.get("params", {})
    if (body.get("jsonrpc") != "2.0" or not isinstance(method, str)
            or not isinstance(params, dict)
            or "id" in body and (type(identifier) not in (str, int) or isinstance(identifier, str) and len(identifier) > 200)):
        return _rpc_error(None, -32600, "Invalid JSON-RPC request.", 400)
    if "id" not in body:
        if not method.startswith("notifications/"):
            return _rpc_error(None, -32600, "An MCP request requires an id.", 400)
        return Response(status=202)
    if method == "initialize":
        return _mcp_initialize(identifier, params)
    if method == "ping":
        return _rpc_result(identifier, {})
    if method == "tools/list":
        return _rpc_result(identifier, {"tools": [entry["definition"] for entry in _CATALOGUE["tools"]
            if management.permits(g.authenticated_user, entry["scope"])]})
    if method != "tools/call":
        return _rpc_error(identifier, -32601, "Method not found.")
    return _mcp_tool(identifier, params, protocol)


def register_knowledge_routes(app, csrf):
    register_knowledge_onboarding_routes(app)
    @app.after_request
    def private_knowledge_response(response):
        if request.path == "/mcp" or request.path.startswith(("/knowledge", "/v1/knowledge/", "/admin/knowledge/")):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(KnowledgeError)
    def knowledge_error(error):
        return _error(error.code, error.message, error.status)

    def query_api(operation):
        def handle():
            body = _body()
            payload = alexandria.parse_request(operation, body) if operation in alexandria.OPERATIONS else _query(body)
            return jsonify(dispatch(operation, g.authenticated_user, payload))
        handle.__name__ = "knowledge_" + operation.replace(".", "_")
        return csrf.exempt(api_authenticate_only(required_scope="knowledge:read")(handle))

    for operation in ("context", "search", *alexandria.OPERATIONS):
        app.add_url_rule("/v1/knowledge/" + operation.replace(".", "/"), "knowledge_" + operation.replace(".", "_"),
                         query_api(operation), methods=["POST", "OPTIONS"])

    def native_api(tool):
        operation = "native." + tool
        if operation not in mcp.NATIVE_OPERATIONS:
            raise KnowledgeError("unknown_operation", "Unknown Knowledge provider tool.", 404)
        return jsonify(dispatch(operation, g.authenticated_user, _body()))

    app.add_url_rule("/v1/knowledge/native/<tool>", "knowledge_native",
                     csrf.exempt(api_authenticate_only(required_scope="knowledge:read")(native_api)),
                     methods=["POST", "OPTIONS"])

    @app.get("/v1/knowledge/artifacts/<artifact_id>")
    @api_authenticate_only(required_scope="knowledge:read")
    def knowledge_artifact(artifact_id):
        return jsonify(dispatch("artifact", g.authenticated_user, {"id": _identifier(artifact_id)}))

    app.add_url_rule("/mcp", "knowledge_mcp",
                     csrf.exempt(api_authenticate_only(required_scope=lambda:
                         "knowledge:read" if management.permits(g.authenticated_user, "knowledge:read")
                         else "knowledge:manage")(_mcp)),
                     methods=["POST", "GET", "DELETE"])

    @app.get("/knowledge")
    @login_required
    def knowledge_page():
        require_admin_dashboard_user()
        return render_template("knowledge.html")

    def admin_operation(operation, path, methods, *, parse_body=False, query=False):
        @login_required
        def handle(identifier=None):
            user = require_admin_dashboard_user()
            payload = _body() if parse_body else {}
            if operation in alexandria.OPERATIONS:
                payload = alexandria.parse_request(operation, payload)
            if identifier is not None:
                if "id" in payload:
                    raise KnowledgeError("invalid_request", "Source and job ids belong in the URL.", 400)
                payload["id"] = _identifier(identifier)
            return jsonify(dispatch(operation, user, _query(payload) if query else payload))
        handle.__name__ = "knowledge_admin_" + operation.replace(".", "_")
        app.add_url_rule(path, handle.__name__, handle, methods=methods)
        if operation not in {"context", "artifact", *alexandria.OPERATIONS}:
            def public_handle(identifier=None):
                payload = _body() if parse_body else {}
                if identifier is not None:
                    if "id" in payload:
                        raise KnowledgeError("invalid_request", "Source and job ids belong in the URL.", 400)
                    payload["id"] = _identifier(identifier)
                return jsonify(dispatch(operation, g.authenticated_user, payload))
            public_path = path.replace("/admin/knowledge/", "/v1/knowledge/", 1)
            public_handle.__name__ = "knowledge_manage_" + operation.replace(".", "_")
            app.add_url_rule(public_path, public_handle.__name__,
                             csrf.exempt(api_authenticate_only(required_scope="knowledge:manage")(public_handle)),
                             methods=methods + ["OPTIONS"])

    admin_operation("status", "/admin/knowledge/status", ["GET"])
    admin_operation("context", "/admin/knowledge/query", ["POST"], parse_body=True, query=True)
    admin_operation("sources.create", "/admin/knowledge/sources", ["POST"], parse_body=True)
    admin_operation("sources.update", "/admin/knowledge/sources/<identifier>", ["PATCH"], parse_body=True)
    admin_operation("sources.refresh", "/admin/knowledge/sources/<identifier>/refresh", ["POST"])
    admin_operation("jobs.cancel", "/admin/knowledge/jobs/<identifier>/cancel", ["POST"])
    admin_operation("policy.update", "/admin/knowledge/policy", ["PUT"], parse_body=True)
    admin_operation("artifact", "/admin/knowledge/artifacts/<identifier>", ["GET"])
    for operation in alexandria.OPERATIONS:
        admin_operation(operation, "/admin/knowledge/" + operation.replace(".", "/"), ["POST"], parse_body=True)
