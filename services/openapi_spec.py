"""Reviewed static public API descriptors; no catalog or configuration access."""

from __future__ import annotations

import json
import sys
from copy import deepcopy
from typing import Any


def _object(properties: dict[str, Any], *required: str) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "object", "properties": properties, "additionalProperties": True}
    if required:
        schema["required"] = list(required)
    return schema


def _ref(name: str) -> dict[str, str]:
    return {"$ref": f"#/components/schemas/{name}"}


STRING = {"type": "string"}
MESSAGE = _object({"role": STRING, "content": {}}, "role")
MESSAGES = {"type": "array", "items": MESSAGE}
MODEL = {
    "type": "string", "minLength": 1,
    "description": "Managed routes accept provider:model or a configured route ID. Native routes use the provider model ID.",
}
SCHEMAS = {
    "ChatRequest": _object({
        "model": MODEL, "messages": MESSAGES, "stream": {"type": "boolean", "default": False},
        "max_tokens": {"type": "integer", "minimum": 1}, "temperature": {"type": "number"},
        "tools": {"type": "array", "items": {"type": "object"}}, "tool_choice": {},
        "response_format": {"type": "object"},
    }, "model", "messages"),
    "ResponsesRequest": _object({
        "model": MODEL, "input": {"type": ["string", "array"], "items": {}},
        "instructions": STRING, "stream": {"type": "boolean", "default": False},
        "max_output_tokens": {"type": "integer", "minimum": 1},
        "tools": {"type": "array", "items": {"type": "object"}},
    }, "model", "input"),
    "MessagesRequest": _object({
        "model": MODEL, "messages": MESSAGES,
        "max_tokens": {"type": "integer", "minimum": 1}, "system": {},
        "stream": {"type": "boolean", "default": False},
        "tools": {"type": "array", "items": {"type": "object"}},
    }, "model", "messages", "max_tokens"),
    "TokenCountRequest": _object({"model": MODEL, "messages": MESSAGES, "system": {},
                                  "tools": {"type": "array", "items": {"type": "object"}}}, "messages"),
    "ImageRequest": _object({
        "model": MODEL, "prompt": {"type": "string", "minLength": 1},
        "n": {"type": "integer", "minimum": 1}, "size": STRING,
        "quality": STRING, "response_format": STRING,
    }, "model", "prompt"),
    "ChatCompletion": _object({
        "id": STRING, "object": {"const": "chat.completion"}, "model": STRING,
        "choices": {"type": "array", "items": _object({
            "index": {"type": "integer"}, "message": MESSAGE, "finish_reason": {"type": ["string", "null"]},
        })}, "usage": {"type": ["object", "null"]},
    }),
    "Response": _object({
        "id": STRING, "object": {"const": "response"}, "status": STRING,
        "output": {"type": "array", "items": {"type": "object"}},
        "usage": {"type": ["object", "null"]},
    }),
    "Message": _object({
        "id": STRING, "type": {"const": "message"}, "role": {"const": "assistant"},
        "model": STRING, "content": {"type": "array", "items": {"type": "object"}},
        "stop_reason": {"type": ["string", "null"]}, "usage": {"type": "object"},
    }),
    "Images": _object({
        "created": {"type": "integer"}, "data": {"type": "array", "items": _object({
            "url": STRING, "b64_json": STRING, "revised_prompt": STRING,
        })},
    }),
    "Models": _object({
        "object": {"const": "list"}, "data": {"type": "array", "items": _object({
            "id": STRING, "object": {"const": "model"}, "owned_by": STRING,
        }, "id")},
    }, "data"),
    "TokenCount": _object({"input_tokens": {"type": "integer", "minimum": 0}}, "input_tokens"),
    "GatewayError": _object({
        "error": STRING, "message": STRING, "request_id": STRING,
    }, "message"),
    "OpenAIError": _object({"error": _object({
        "message": STRING, "type": STRING,
        "code": {"type": ["string", "null"]}, "param": {"type": ["string", "null"]},
    }, "message", "type")}, "error"),
    "AnthropicError": _object({
        "type": {"const": "error"}, "error": _object({"type": STRING, "message": STRING}, "type", "message"),
        "request_id": STRING,
    }, "type", "error"),
}

# These are client controls, not a reflection of environment or private headers.
REQUEST_HEADERS = {
    "ProxyKey": ("X-MultiLLM-Api-Key", "Alternative gateway credential; never a provider credential.", STRING),
    "AnthropicKey": ("X-Api-Key", "Alternative gateway credential for Messages clients.", STRING),
    "AnthropicVersion": ("Anthropic-Version", "Accepted Messages version header; optional on the managed bridge.", STRING),
    "AnthropicBeta": ("Anthropic-Beta", "Native beta selection is provider-defined; managed translation may reject unsupported features.", STRING),
    "Cache": ("X-MultiLLM-Cache", "Chat only: off/bypass unless explicitly opted in. Eligibility and configured storage limits still apply.",
              {"type": "string", "enum": ["on", "refresh", "off"]}),
    "ToolRepair": ("X-MultiLLM-Tool-Repair", "Managed Chat repair override; deployment default is repair. Full may request another generation.",
                   {"type": "string", "enum": ["off", "repair", "full"]}),
    "ImageQA": ("X-MultiLLM-Image-QA", "Managed images: opt in to bounded generation/judging; may incur additional cost. Off by default.",
                {"type": "string", "enum": ["on", "off"]}),
    "Cascade": ("X-MultiLLM-Cascade", "Managed Chat: select a configured cascade explicitly; not enabled by fetching this contract.", STRING),
}
RESPONSE_HEADERS = {
    "X-Request-ID": "Request correlation ID.",
    "X-MultiLLM-Provider": "Selected provider, when known.",
    "X-MultiLLM-Model": "Selected model, when known.",
    "X-MultiLLM-Route-Decision": "Routing decision, when available.",
    "X-MultiLLM-Latency-Ms": "Observed latency in milliseconds, when available.",
    "X-MultiLLM-Estimated-Cost-USD": "Estimated USD cost when available; absence does not mean zero.",
    "X-MultiLLM-Cost-Basis": "Basis of the available cost estimate.",
    "X-MultiLLM-Auto-Route": "Configured automatic route ID, when used.",
    "X-MultiLLM-Auto-Selected-Model": "Selected automatic-route candidate.",
    "X-MultiLLM-Auto-Attempts": "Automatic-route attempts; not permission to replay a request.",
    "X-MultiLLM-Auto-Selected-Priority": "Selected automatic-route candidate priority.",
    "X-MultiLLM-Auto-Ordering": "Existing automatic-route ordering mode.",
    "X-MultiLLM-Auto-Failover-Reasons": "Existing automatic-route failover reasons, when available.",
    "X-MultiLLM-Credential-Attempts": "Credential selection attempts, when available; no credential values.",
    "X-MultiLLM-Circuit-State": "Existing managed circuit state, when available.",
    "X-MultiLLM-Transport-Failure": "Transport failure metadata; never permission to retry output.",
    "X-MultiLLM-Cache": "Cache result on eligible opted-in managed Chat requests.",
    "X-MultiLLM-Tool-Repair": "Managed Chat repair summary, when enabled.",
    "X-MultiLLM-Image-QA": "Managed image quality summary, when requested.",
    "X-MultiLLM-Cascade": "Managed cascade selection summary, when requested.",
    "X-MultiLLM-Optimization": "Existing managed context optimization status.",
    "X-MultiLLM-Optimization-Mode": "Existing managed optimization mode.",
    "X-MultiLLM-Estimated-Input-Before": "Provider-neutral estimated input tokens before optimization.",
    "X-MultiLLM-Estimated-Input-After": "Provider-neutral estimated input tokens after optimization.",
    "X-MultiLLM-Image-Prompts-Compacted": "Image prompts compacted by managed optimization.",
    "X-MultiLLM-Messages-Summarized": "Managed optimization summary count.",
    "X-MultiLLM-Optimization-Target-Met": "Whether the managed optimization target was met.",
    "X-MultiLLM-Summary": "Managed summary status.",
    "X-MultiLLM-Optimization-Cache-Hits": "Managed optimization cache hit count.",
    "X-MultiLLM-Optimization-Cache-Misses": "Managed optimization cache miss count.",
    "X-MultiLLM-Prompt-Cache": "Existing managed prompt-cache policy status.",
    "X-MultiLLM-Prompt-Cache-Mode": "Existing managed prompt-cache mode.",
    "X-MultiLLM-Prompt-Cache-Estimated-Tokens": "Estimated prompt-cache tokens; not guaranteed billed usage.",
    "X-MultiLLM-Secret-Scan": "Existing outbound policy counts; not a client policy override.",
    "Retry-After": "Rate/provider advice, when supplied; not authorization to retry generated output.",
}

MANAGED_ROUTES = (
    ("/v1/models", "get", "listModels", None, "Models", None),
    ("/v1/chat/completions", "post", "createChatCompletion", "ChatRequest", "ChatCompletion", "chat"),
    ("/v1/responses", "post", "createResponse", "ResponsesRequest", "Response", "responses"),
    ("/v1/messages", "post", "createMessage", "MessagesRequest", "Message", "messages"),
    ("/v1/images/generations", "post", "generateImages", "ImageRequest", "Images", None),
    ("/v1/messages/count_tokens", "post", "estimateMessageTokens", "TokenCountRequest", "TokenCount", None),
)
NATIVE_ROUTES = (
    ("/opencode/v1/models", "get", "nativeOpencodeModels", None),
    ("/opencode/v1/chat/completions", "post", "nativeOpencodeChat", "chat"),
    ("/opencode/v1/responses", "post", "nativeOpencodeResponses", "responses"),
    ("/opencode/v1/messages", "post", "nativeOpencodeMessages", "messages"),
    ("/codex-easy/v1/images/generations", "post", "nativeCodexImages", None),
)
SSE_DESCRIPTIONS = {
    "chat": "SSE data frames with Chat deltas and [DONE]; errors can appear after HTTP 200. EOF alone is not completion.",
    "responses": "Named Responses SSE events, including response.completed, response.failed or response.incomplete; no Chat [DONE] guarantee.",
    "messages": "Named Messages SSE events, including message_stop or error; no Chat [DONE] sentinel.",
}


def _headers(names: tuple[str, ...] | None = None) -> dict[str, Any]:
    return {
        name: {"description": description, "schema": {"type": "string"}}
        for name, description in RESPONSE_HEADERS.items() if names is None or name in names
    }


def _responses(schema: dict[str, Any], stream: str | None, *, native: bool = False,
               messages: bool = False) -> dict[str, Any]:
    content: dict[str, Any] = {"application/json": {"schema": schema}}
    if stream:
        content["text/event-stream"] = {"schema": {"type": "string", "description": SSE_DESCRIPTIONS[stream]}}
    errors: dict[str, Any] = {"anyOf": [_ref("AnthropicError" if messages else "OpenAIError"), _ref("GatewayError")]}
    if native:
        errors = {}
    return {
        "200": {"description": "Successful response; fields and availability depend on the selected model.",
                "headers": _headers(), "content": content},
        "default": {
            "description": "Non-2xx error. Common statuses: 400 invalid input, 401 unauthenticated, 403 forbidden, 402 budget, 404 unavailable, 413 too large, 429 limited, 500/502/503/504 failure. Native upstream errors may be non-JSON.",
            "headers": _headers(("X-Request-ID", "Retry-After")),
            "content": {"application/json": {"schema": errors}, "text/plain": {"schema": {"type": "string"}}},
        },
    }


def _parameters(*names: str) -> list[dict[str, str]]:
    return [{"$ref": f"#/components/parameters/{name}"} for name in names]


def _managed_paths() -> dict[str, Any]:
    paths = {}
    for path, method, identifier, input_schema, output_schema, stream in MANAGED_ROUTES:
        parameters = ["ProxyKey"]
        if "/messages" in path:
            parameters += ["AnthropicKey", "AnthropicVersion", "AnthropicBeta"]
        if input_schema == "ChatRequest":
            parameters += ["Cache", "ToolRepair", "Cascade"]
        if input_schema == "ImageRequest":
            parameters += ["ImageQA"]
        runtime = {"mode": "managed", "flask": "managed", "worker": "forwarded",
                   "required_scope": "models" if method == "get" else "chat"}
        operation: dict[str, Any] = {
            "operationId": identifier, "tags": ["Managed"], "parameters": _parameters(*parameters),
            "description": "Gateway model selection and existing managed policy apply. Protocol translation is stateless and bounded; unsupported features may fail with 400. This descriptor does not enable any optional feature.",
            "x-multillm-runtime": runtime,
            "responses": _responses(_ref(output_schema), stream, messages="/messages" in path),
        }
        if "/messages" in path:
            operation["security"] = [{"BearerAuth": []}, {"ProxyKeyAuth": []}, {"AnthropicKeyAuth": []}]
        if input_schema:
            operation["requestBody"] = {"required": True, "content": {"application/json": {"schema": _ref(input_schema)}}}
        if output_schema == "TokenCount":
            runtime["token_count"] = {"source": "estimate", "provider_call": False}
            operation["description"] = "Local input token estimate, not native provider tokenization; no generation."
            operation["responses"]["200"]["headers"]["X-MultiLLM-Token-Count"] = {
                "schema": {"const": "estimate"}, "description": "Estimate provenance.",
            }
        paths[path] = {method: operation}
    return paths


def _native_paths() -> dict[str, Any]:
    paths = {}
    for path, method, identifier, stream in NATIVE_ROUTES:
        opencode = path.startswith("/opencode/")
        operation: dict[str, Any] = {
            "operationId": identifier, "tags": ["Native"], "parameters": _parameters("ProxyKey"),
            "description": "Bounded example of the native public surface. Provider-native request/response fields are intentionally unspecified. Gateway auth and outbound policy still apply; capability and configuration are not certified by this document.",
            "x-multillm-runtime": {
                "mode": "native", "flask": "native", "worker": "native-when-enabled" if opencode else "native",
                "worker_condition": "OPENCODE_EDGE_FETCH=true" if opencode else "existing direct provider handler",
                "worker_otherwise": "forwarded" if opencode else "native",
                "required_scope": "admin",
                "availability": "requires provider configuration and route permission",
            },
            "responses": _responses({}, stream, native=True),
        }
        if stream == "messages":
            operation["parameters"] += _parameters("AnthropicKey", "AnthropicVersion", "AnthropicBeta")
            operation["security"] = [{"BearerAuth": []}, {"ProxyKeyAuth": []}, {"AnthropicKeyAuth": []}]
        if method == "post":
            operation["requestBody"] = {"required": True, "content": {"application/json": {"schema": {}}}}
        paths[path] = {method: operation}
    return paths


def build_openapi_spec() -> dict[str, Any]:
    """Return a fresh contract from static descriptors only."""
    spec: dict[str, Any] = {
        "openapi": "3.1.0",
        "info": {"title": "MultiLLM public client API", "version": "1.0.0",
                 "description": "Bounded client contract, not a live provider catalog. Optional future APIs and administrator routes are excluded. Extra fields are not a guarantee of upstream support."},
        "servers": [{"url": "/"}],
        "security": [{"BearerAuth": []}, {"ProxyKeyAuth": []}],
        "tags": [{"name": "Managed"}, {"name": "Native"}, {"name": "Documentation"}],
        "x-multillm-runtime": {
            "flask": "registered client routes", "worker": "native handlers or Flask forwarding as annotated",
            "catalog_refresh": False, "source": "reviewed static descriptors",
            "optional_features": "No new feature is enabled by this contract; deployment configuration and permissions control availability.",
            "limits": "Existing request, scope, rate, budget and provider bounds apply. Usage/cost may be missing or estimated. No retention or retry guarantee.",
        },
        "paths": {**_managed_paths(), **_native_paths()},
        "components": {
            "securitySchemes": {
                "BearerAuth": {"type": "http", "scheme": "bearer"},
                "ProxyKeyAuth": {"type": "apiKey", "in": "header", "name": "X-MultiLLM-Api-Key"},
                "AnthropicKeyAuth": {"type": "apiKey", "in": "header", "name": "X-Api-Key"},
                "DashboardSession": {"type": "apiKey", "in": "cookie", "name": "session",
                                     "description": "Existing dashboard session, revalidated by the server."},
            },
            "schemas": SCHEMAS,
            "parameters": {
                identifier: {"name": name, "in": "header", "required": False,
                             "description": description, "schema": schema}
                for identifier, (name, description, schema) in REQUEST_HEADERS.items()
            },
        },
    }
    spec["paths"]["/openapi.json"] = {"get": {
        "operationId": "getOpenAPIContract", "tags": ["Documentation"],
        "description": "Dashboard session or gateway API credential with models scope. Anonymous browser requests redirect to login; JSON clients receive 401. No provider/catalog access.",
        "parameters": _parameters("ProxyKey"),
        "security": [{"BearerAuth": []}, {"ProxyKeyAuth": []}, {"DashboardSession": []}],
        "x-multillm-runtime": {"mode": "documentation", "flask": "static", "worker": "forwarded", "required_scope": "models"},
        "responses": {
            "200": {"description": "Static OpenAPI 3.1.0 contract.", "content": {"application/json": {"schema": {"type": "object"}}}},
            "302": {"description": "Anonymous browser sign-in redirect.", "headers": {"Location": {"schema": STRING}}},
            "401": {"description": "Missing or invalid credential.", "content": {"application/json": {"schema": _ref("GatewayError")}}},
            "403": {"description": "Credential lacks models scope.", "content": {"application/json": {"schema": _ref("GatewayError")}}},
        },
    }}
    return deepcopy(spec)


def render_openapi_spec() -> str:
    """Canonical UTF-8 snapshot, independent of host, time and configuration."""
    return json.dumps(build_openapi_spec(), ensure_ascii=False, sort_keys=True, indent=2) + "\n"


if __name__ == "__main__":
    sys.stdout.write(render_openapi_spec())
