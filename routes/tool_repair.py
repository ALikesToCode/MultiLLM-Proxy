"""Repair responses at the Chat pivot without changing provider transports."""

import json
from functools import wraps
from itertools import chain

from flask import Response, g, request

from providers.cline_pass import cline_completion_payload
from routes.protocol_bridge import ENDPOINT_PROTOCOLS, as_flask_response, translate_downstream_response
from services.protocol_translation import CHAT, translate_request
from services.tool_repair_runtime import HEADER, SKIP_REASK, log_report, repair_completion, repair_mode, summary_header
from services.tool_repair_stream import ToolCallBuffer, repair_sse

MAX_RESPONSE_BYTES = 8 * 1024 * 1024


def _decode_response(response):
    parts, size = [], 0
    chunks = iter(response.iter_encoded())
    for part in chunks:
        parts.append(part)
        size += len(part)
        if size > MAX_RESPONSE_BYTES:
            response.response = chain(parts, chunks)
            return None
    body = b"".join(parts)
    response.set_data(body)
    try:
        payload = json.loads(body)
        return payload if isinstance(payload, dict) else None
    except (ValueError, UnicodeError, RecursionError):
        return None


def repair_response(upstream, payload, *, mode, provider, model, reask=None):
    if not payload.get("tools"):
        return upstream
    response = as_flask_response(upstream)
    if mode == "off" or response.status_code >= 400:
        response.headers[HEADER] = summary_header({}, streaming=response.mimetype == "text/event-stream", mode=mode)
        return response
    if response.mimetype == "text/event-stream":
        buffer = ToolCallBuffer(payload["tools"], payload.get("tool_choice"), mode)

        def generate():
            try:
                yield from repair_sse(response.iter_encoded(), buffer)
            finally:
                log_report(buffer.report, model, provider)
                response.close()

        headers = [(k, v) for k, v in response.headers.items() if k.lower() not in ("content-length", "content-type")]
        downstream = Response(generate(), status=response.status_code, headers=headers, content_type="text/event-stream")
        downstream.headers[HEADER] = summary_header(buffer.report, streaming=True, mode=mode)
        downstream.call_on_close(response.close)
        return downstream
    decoded = _decode_response(response)
    if decoded is None:
        response.headers[HEADER] = summary_header({}, streaming=response.mimetype == "text/event-stream", mode=mode)
        return response
    if provider == "cline-pass":
        decoded = cline_completion_payload(decoded)

    def followup(body):
        extra = reask(body)
        if extra is SKIP_REASK:
            return SKIP_REASK
        extra = as_flask_response(extra)
        try:
            decoded = _decode_response(extra) if extra.status_code < 400 else None
            return cline_completion_payload(decoded) if decoded is not None and provider == "cline-pass" else decoded
        finally:
            extra.close()

    repaired, report = repair_completion(decoded, payload, mode=mode,
                                          reask=followup if reask and not payload.get("stream") else None)
    if repaired is not decoded:
        response.set_data(json.dumps(repaired, ensure_ascii=False, separators=(",", ":")))
        response.content_type = "application/json"
        for name in ("Content-Encoding", "ETag", "Content-MD5"):
            response.headers.pop(name, None)
    response.headers[HEADER] = summary_header(report)
    log_report(report, model, provider)
    return response


def with_chat_tool_repair(dispatch):
    """One wrapper covers both direct Chat providers and native-to-Chat bridges."""
    @wraps(dispatch)
    def wrapped(app, auth, metrics, proxy, payload, **kwargs):
        headers = kwargs.get("request_headers")
        mode = repair_mode(request.headers if headers is None else headers, app.config)
        response = dispatch(app, auth, metrics, proxy, payload, **kwargs)
        model = payload.get("model", "unknown")
        provider = model.split(":", 1)[0] if isinstance(model, str) else "unknown"
        def reask(body):
            if getattr(g, "tool_repair_reasked", False):
                return SKIP_REASK
            g.tool_repair_reasked = True
            return dispatch(app, auth, metrics, proxy, body, **kwargs)

        return repair_response(response, payload, mode=mode, provider=provider, model=model,
                               reask=reask)
    return wrapped


def _native_chat_payload(payload, source):
    tools = []
    definitions = payload.get("tools")
    if not isinstance(definitions, list) or len(definitions) > 128:
        definitions = []
    for tool in definitions:
        if not isinstance(tool, dict):
            continue
        if source == "messages":
            function = {"name": tool.get("name"), "parameters": tool.get("input_schema", {})}
        elif tool.get("type") == "function":
            function = {"name": tool.get("name"), "parameters": tool.get("parameters", {})}
        else:
            continue
        if isinstance(function.get("name"), str):
            tools.append({"type": "function", "function": function})
    choice = payload.get("tool_choice")
    if isinstance(choice, dict):
        if choice.get("type") in ("tool", "function"):
            choice = {"type": "function", "function": {"name": choice.get("name")}}
        else:
            choice = "required" if choice.get("type") == "any" else choice.get("type")
    return {"model": payload.get("model"), "tools": tools, "tool_choice": choice, "stream": payload.get("stream", False)}


def with_native_tool_repair(dispatch):
    @wraps(dispatch)
    def wrapped(app, auth, metrics, proxy, payload, **kwargs):
        mode = repair_mode(request.headers, app.config)
        response = dispatch(app, auth, metrics, proxy, payload, **kwargs)
        if not payload.get("tools") or mode == "off":
            if payload.get("tools"):
                response.headers[HEADER] = summary_header({}, streaming=response.mimetype == "text/event-stream", mode=mode)
            return response
        source = ENDPOINT_PROTOCOLS[kwargs["endpoint"]]
        chat_payload = _native_chat_payload(payload, source)
        if not chat_payload["tools"]:
            response.headers[HEADER] = summary_header({}, streaming=response.mimetype == "text/event-stream", mode=mode)
            return response
        if response.mimetype != "text/event-stream" and _decode_response(response) is None:
            response.headers[HEADER] = summary_header({}, streaming=response.mimetype == "text/event-stream", mode=mode)
            return response
        chat = translate_downstream_response(response, source=source, target=CHAT,
                                             stream=bool(payload.get("stream")), request_payload=payload)
        if chat.status_code >= 400 and response.status_code < 400:
            response.headers[HEADER] = summary_header({}, streaming=response.mimetype == "text/event-stream", mode=mode)
            return response

        def reask(body):
            if getattr(g, "tool_repair_reasked", False):
                return SKIP_REASK
            conversation = translate_request(payload, source, CHAT)
            conversation["messages"] = [*conversation.get("messages", []), *body["messages"]]
            converted = translate_request(conversation, CHAT, source)
            extra_payload = {**payload, **converted, "stream": False}
            g.tool_repair_reasked = True
            extra = dispatch(app, auth, metrics, proxy, extra_payload, **kwargs)
            return translate_downstream_response(extra, source=source, target=CHAT,
                                                 stream=False, request_payload=extra_payload)

        repaired = repair_response(chat, chat_payload, mode=mode, provider=kwargs["provider"],
                                   model=kwargs["provider_model"], reask=reask)
        counts = repaired.headers.get(HEADER, "")
        if (repaired.mimetype != "text/event-stream" and "repaired=0" in counts
                and "extracted=0" in counts and "reasked=0" in counts):
            response.headers[HEADER] = counts
            return response
        return translate_downstream_response(repaired, source=CHAT, target=source,
                                             stream=bool(payload.get("stream")), request_payload=payload)
    return wrapped
