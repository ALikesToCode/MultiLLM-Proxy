"""Hosted Responses routes and bounded SSE completion observation."""
from __future__ import annotations

import json
from functools import wraps

from flask import Response, abort, current_app, g, request
from werkzeug.exceptions import HTTPException
from werkzeug.routing import Map

from route_helpers import api_auth_required
from services import responses_state as state
from services.generation_deadline import current_deadline, GenerationDeadlineExceeded, error_event, error_response as deadline_error
from services.intelligence_contract import GatewayError


def error_response(error):
    return Response(json.dumps({"error": {"code": error.code, "message": error.message}}),
                    status=error.status, content_type="application/json", headers={"Cache-Control": "no-store"})


def defer_hosted_idempotency(finalizer):
    """Hosted completion settles after accounting and deadline response checks."""
    @wraps(finalizer)
    def finish(response):
        if getattr(g, "hosted_responses_turn", None) is not None:
            return response
        return finalizer(response)
    return finish


def responses_state_hook():
    if not state.enabled() or request.path != "/v1/responses" or request.method != "POST":
        return None
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return None
    try:
        turn = state.prepare(payload)
        if turn is None:
            return None
        g.hosted_responses_turn = turn
        from middleware.idempotency import begin_managed_request
        replay = begin_managed_request(payload, turn.revision)
        if replay is not None:
            g.hosted_responses_turn = None
        return replay
    except GatewayError as error:
        return error_response(error)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return error_response(GatewayError("invalid_request", "Hosted Responses input must be valid finite JSON."))


def _event_data(frame):
    lines = frame.replace(b"\r\n", b"\n").split(b"\n")
    return lines, b"\n".join(line[5:].lstrip(b" ") for line in lines if line.startswith(b"data:"))


def _event(frame, turn):
    lines, data = _event_data(frame)
    if not data or data == b"[DONE]":
        return frame + b"\n\n", None, False
    try:
        event = json.loads(data)
    except (ValueError, RecursionError):
        raise GatewayError("invalid_response_stream", "Hosted Responses received an invalid event stream.", 502) from None
    if not isinstance(event, dict):
        raise GatewayError("invalid_response_stream", "Hosted Responses received an invalid event stream.", 502)
    body = event.get("response")
    if isinstance(body, dict):
        event["response"] = state.public_body(body, turn)
    if "response_id" in event:
        event["response_id"] = turn.id
    name = event.get("type", "")
    if name == "response.completed" and not state.complete_body(body):
        raise GatewayError("invalid_response_stream", "Hosted Responses received an invalid completion event.", 502)
    terminal = name in {"response.completed", "response.incomplete", "response.failed", "error"}
    prefix = b"\n".join(line for line in lines if not line.startswith(b"data:"))
    encoded = prefix + b"\ndata: " + json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode() + b"\n\n"
    return encoded, body if name == "response.completed" else None, terminal


def hosted_stream(source, turn, headers):
    """Hold terminal bytes until EOF accounting, rejecting interrupted or ambiguous streams."""
    pending = b""
    terminal = None
    completed = None
    try:
        for chunk in source:
            pending += chunk.encode() if isinstance(chunk, str) else chunk
            while True:
                # SSE allows LF and CRLF separators, including separators split across reads.
                split = pending.find(b"\n\n")
                crlf = pending.find(b"\r\n\r\n")
                if crlf >= 0 and (split < 0 or crlf < split):
                    split, width = crlf, 4
                else:
                    width = 2
                if split < 0:
                    if len(pending) > state.MAX_DOCUMENT_BYTES:
                        raise GatewayError("response_state_too_large", "Hosted Responses event exceeds 1 MiB.", 502)
                    break
                if split > state.MAX_DOCUMENT_BYTES:
                    raise GatewayError("response_state_too_large", "Hosted Responses event exceeds 1 MiB.", 502)
                frame, pending = pending[:split], pending[split + width:]
                encoded, body, is_terminal = _event(frame, turn)
                if is_terminal:
                    if terminal is not None:
                        raise GatewayError("invalid_response_stream", "Hosted Responses received multiple terminal events.", 502)
                    terminal, completed = encoded, body
                elif terminal is None:
                    yield encoded
                elif _event_data(frame)[1] not in (b"", b"[DONE]"):
                    raise GatewayError("invalid_response_stream", "Hosted Responses received data after completion.", 502)
        if pending.strip() or terminal is None:
            raise GatewayError("incomplete_response_stream", "Hosted Responses stream ended without a terminal event.", 502)
        close = getattr(source, "close", None)
        if close is not None:
            close()
        if completed is not None and not state.persist(turn, completed, headers):
            raise GatewayError("response_outcome_unknown", "Hosted Responses completion could not be verified.", 502)
        yield terminal
    except GatewayError as error:
        yield ("event: error\ndata: " + json.dumps({"type": "error", "code": error.code, "message": error.message}) + "\n\n").encode()
    except GenerationDeadlineExceeded:
        yield error_event("responses")
    except Exception:
        yield b'event: error\ndata: {"type":"error","code":"response_outcome_unknown","message":"Hosted Responses stream was interrupted."}\n\n'
    finally:
        close = getattr(source, "close", None)
        if close is not None:
            close()


def finish_hosted_response(response):
    turn = getattr(g, "hosted_responses_turn", None)
    if turn is None:
        return response
    from middleware.idempotency import finish_managed_response
    if not turn.keep:
        from services.managed_turn import completed_response
        return finish_managed_response(response, complete=completed_response(response))
    turn.cancellation = getattr(g, "gateway_cancellation", None) or turn.cancellation
    turn.deadline = current_deadline() or turn.deadline
    if response.status_code != 200:
        return finish_managed_response(response)
    if response.mimetype == "text/event-stream":
        response.response = hosted_stream(response.response, turn, response.headers)
        response.headers.pop("Content-Length", None)
        return response
    try:
        if response.is_streamed:
            # The existing passthrough iterator must finish accounting before storage.
            source = response.response
            data = bytearray()
            try:
                for chunk in source:
                    data.extend(chunk.encode() if isinstance(chunk, str) else chunk)
                    if len(data) > state.MAX_DOCUMENT_BYTES:
                        raise GatewayError("response_state_too_large", "Hosted Responses state exceeds 1 MiB.", 502)
            finally:
                close = getattr(source, "close", None)
                if close is not None:
                    close()
            response.set_data(bytes(data))
        body = json.loads(response.get_data())
        stored = state.persist(turn, body, response.headers)
        if state.complete_body(body) and not stored:
            raise GatewayError("response_outcome_unknown", "Hosted Responses completion could not be verified.", 502)
        if stored:
            response.set_data(json.dumps(state.public_body(body, turn), ensure_ascii=False, separators=(",", ":")))
        return finish_managed_response(response, complete=stored)
    except GatewayError as error:
        return finish_managed_response(error_response(error))
    except GenerationDeadlineExceeded:
        return finish_managed_response(deadline_error())
    except (ValueError, RecursionError):
        return finish_managed_response(error_response(GatewayError("invalid_response", "Hosted Responses received an invalid response.", 502)))
    except Exception:
        return finish_managed_response(error_response(GatewayError("response_outcome_unknown", "Hosted Responses completion was interrupted.", 502)))


def register_responses_state(app, csrf):
    if app.extensions.get("responses_state_registered"):
        return
    original_routes = Map([rule.empty() for rule in app.url_map.iter_rules()],
                          default_subdomain=app.url_map.default_subdomain,
                          host_matching=app.url_map.host_matching,
                          strict_slashes=app.url_map.strict_slashes,
                          merge_slashes=app.url_map.merge_slashes,
                          converters=app.url_map.converters)
    app.extensions["responses_state_store"] = state.ResponsesStateStore()
    from services.gateway_extensions import register_authenticated_hook
    register_authenticated_hook(app, responses_state_hook)
    app.extensions["responses_state_registered"] = True
    app.after_request(finish_hosted_response)

    @app.route("/v1/responses/<response_id>", methods=["GET", "DELETE"])
    @csrf.exempt
    def stored_response(response_id):
        if not state.enabled():
            abort(404)
        return authorized_response(response_id)

    def preserve_disabled_routing():
        if request.endpoint != "stored_response" or state.enabled():
            return None
        # Restore the pre-existing rule before CSRF, policy, authentication and accounting.
        try:
            request.url_rule, request.view_args = original_routes.bind_to_environ(request.environ).match(return_rule=True)
        except HTTPException as error:
            request.url_rule, request.view_args = None, None
            request.routing_exception = error
        return None

    app.before_request_funcs.setdefault(None, []).insert(0, preserve_disabled_routing)

    @api_auth_required
    def authorized_response(response_id):
        try:
            if not state.gateway_id(response_id):
                raise state.not_found()
            if request.method == "GET" and not state.request_policy().allows_content:
                raise GatewayError("retention_conflict", "Zero-content retention forbids reading hosted Responses state.")
            owner = state.principal_owner()
            store = current_app.extensions["responses_state_store"]
            if request.method == "DELETE":
                store.delete(owner, response_id)
                body = {"id": response_id, "object": "response.deleted", "deleted": True}
            else:
                body = store.get(owner, response_id)["document"]["response"]
            return Response(json.dumps(body, ensure_ascii=False, separators=(",", ":")), content_type="application/json",
                            headers={"Cache-Control": "no-store"})
        except GatewayError as error:
            return error_response(error)
