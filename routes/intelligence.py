"""HTTP boundary for the version-one intelligence contract."""

import json
import logging
import queue
import threading

from flask import Response, g, jsonify, request
from werkzeug.exceptions import RequestEntityTooLarge

from error_handlers import get_request_id
from route_helpers import api_auth_required
from services.intelligence_contract import ChatRequest, GatewayError
from services.intelligence_gateway import ChatGateway
from services.intelligence_output import sse
from services.intelligence_store import IntelligenceStore
from services.intelligence_transport import IntelligenceTransport

logger = logging.getLogger(__name__)


def error_response(error, gateway=None):
    payload = error.envelope()
    payload["request_id"] = get_request_id()
    if gateway:
        payload = gateway.decorate(payload)
    response = jsonify(payload)
    response.status_code = error.status
    if error.retry_after:
        response.headers["Retry-After"] = error.retry_after
    return response


def load_policy():
    try:
        policy = IntelligenceStore.policy()
    except GatewayError:
        raise
    except Exception:
        raise GatewayError(
            "policy_unavailable",
            "The intelligence policy store is unavailable or invalid.",
            503,
        ) from None
    if not policy["enabled"]:
        raise GatewayError(
            "intelligence_disabled", "The intelligence gateway is not configured.", 503
        )
    return policy


def reject_idempotency():
    if request.headers.get("Idempotency-Key") is not None:
        raise GatewayError(
            "idempotency_not_supported",
            "Version one does not accept Idempotency-Key; uncertain generations must not be replayed.",
        )


def stream_response(gateway):
    events = queue.Queue(maxsize=4)
    started = threading.Event()

    def put(value):
        while not gateway.cancelled.is_set():
            try:
                events.put(value, timeout=0.05)
                return
            except queue.Full:
                continue

    def produce():
        try:
            for event in gateway.events():
                put(sse(event))
            put("data: [DONE]\n\n")
        except GatewayError as error:
            put(sse(gateway.decorate(error.envelope())))
            put("data: [DONE]\n\n")
        except Exception:
            # Never render an exception string or upstream response in an SSE error.
            failure = GatewayError(
                "gateway_error", "The gateway could not complete the request.", 503
            )
            put(sse(gateway.decorate(failure.envelope())))
            put("data: [DONE]\n\n")
        finally:
            put(None)

    def generate():
        try:
            started.set()
            threading.Thread(
                target=produce, daemon=True, name="intelligence-stream"
            ).start()
            while not gateway.cancelled.is_set():
                try:
                    event = events.get(timeout=0.25)
                except queue.Empty:
                    # Heartbeats let the WSGI server observe a disconnected client
                    # while headers or the next provider event are still pending.
                    yield ": keep-alive\n\n"
                    continue
                if event is None:
                    return
                yield event
        finally:
            gateway.cancel()

    def close():
        gateway.cancel()
        if not started.is_set():
            gateway.settle()

    response = Response(
        generate(),
        content_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )
    response.call_on_close(close)
    return response


def dispatch_intelligence_chat(app, auth, metrics, proxy, payload):
    gateway = None
    try:
        reject_idempotency()
        policy = load_policy()
        if len(request.get_data(cache=True)) > policy["max_request_bytes"]:
            raise GatewayError(
                "request_too_large",
                "The intelligence request exceeds the size limit.",
                413,
            )
        try:
            parsed = ChatRequest.parse(payload, policy)
        except (ValueError, TypeError, AttributeError, OverflowError):
            raise GatewayError(
                "invalid_routing_request",
                "The request does not satisfy the version-one chat and routing contract.",
            ) from None
        gateway = ChatGateway(
            parsed,
            policy,
            IntelligenceTransport(app.config, auth, proxy),
            g.authenticated_user["username"],
            get_request_id(),
            metrics,
        )
        if parsed.payload.get("stream"):
            return stream_response(gateway)
        result = list(gateway.events())
        return Response(json.dumps(result[-1]), content_type="application/json")
    except GatewayError as error:
        return error_response(error, gateway)
    except Exception:
        return error_response(
            GatewayError(
                "gateway_error", "The gateway could not complete the request.", 503
            ),
            gateway,
        )


def normalize_gateway_error(response):
    """Keep authentication, scope and outer admission failures on the same contract."""
    if response.status_code < 400 or response.is_streamed:
        return response
    body = response.get_json(silent=True)
    if isinstance(body, dict) and isinstance(body.get("error"), dict):
        return response
    code = {
        400: "invalid_request",
        401: "authentication_required",
        403: "insufficient_scope",
        413: "request_too_large",
        429: "allowance_exhausted",
    }.get(response.status_code, "gateway_error")
    response.set_data(
        json.dumps(
            {
                "error": {
                    "code": code,
                    "message": "The gateway could not accept the request.",
                    "retryable": response.status_code == 429,
                },
                "request_id": get_request_id(),
            }
        )
    )
    response.content_type = "application/json"
    return response


def register_intelligence_routes(app, csrf, auth, metrics, proxy):
    @app.route("/intelligence/v1/chat/completions", methods=["POST", "OPTIONS"])
    @csrf.exempt
    @api_auth_required
    def intelligence_chat_completions():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return error_response(
                GatewayError("invalid_request", "A JSON object is required.")
            )
        payload = dict(payload)
        payload.setdefault("model", "auto:intelligence")
        return dispatch_intelligence_chat(app, auth, metrics, proxy, payload)

    @app.after_request
    def intelligence_error_contract(response):
        dedicated = request.path.startswith("/intelligence/") or request.path in {
            "/v1/audio/transcriptions",
            "/v1/audio/speech",
            "/v1/embeddings",
        }
        payload = None
        if request.path == "/v1/chat/completions" and request.is_json:
            try:
                payload = request.get_json(silent=True)
            except RequestEntityTooLarge:
                payload = None
        routed = isinstance(payload, dict) and (
            payload.get("model") == "auto:intelligence" or "routing" in payload
        )
        return normalize_gateway_error(response) if dedicated or routed else response
