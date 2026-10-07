"""Verification-gated chat orchestration through the normal accounted dispatcher."""

import json
import time
from itertools import chain

from flask import Response, g, jsonify, request

from error_handlers import APIError
from routes.protocol_bridge import STREAM_HEADERS
from services.accounted_dispatch import accounted_dispatch, release_outer_accounting
from services.cascade_checks import agrees, choice_message, judge_passes, judge_payload, local_check, short_answer
from services.cascade_service import CascadeService
from services.judge_routing import excluding_gemini
from services.intelligence_contract import GatewayError
from services.key_controls import model_allowed
from services.protocol_translation import CHAT, completion_stream
from services.route_health import RouteHealth

HEADER = "X-MultiLLM-Cascade"
MAX_ANSWER_BYTES = 1024 * 1024


def _body(response):
    source = response.response
    close = getattr(source, "close", lambda: None)
    iterator = response.iter_encoded()
    parts, size = [], 0
    def preserve():
        response.response = chain(parts, iterator)
        response.call_on_close(close)

    for _ in range(4096):
        deadline = getattr(g, "cascade_deadline", None)
        if deadline is not None and time.monotonic() >= deadline:
            preserve()
            return None
        try:
            chunk = next(iterator)
        except StopIteration:
            break
        except Exception:
            close()
            response.status_code = 502
            response.direct_passthrough = False
            response.set_data(json.dumps({"error": {"type": "upstream_error", "message": "The cascade tier response was interrupted"}}))
            return None
        parts.append(chunk)
        size += len(chunk)
        if size > MAX_ANSWER_BYTES:
            preserve()
            return None
    else:
        preserve()
        return None
    raw = b"".join(parts)
    close()
    response.direct_passthrough = False
    response.set_data(raw)
    try:
        value = json.loads(raw)
        return value if isinstance(value, dict) else None
    except (ValueError, UnicodeError, RecursionError):
        return None


def _selected(response, model):
    return response.headers.get("X-MultiLLM-Auto-Selected-Model") or response.headers.get("X-MultiLLM-Model") or model


def _result(response, payload, index, count, model, skipped):
    g.multillm_model, g.multillm_provider = model, model.split(":", 1)[0]
    g.multillm_route_decision = "cascade"
    response.headers[HEADER] = f"tier={index}/{count}; model={model}; skipped=" + ",".join(skipped)
    if payload.get("stream") and response.mimetype != "text/event-stream" and response.status_code < 400:
        body = _body(response)
        if body is not None:
            headers = {key: value for key, value in response.headers.items()
                       if key.lower() not in {"content-type", "content-length", "content-encoding", "transfer-encoding"}}
            replay = Response(completion_stream(body, CHAT, CHAT, model=model, request=payload),
                              headers={**headers, **STREAM_HEADERS}, content_type="text/event-stream")
            replay.call_on_close(response.close)
            return replay
    return response


def _tier_payload(payload, tier, final):
    result = {**payload, "model": tier["model"], "stream": bool(payload.get("stream")) if final else False}
    if "max_output_tokens" in tier:
        limits = [tier["max_output_tokens"]]
        for field in ("max_tokens", "max_completion_tokens"):
            value = result.pop(field, None)
            if type(value) is int and value > 0:
                limits.append(value)
        result["max_completion_tokens"] = min(limits)
    return result


def _checks(config, body, payload, response, call, can_call):
    for check in config["checks"]:
        if check == "agreement":
            text = short_answer(body)
            if text is None:
                continue
            if not can_call():
                return "deadline"
            model = config.get("agreement", {}).get("model", payload["model"])
            try:
                with excluding_gemini(model):
                    other = call({**payload, "model": model, "stream": False})
                try:
                    if other.status_code >= 400 or not agrees(text, short_answer(_body(other))):
                        return check
                finally:
                    other.close()
            except APIError as error:
                if (error.payload or {}).get("error") == "secret_detected":
                    raise
                return check
            except Exception:
                return check
        elif check == "judge":
            if not can_call():
                return "deadline"
            options = config["judge"]
            try:
                with excluding_gemini(options["model"]):
                    judge = call(judge_payload(options["model"], payload, body))
                try:
                    if judge.status_code < 400 and not judge_passes(_body(judge), options["min_score"]):
                        return check
                finally:
                    judge.close()
            except APIError as error:
                if (error.payload or {}).get("error") == "secret_detected":
                    raise
                # The judge is advisory; an unavailable judge never blocks an answer.
            except Exception:
                pass
        elif not local_check(check, body, payload, response.status_code):
            return check
    return None


def dispatch_cascade(payload, dispatch, *, timeout=120):
    config = CascadeService.get_route(payload.get("model"))
    if config is None:
        raise APIError(f"Cascade not found: {payload.get('model')}", 404)
    user = getattr(g, "authenticated_user", None) or {}
    if not model_allowed(user, config["name"]):
        raise APIError("This API key is not allowed to use this cascade", 403, {"error": "model_not_allowed"})
    if "routing" in payload:
        raise APIError("Cascades do not accept intelligence routing overrides", 400)
    if payload.get("n", 1) != 1:
        raise APIError("Cascades support one answer per request", 400)
    started = getattr(g, "request_started_at", None) or time.perf_counter()
    remaining = max(0.01, min(float(timeout), 600) - (time.perf_counter() - started))
    deadline = time.monotonic() + remaining
    previous_deadline = getattr(g, "cascade_deadline", None)
    g.cascade_deadline = deadline
    skip_first_rate = getattr(g, "usage_context", None) is not None
    release_outer_accounting()
    skipped, best = [], None
    best_rank = -1
    estimate = 1.0
    first = True

    def can_call():
        return deadline - time.monotonic() >= estimate

    def call(body):
        nonlocal first, estimate
        before = time.monotonic()
        skip_rate = first and skip_first_rate
        first = False
        response = accounted_dispatch(body, lambda value: dispatch(value, max(0.01, deadline - time.monotonic())),
                                      kind="chat", skip_rate=skip_rate)
        estimate = max(1.0, time.monotonic() - before)
        return response

    try:
        for position, tier in enumerate(config["tiers"], 1):
            if best is not None and not can_call():
                skipped.append(f"{position}:deadline")
                break
            final = position == len(config["tiers"])
            body_payload = _tier_payload(payload, tier, final)
            try:
                response = call(body_payload)
            except APIError as error:
                if (error.payload or {}).get("error") == "secret_detected":
                    raise
                skipped.append(f"{position}:admission" if error.status_code in {402, 403, 429} else f"{position}:complete")
                if best is not None and error.status_code in {402, 429}:
                    break
                if final and best is None:
                    raise
                continue
            except Exception:
                skipped.append(f"{position}:complete")
                if final and best is None:
                    raise
                continue
            selected = _selected(response, tier["model"])
            if not tier["model"].startswith(("auto:", "free:")):
                RouteHealth.record(selected, ok=response.status_code < 400,
                                   outcome="ok" if response.status_code < 400 else "error")
            if final:
                if best is not None:
                    best[0].close()
                return _result(response, payload, position, len(config["tiers"]), selected, skipped)
            body = _body(response)
            failure = "complete" if response.status_code >= 400 or body is None or body.get("error") else None
            if failure is None:
                try:
                    failure = _checks(config, body, body_payload, response, call, can_call)
                except (ValueError, TypeError, RecursionError):
                    failure = "complete"
                except Exception:
                    response.close()
                    raise
                # Tool repair must be reflected in the answer, including SSE replay.
                response.set_data(json.dumps(body, ensure_ascii=False))
            if failure is None:
                if best is not None:
                    best[0].close()
                return _result(response, payload, position, len(config["tiers"]), selected, skipped)
            skipped.append(f"{position}:{failure}")
            usable = local_check("complete", body, body_payload, response.status_code) or (
                response.status_code < 400 and choice_message(body)[0].get("finish_reason") == "length"
                and bool(choice_message(body)[1].get("content")))
            rank = config["checks"].index(failure) if failure in config["checks"] else len(config["checks"]) if failure == "deadline" else -1
            if best is None or usable and rank >= best_rank:
                best_rank = rank
                if best is not None:
                    best[0].close()
                best = (response, position, selected)
            else:
                response.close()
            if failure == "deadline":
                break
        if best is None:
            raise APIError("No permitted cascade tier is available", 503)
        response, position, selected = best
        return _result(response, payload, position, len(config["tiers"]), selected, skipped)
    except Exception:
        if best is not None:
            best[0].close()
        raise
    finally:
        g.cascade_deadline = previous_deadline


def validate_cascade_target(app, auth, model, proxy):
    from routes.unified import validate_unified_chat_target
    config = CascadeService.get_route(model)
    if config is None:
        raise APIError(f"Cascade not found: {model}", 404)
    for tier in config["tiers"]:
        try:
            if tier["model"] == "auto:intelligence":
                from routes.intelligence import load_policy
                policy = load_policy()
                if any(model_allowed(getattr(g, "authenticated_user", {}) or {}, candidate["model"])
                       for candidate in policy["candidates"]):
                    return "cascade"
                continue
            if tier["model"].startswith("free:"):
                from services.free_model_policy import FREE_MODELS
                if tier["model"] in FREE_MODELS:
                    return "cascade"
                continue
            validate_unified_chat_target(app, auth, tier["model"], proxy)
            return "cascade"
        except (APIError, ValueError, GatewayError):
            continue
    raise APIError(f"No configured provider is available for cascade: {model}", 503)


def dispatch_unified_cascade(app, auth, metrics, proxy, payload, **options):
    from routes.unified import dispatch_unified_chat_completion
    timeout = options.pop("request_timeout", None) or app.config.get("REQUEST_TIMEOUT", 120)
    if isinstance(timeout, (list, tuple)):
        timeout = sum(timeout)
    return dispatch_cascade(payload, lambda body, remaining: app.make_response(dispatch_unified_chat_completion(
        app, auth, metrics, proxy, body, request_timeout=(min(5, remaining / 2), remaining / 2), **options)), timeout=timeout)


def register_cascade_admin_routes(app, login_required, auth):
    @app.route("/admin/cascades", methods=["GET", "PUT"])
    @login_required
    def admin_cascades():
        user = auth.get_current_user()
        if not user or not user.get("is_admin"):
            raise APIError("Only admin users can edit cascades", 403)
        if request.method == "PUT":
            try:
                CascadeService.save_route(request.get_json(silent=True), app.config["API_BASE_URLS"])
            except ValueError as error:
                raise APIError(str(error), 400) from error
        return jsonify({"cascades": CascadeService.list_routes()})
