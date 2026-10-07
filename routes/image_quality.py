"""Generate, judge and selectively retry images without crossing provider boundaries."""

import json
import logging
from functools import partial

from flask import Response, g, request

from error_handlers import APIError
from routes.media_images import _image_count, _read, run_image_tasks
from services import key_controls
from services.accounted_dispatch import accounted_dispatch, release_outer_accounting
from services.auto_route_service import AutoRouteService
from services.free_model_policy import validate_free_payload
from services.image_quality import (
    MAX_PROMPT_CHARS, QA_HEADER, expected_text, image_source, judge_payload, parse_grade, parse_options,
)
from services.media_catalog import DEFAULT_IMAGE_QUALITY, prepare_image_payload

logger = logging.getLogger(__name__)


def validate_judge(options, validate_target) -> None:
    if not key_controls.model_allowed(getattr(g, "authenticated_user", None) or {}, options.judge_model):
        raise APIError("This API key is not allowed to use quality_check.judge_model", 403)
    if options.judge_model.startswith("free:"):
        validate_free_payload(judge_payload(options, "test", "data:image/png;base64,aW1hZ2U="))
    else:
        try:
            validate_target(options.judge_model)
        except ValueError as error:
            raise APIError("quality_check.judge_model must be a valid chat model ID", 400) from error


def _judge(entry, model, prompt, options, dispatch) -> tuple[dict, str]:
    quality = {"score": None, "passed": False, "issues": [], "judge_model": options.judge_model}
    expected = expected_text(prompt)
    if expected:
        quality["text_similarity"] = None
    response = None
    previous_exclusion = getattr(g, "image_qa_exclude_gemini", False)
    g.image_qa_exclude_gemini = options.judge_model.startswith(("free:", "auto:"))
    try:
        source, signed_url = image_source(entry, model)
        if signed_url:
            quality["judge_image_source"] = "signed_url"
        response = accounted_dispatch(judge_payload(options, prompt, source), dispatch, kind="chat")
        if response.status_code >= 400:
            raise ValueError("judge_unavailable")
        raw = response.get_data()
        if len(raw) > 64 * 1024:
            raise ValueError("judge_response_too_large")
        body = json.loads(raw)
        grade = parse_grade(body["choices"][0]["message"]["content"], expected)
        quality.update(score=grade["score"], passed=grade["score"] >= options.min_score, issues=grade["issues"])
        if expected:
            quality["text_similarity"] = grade["text_similarity"]
        return quality, grade["fix_instructions"] or "; ".join(grade["issues"])[:300]
    except Exception as error:
        # Never expose judge/provider bodies, which may contain sensitive content.
        quality["judge_error"] = "judge_error"
        if isinstance(error, APIError) and error.status_code in (402, 403, 429, 503):
            quality["stopped_reason"] = (error.payload or {}).get("error", "judge_unavailable")
        logger.warning("Image judge failed (%s)", type(error).__name__)
        return quality, ""
    finally:
        g.image_qa_exclude_gemini = previous_exclusion
        if response is not None:
            response.close()


def _retry_payload(payload, model, prompt, fixes):
    retry = {**payload, "model": model, "prompt": prompt + ("\n\nAvoid: " + fixes[:300] if fixes else ""), "n": 1}
    if AutoRouteService.is_auto_route(payload.get("model")):
        provider, provider_model = model.split(":", 1)
        retry = prepare_image_payload(provider, provider_model, retry)
    return retry


def _one_image(payload, options, generate, judge, skip_rate, image_index):
    first = _read(accounted_dispatch(payload, partial(generate, image_index=image_index, attempt_number=0),
                                      kind="images", skip_rate=skip_rate))
    if first["status"] >= 400 or not first["body"]:
        return first
    entries = first["body"].get("data") or []
    if not entries or not isinstance(entries[0], dict):
        return first
    model = first["headers"].get("X-MultiLLM-Auto-Selected-Model") or payload["model"]
    prompt, attempts = payload["prompt"], 1
    best = entries[0]
    quality, fixes = _judge(best, model, prompt, options, judge)
    while not quality["passed"] and "judge_error" not in quality and attempts < options.max_attempts:
        if AutoRouteService.is_auto_route(model):
            quality["stopped_reason"] = "selected_model_unavailable"
            break
        try:
            retry = _read(accounted_dispatch(
                _retry_payload(payload, model, prompt, fixes),
                partial(generate, image_index=image_index, attempt_number=attempts), kind="images"))
        except APIError as error:
            quality["stopped_reason"] = (error.payload or {}).get("error", "generation_refused")
            break
        except Exception:
            quality["stopped_reason"] = "generation_error"
            break
        attempts += 1
        images = (retry["body"] or {}).get("data") or []
        if retry["status"] >= 400 or not images or not isinstance(images[0], dict):
            quality["stopped_reason"] = "generation_refused"
            break
        candidate_quality, fixes = _judge(images[0], model, prompt, options, judge)
        if "judge_error" in candidate_quality:
            quality["stopped_reason"] = candidate_quality.get("stopped_reason", "judge_error")
            break
        if candidate_quality["score"] > quality["score"]:
            best, quality = images[0], candidate_quality
        if candidate_quality["passed"]:
            break
    quality["attempts"] = attempts
    first["body"]["data"] = [{**best, "quality": quality}]
    return first


def qa_header(images: list) -> str | None:
    qualities = [entry["quality"] for entry in images if isinstance(entry, dict) and isinstance(entry.get("quality"), dict)]
    if not qualities:
        return None
    scores = [value["score"] for value in qualities if value.get("score") is not None]
    return f"attempts={sum(value['attempts'] for value in qualities)} best={max(scores) if scores else 'unknown'}"


def dispatch_image_quality(payload, generate, judge, validate_target, *, request_headers=None):
    headers = request.headers if request_headers is None else request_headers
    header = next((value for name, value in headers.items() if name.lower() == QA_HEADER.lower()), None)
    options = parse_options(payload, header)
    clean = {name: value for name, value in payload.items() if name != "quality_check"}
    if options is None:
        return generate(clean)
    count = _image_count(clean)
    prompt = clean.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > MAX_PROMPT_CHARS:
        raise APIError(f"quality_check needs a prompt of at most {MAX_PROMPT_CHARS} characters", 400)
    validate_judge(options, validate_target)
    if AutoRouteService.is_auto_route(clean.get("model")):
        clean.setdefault("quality", DEFAULT_IMAGE_QUALITY)
    skip_first_rate = getattr(g, "usage_context", None) is not None
    release_outer_accounting()
    def pipeline(index):
        try:
            return _one_image({**clean, "n": 1}, options, generate, judge, skip_first_rate and index == 0, index)
        except APIError as error:
            result = {"status": error.status_code, "body": {"error": error.to_dict()}, "headers": {}}
            if error.status_code in (402, 403, 429, 503):
                result["stopped_reason"] = (error.payload or {}).get("error", "generation_refused")
            return result

    results = run_image_tasks([partial(pipeline, index) for index in range(count)], read_response=False)
    succeeded = [result for result in results if result["status"] < 400 and result["body"]]
    if not succeeded:
        result = results[-1]
        return Response(json.dumps(result["body"]), status=result["status"], content_type="application/json")
    body = dict(succeeded[0]["body"])
    body["data"] = [image for result in succeeded for image in result["body"].get("data", [])]
    errors = [{"index": index, "error": result["body"].get("error"),
               **({"stopped_reason": result["stopped_reason"]} if "stopped_reason" in result else {})}
              for index, result in enumerate(results) if result["status"] >= 400]
    if errors:
        body["errors"] = errors
    response = Response(json.dumps(body), content_type="application/json")
    for name, value in succeeded[0]["headers"].items():
        response.headers[name] = value
    response.headers[QA_HEADER] = qa_header(body["data"]) or "attempts=0 best=unknown"
    if count > 1:
        response.headers["X-MultiLLM-Images-Requested"] = str(count)
        response.headers["X-MultiLLM-Images-Returned"] = str(len(body["data"]))
        response.headers["X-MultiLLM-Auto-Selected-Models"] = ",".join(dict.fromkeys(
            result["headers"].get("X-MultiLLM-Auto-Selected-Model", clean["model"]) for result in succeeded))
    return response
