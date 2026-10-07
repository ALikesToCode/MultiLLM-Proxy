"""Bounded shadow evaluation configuration and privacy-preserving sample contract."""

import json
import math
import os
import re
import time
import uuid

from services.secret_scan import scan_payload

TASKS = ("coding", "extraction", "writing", "reasoning", "chat")
REQUEST_BYTES = 65536
ANSWER_BYTES = 32768
SAMPLE_TTL = 7 * 86400
MAX_SAMPLES = 2000
MAX_RESULTS = 10000
MODEL = re.compile(r"[a-z][a-z0-9-]{0,31}:[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,223}\Z")
ID = re.compile(r"[0-9a-f]{32}\Z")
REQUEST_FIELDS = ("messages", "tools", "tool_choice", "response_format")


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False, sort_keys=True)


def default_config():
    return {"enabled": False, "candidate_models": {task: [] for task in TASKS},
            "judge_model": os.environ.get("SHADOW_EVAL_JUDGE_MODEL") or "free:json",
            "max_replays_per_run": 3, "daily_cap": 50}


def validate_config(value):
    defaults = default_config()
    if not isinstance(value, dict) or set(value) != set(defaults) or type(value["enabled"]) is not bool:
        raise ValueError("Invalid shadow evaluation config")
    for field, maximum in (("max_replays_per_run", 20), ("daily_cap", 500)):
        if type(value[field]) is not int or not 1 <= value[field] <= maximum:
            raise ValueError(f"{field} must be between 1 and {maximum}")
    if not isinstance(value["judge_model"], str) or not MODEL.fullmatch(value["judge_model"]):
        raise ValueError("Invalid judge model")
    candidates = value["candidate_models"]
    if not isinstance(candidates, dict) or set(candidates) != set(TASKS):
        raise ValueError("Candidate models must name every shadow task type")
    for models in candidates.values():
        if (not isinstance(models, list) or len(models) > 8
                or any(not isinstance(model, str) or not MODEL.fullmatch(model) for model in models)
                or len(set(models)) != len(models)):
            raise ValueError("Use at most eight distinct model IDs per task")
        if any(model.startswith(("free:", "roleplay:", "knowledge:")) for model in models):
            raise ValueError("Candidates require provider:model, auto: or cascade: IDs")
    return json.loads(encoded(value))


def task_type(payload):
    text = encoded(payload.get("messages", []))
    if payload.get("tools") or "```" in text:
        return "coding"
    response_format = payload.get("response_format") or {}
    if isinstance(response_format, dict) and response_format.get("type") in {"json_object", "json_schema"}:
        return "extraction"
    if re.search(r"\b(essay|article|long[ -]form|write.{0,30}(story|report|chapter)|draft.{0,30}(report|article))\b", text, re.I):
        return "writing"
    if re.search(r"\b(math|calculate|solve|prove|step.by.step|reason through)\b|\d+\s*[+*/=]\s*\d+", text, re.I):
        return "reasoning"
    return "chat"


def eligible(payload, user, path, *, random_value):
    model = payload.get("model")
    rate = user.get("shadow_eval_rate")
    return (path in {"/v1/chat/completions", "/v1/responses", "/intelligence/v1/chat/completions"}
            and isinstance(payload.get("messages"), list)
            and ((isinstance(model, str) and model.startswith(("auto:", "cascade:")))
                 or path == "/intelligence/v1/chat/completions" or "routing" in payload)
            and type(rate) in (int, float) and 0 < rate <= 0.2 and random_value < rate)


def make_sample(payload, user, route, answer, model, latency_ms, usage, *, now=None):
    request = {name: payload[name] for name in REQUEST_FIELDS if name in payload}
    answer = {name: answer[name] for name in ("content", "tool_calls") if name in answer}
    if (len(encoded(request).encode()) > REQUEST_BYTES or len(encoded(answer).encode()) > ANSWER_BYTES
            or not isinstance(model, str) or not MODEL.fullmatch(model)):
        return None
    # Scan the entire request, including fields omitted from persisted replay data.
    for value in (payload, answer):
        report = scan_payload(value)
        if report["high"] or report["truncated"]:
            return None
    return {"id": uuid.uuid4().hex, "created_at": time.time() if now is None else now,
            "key_id": str(user.get("username") or user.get("id") or "")[:128],
            "route": route, "task_type": task_type(payload), "request": request,
            "production_model": model, "production_answer": answer,
            "latency_ms": min(86400000, max(0, round(latency_ms))), "usage": clean_usage(usage)}


def clean_usage(value):
    if not isinstance(value, dict):
        return {}
    return {name: value[name] for name in ("prompt_tokens", "completion_tokens", "total_tokens")
            if type(value.get(name)) is int and 0 <= value[name] <= 2**31 - 1}


def finite(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def valid_sample(value, now):
    return (isinstance(value, dict) and set(value) == {"id", "created_at", "key_id", "route", "task_type",
            "request", "production_model", "production_answer", "latency_ms", "usage"}
            and isinstance(value["id"], str) and bool(ID.fullmatch(value["id"]))
            and finite(value["created_at"]) and now - SAMPLE_TTL < value["created_at"] <= now + 60
            and isinstance(value["key_id"], str) and 0 < len(value["key_id"]) <= 128
            and isinstance(value["route"], str) and bool(MODEL.fullmatch(value["route"]))
            and value["route"].startswith(("auto:", "cascade:")) and value["task_type"] in TASKS
            and isinstance(value["request"], dict) and not set(value["request"]) - set(REQUEST_FIELDS)
            and isinstance(value["request"].get("messages"), list)
            and len(encoded(value["request"]).encode()) <= REQUEST_BYTES
            and isinstance(value["production_answer"], dict)
            and not set(value["production_answer"]) - {"content", "tool_calls"}
            and len(encoded(value["production_answer"]).encode()) <= ANSWER_BYTES
            and isinstance(value["production_model"], str) and bool(MODEL.fullmatch(value["production_model"]))
            and finite(value["latency_ms"]) and value["latency_ms"] <= 86400000
            and value["usage"] == clean_usage(value["usage"]))
