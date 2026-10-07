"""Bounded background replays under an independent, accounted evaluation principal."""

import logging
import os
import threading
import time
import uuid

from flask import g

from services.accounted_dispatch import accounted_dispatch
from services.intelligence_store import IntelligenceStore
from services.judge_routing import excluding_gemini
from services.request_accounting import price
from services.shadow_eval_contract import TASKS, clean_usage, encoded, finite
from services.shadow_eval_judge import judge_payload, outcome, parse_judgment, random_order, tool_validity
from services.shadow_eval_store import ShadowEvalStore

PRINCIPAL = "internal:shadow-evaluation"
logger = logging.getLogger(__name__)
_RUN_LOCK = threading.Lock()
RUN_SECONDS = 240


def evaluation_principal():
    user = {"username": PRINCIPAL, "is_admin": False, "scopes": ["chat", "models"], "shadow_eval_rate": None}
    for period in ("daily", "monthly"):
        value = os.environ.get(f"SHADOW_EVAL_{period.upper()}_BUDGET_USD")
        if value is not None:
            amount = float(value)
            if not finite(amount):
                raise ValueError("Invalid evaluation budget")
            user[f"{period}_budget_usd"] = amount
    return user


def _cost(model, usage):
    if not usage:
        return None
    return price([model], usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0), 1)


def call(payload, dispatch, *, judge=False):
    response = None
    started = time.monotonic()
    try:
        # Both replay and judge go through normal admission and one ledger row.
        with excluding_gemini(payload["model"] if judge else ""):
            response = accounted_dispatch(payload, dispatch, kind="chat")
        if response.status_code >= 400 or response.is_streamed or len(response.get_data()) > 131072:
            raise ValueError("Evaluation call failed")
        body = response.get_json()
        answer = body["choices"][0]["message"]
        if not isinstance(answer, dict) or len(encoded(answer).encode()) > 32768:
            raise ValueError("Invalid evaluation answer")
        model = response.headers.get("X-MultiLLM-Auto-Selected-Model") or (body.get("multillm") or {}).get("selected_model") or payload["model"]
        usage = clean_usage(body.get("usage"))
        return {"answer": answer, "model": model, "usage": usage, "cost": _cost(model, usage),
                "latency_ms": round((time.monotonic() - started) * 1000),
                "finish_reason": body["choices"][0].get("finish_reason")}
    finally:
        if response is not None:
            response.close()


def replay_payload(sample, candidate):
    tokens = sample["usage"].get("completion_tokens")
    cap = max(1024, min(8192, 2 * tokens)) if type(tokens) is int else 8192
    payload = dict(sample["request"])
    for name in ("max_tokens", "max_completion_tokens"):
        limit = payload.pop(name, None)
        if type(limit) is int and limit > 0:
            cap = min(cap, limit)
    return {**payload, "model": candidate, "stream": False, "max_completion_tokens": cap}


def evaluate(sample, candidate, config, dispatch, *, deadline):
    result = {"sample_id": sample["id"], "task_type": sample["task_type"], "candidate_model": candidate,
        "candidate_route": candidate, "production_model": sample["production_model"], "outcome": "failed",
        "judge_model": config["judge_model"], "latencies": {"production": sample["latency_ms"], "candidate": 0, "judges": []},
        "usage": {"production": sample["usage"], "candidate": {}, "judges": []},
        "costs": {"production": _cost(sample["production_model"], sample["usage"]), "candidate": None, "judges": []},
        "tool_validity": None}
    try:
        candidate_call = call(replay_payload(sample, candidate), dispatch)
        result["candidate_model"] = candidate_call["model"]
        for target, source in (("latencies", "latency_ms"), ("usage", "usage"), ("costs", "cost")):
            result[target]["candidate"] = candidate_call[source]
        if candidate_call["model"] == sample["production_model"]:
            result["outcome"] = "same_model"
            return result
        if candidate_call.get("finish_reason") == "length" and sample.get("production_finish_reason") != "length":
            result["candidate_truncated"] = True
            result["outcome"] = "candidate_truncated"
            return result
        production_validity = tool_validity(sample["production_answer"], sample)
        if production_validity is not None:
            result["tool_validity"] = {"production": production_validity, "candidate": tool_validity(candidate_call["answer"], sample)}
        candidate_first = random_order()
        judgments = []
        for first in (candidate_first, not candidate_first):
            if time.monotonic() >= deadline:
                return result
            judged = call(judge_payload(config["judge_model"], sample, candidate_call["answer"], first), dispatch, judge=True)
            for target, source in (("latencies", "latency_ms"), ("usage", "usage"), ("costs", "cost")):
                result[target]["judges"].append(judged[source])
            judgments.append(parse_judgment(judged["answer"].get("content")))
        result["outcome"] = outcome(judgments[0], judgments[1], candidate_first)
    except Exception as error:
        logger.warning("Shadow comparison failed (%s)", type(error).__name__)
    return result


def run(app, dispatch, *, store=ShadowEvalStore):
    from services.intelligence_policy import validate_policy

    run_id = uuid.uuid4().hex
    leased = False
    count = 0
    try:
        config = store.config()
        store.cleanup()
        if not config["enabled"] or not store.lease(run_id):
            return 0
        leased = True
        deadline = time.monotonic() + RUN_SECONDS
        try:
            billing = {item["model"]: item["billing"] for item in validate_policy(IntelligenceStore.policy())["candidates"]}
        except Exception:
            billing = {}
        g.authenticated_user = evaluation_principal()
        g.shadow_eval_internal = True
        g.usage_context = None
        work = [(task, model) for task in TASKS for model in config["candidate_models"][task]]
        # Preserve the operator's order within each billing class.
        work.sort(key=lambda item: billing.get(item[1]) not in {"free", "subscription"})
        for _ in range(config["max_replays_per_run"]):
            progressed = False
            for task, model in work:
                if count >= config["max_replays_per_run"] or time.monotonic() >= deadline:
                    return count
                sample = store.pending(task, model)
                if not sample:
                    continue
                identifier = uuid.uuid4().hex
                if not store.claim(sample, model, config, run_id, identifier):
                    return count
                count += 1
                progressed = True
                store.finish(identifier, evaluate(sample, model, config, dispatch, deadline=deadline))
            if not progressed:
                break
    except Exception as error:
        logger.warning("Shadow run unavailable (%s)", type(error).__name__)
    finally:
        if leased:
            try:
                store.release(run_id)
            except Exception as error:
                logger.warning("Shadow run lease release unavailable (%s)", type(error).__name__)
    return count


def start_run(app, dispatch):
    if not _RUN_LOCK.acquire(blocking=False):
        return False

    def background():
        try:
            # A fresh request context prevents sampled/admin identity and headers leaking into calls.
            with app.test_request_context("/admin/shadow-eval/run", method="POST", json={}):
                run(app, dispatch)
        finally:
            _RUN_LOCK.release()
    try:
        threading.Thread(target=background, name="shadow-evaluation", daemon=True).start()
    except Exception:
        _RUN_LOCK.release()
        raise
    return True
