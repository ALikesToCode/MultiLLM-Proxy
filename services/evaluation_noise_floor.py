"""Opt-in three-arm comparisons and seeded, paired noise-floor statistics."""

import hashlib
import logging
import os
import random
import time
from statistics import mean

from services.shadow_eval_contract import encoded
from services.shadow_eval_judge import judge_payload, outcome, parse_judgment, tool_validity

CALL_UNITS = 9
MIN_SAMPLES = 30
DEFAULT_DRAWS = 1000
MAX_DRAWS = 5000
PAIRS = (("ab", 0, 1), ("ac", 0, 2), ("bc", 1, 2))
SCORES = {"win": 1, "loss": -1, "tie": 0}
logger = logging.getLogger(__name__)


def enabled():
    return os.environ.get("SHADOW_EVAL_NOISE_FLOOR_ENABLED", "").lower() == "true"


def run_options(value):
    if not isinstance(value, dict) or set(value) - {"three_arm", "seed", "bootstrap_draws"}:
        raise ValueError("Unknown three-arm run option")
    if value.get("three_arm") is not True:
        raise ValueError("three_arm must be true")
    seed = value.get("seed", 0)
    draws = value.get("bootstrap_draws", DEFAULT_DRAWS)
    if type(seed) is not int or not 0 <= seed < 2**32:
        raise ValueError("seed must be an integer between 0 and 4294967295")
    if type(draws) is not int or not 1 <= draws <= MAX_DRAWS:
        raise ValueError("bootstrap_draws must be between 1 and 5000")
    return {"three_arm": True, "seed": seed, "bootstrap_draws": draws}


def judge_orders(sample_id, seed):
    digest = hashlib.sha256(f"{seed}:{sample_id}".encode()).digest()
    return tuple((bool(digest[index] & 1), not bool(digest[index] & 1)) for index in range(3))


def claim(store, sample, candidate, config, run_id, identifier):
    # The fixed SQL reserves the entire comparison inside the existing transaction/batch.
    return store._call("claim_three_arm", sample_id=sample["id"], candidate=candidate,
                       config=encoded(config), run_id=run_id, id=identifier)


def _empty_result(sample, candidate, config, options, run_id):
    repeat = {"model": sample["production_model"], "latency_ms": 0, "usage": {}, "cost": None, "tool_validity": None}
    return {"sample_id": sample["id"], "task_type": sample["task_type"], "candidate_model": candidate,
        "candidate_route": candidate, "production_model": sample["production_model"], "outcome": "failed",
        "judge_model": config["judge_model"], "latencies": {"production": 0, "candidate": 0, "judges": []},
        "usage": {"production": {}, "candidate": {}, "judges": []},
        "costs": {"production": None, "candidate": None, "judges": []}, "tool_validity": None,
        "noise_floor": {"version": 1, "run_id": run_id, "seed": options["seed"],
            "bootstrap_draws": options["bootstrap_draws"], "completed_arms": 0,
            "candidate_first": [pair[0] for pair in judge_orders(sample["id"], options["seed"])],
            "pairs": {name: None for name, _, _ in PAIRS}, "repeat": repeat}}


def _record_arm(result, index, response, sample):
    result["noise_floor"]["completed_arms"] += 1
    if index == 1:
        result["noise_floor"]["repeat"] = {name: response[source] for name, source in
            (("model", "model"), ("latency_ms", "latency_ms"), ("usage", "usage"), ("cost", "cost"))}
        result["noise_floor"]["repeat"]["tool_validity"] = tool_validity(response["answer"], sample)
        return
    side = "production" if index == 0 else "candidate"
    result[f"{side}_model"] = response["model"]
    for target, source in (("latencies", "latency_ms"), ("usage", "usage"), ("costs", "cost")):
        result[target][side] = response[source]


def _judge_pairs(result, arms, sample, config, dispatch, deadline, call):
    for index, (name, baseline, candidate) in enumerate(PAIRS):
        view = {**sample, "production_answer": arms[baseline]["answer"]}
        first = result["noise_floor"]["candidate_first"][index]
        judgments = []
        for order in (first, not first):
            if time.monotonic() >= deadline:
                return False
            judged = call(judge_payload(config["judge_model"], view, arms[candidate]["answer"], order), dispatch, judge=True)
            for target, source in (("latencies", "latency_ms"), ("usage", "usage"), ("costs", "cost")):
                result[target]["judges"].append(judged[source])
            judgments.append(parse_judgment(judged["answer"].get("content")))
        result["noise_floor"]["pairs"][name] = outcome(judgments[0], judgments[1], first)
    return True


def evaluate_three_arm(sample, candidate, config, dispatch, *, deadline, options, run_id, call):
    from services.shadow_eval_runner import replay_payload

    result = _empty_result(sample, candidate, config, options, run_id)
    arms = []
    try:
        for index, model in enumerate((sample["production_model"], sample["production_model"], candidate)):
            if time.monotonic() >= deadline:
                return result
            response = call(replay_payload(sample, model), dispatch)
            arms.append(response)
            _record_arm(result, index, response, sample)
            if index < 2 and response["model"] != sample["production_model"]:
                return result
            # All three arms need complete output under the same retained request limits.
            if response.get("finish_reason") in {"length", "content_filter"}:
                if index == 2:
                    result.update(outcome="candidate_truncated", candidate_truncated=True)
                return result
        if arms[2]["model"] == arms[0]["model"]:
            result["outcome"] = "same_model"
            return result
        validity = tool_validity(arms[0]["answer"], sample)
        if validity is not None:
            result["tool_validity"] = {"production": validity, "candidate": tool_validity(arms[2]["answer"], sample)}
        if _judge_pairs(result, arms, sample, config, dispatch, deadline, call):
            pairs = result["noise_floor"]["pairs"]
            result["outcome"] = pairs["ac"] if pairs["ac"] == pairs["bc"] else "tie"
    except Exception as error:
        logger.warning("Three-arm comparison failed (%s)", type(error).__name__)
    return result


def _cohorts(results):
    groups = {}
    for result in results:
        noise = result.get("noise_floor")
        if not noise or result.get("candidate_truncated") or result["outcome"] not in SCORES:
            continue
        if (noise["completed_arms"] != 3 or len(result["usage"]["judges"]) != 6
                or noise["repeat"]["model"] != result["production_model"]
                or result["candidate_model"] == result["production_model"]
                or any(value not in SCORES for value in noise["pairs"].values())):
            continue
        validity = result.get("tool_validity")
        repeat_validity = noise["repeat"]["tool_validity"]
        if (validity and any(value["invalid"] for value in validity.values())) or (repeat_validity and repeat_validity["invalid"]):
            continue
        key = (result["task_type"], result["candidate_route"], result["candidate_model"], result["production_model"],
               noise["seed"], noise["bootstrap_draws"])
        # An observation never gains statistical weight from duplicate exports.
        groups.setdefault(key, {})[result["sample_id"]] = noise["pairs"]
    return groups


def _interval(values):
    values = sorted(values)
    last = len(values) - 1
    return [round(values[int(last * .025)], 6), round(values[int(last * .975)], 6)]


def _statistics(key, records):
    task, route, model, baseline, seed, draws = key
    pairs = sorted(records.items())
    effects = [(SCORES[pair["ac"]] + SCORES[pair["bc"]]) / 2 for _, pair in pairs]
    floors = [abs(SCORES[pair["ab"]]) for _, pair in pairs]
    adjusted = [effect - floor for effect, floor in zip(effects, floors)]
    # Resample paired samples, keeping C effects and A/B variation together.
    # This generator controls reproducible statistics, never security tokens.
    rng = random.Random(seed)  # nosec B311
    count = len(pairs)
    bootstraps = [mean(rng.choices(adjusted, k=count)) for _ in range(draws)]
    interval = _interval(bootstraps)
    return {"task_type": task, "candidate_route": route, "candidate_model": model, "baseline_model": baseline,
        "seed": seed, "bootstrap_draws": draws, "sample_count": count, "minimum_samples": MIN_SAMPLES,
        "effect": round(mean(effects), 6), "noise_floor": round(mean(floors), 6), "adjusted_ci": interval,
        "eligible": count >= MIN_SAMPLES and draws >= DEFAULT_DRAWS and interval[0] > 0,
        "evidence_revision": hashlib.sha256(encoded(pairs).encode()).hexdigest()}


def summarize(results):
    return [_statistics(key, records) for key, records in sorted(_cohorts(results).items())]


def annotate_league(rows, results):
    summaries = summarize(results)
    affected = {(result["task_type"], result[f"{side}_model"]) for result in results if "noise_floor" in result
                for side in ("candidate", "production")}
    for row in rows:
        cohorts = [item for item in summaries if item["task_type"] == row["task_type"]
                   and row["model"] in {item["candidate_model"], item["baseline_model"]}]
        if (row["task_type"], row["model"]) in affected:
            row["noise_floor"] = {"eligible": bool(cohorts) and all(item["eligible"] for item in cohorts), "cohorts": cohorts,
                "role": "candidate" if any(item["candidate_model"] == row["model"] for item in cohorts) else "baseline"}
    return rows


def reviewable(row):
    return row["sample_count"] >= 20 and row.get("noise_floor", {}).get("eligible", True)
