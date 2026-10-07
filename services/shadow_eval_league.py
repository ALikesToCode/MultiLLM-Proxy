"""Deterministic Elo, content-free exports and reviewed policy proposals."""

import copy
import hashlib
from statistics import mean, median

from services.shadow_eval_contract import encoded


# Anchor Elo differences to existing absolute policy scores (100 Elo = 10 points).
SCORE_PER_ELO = 0.1
# Limit one reviewed update to 15 points from an existing task score.
MAX_STEP = 15


def league(results):
    rows = {}
    for result in sorted(results, key=lambda value: (value.get("_created_at", 0), value.get("_id", ""))):
        if result.get("candidate_truncated") or result["outcome"] not in {"win", "loss", "tie"} or result["candidate_model"] == result["production_model"]:
            continue
        task = result["task_type"]
        pair = []
        for side in ("candidate", "production"):
            model = result[f"{side}_model"]
            row = rows.setdefault((task, model), {"task_type": task, "model": model, "wins": 0, "losses": 0,
                "ties": 0, "sample_count": 0, "rating": 1500.0, "latencies": [], "costs": [],
                "tool_calls_checked": 0, "tool_calls_valid": 0, "tool_calls_invalid": 0})
            pair.append(row)
            row["sample_count"] += 1
            row["latencies"].append(result["latencies"][side])
            cost = result["costs"][side]
            if cost is not None:
                row["costs"].append(cost)
            validity = result.get("tool_validity")
            if validity:
                for name in ("checked", "valid", "invalid"):
                    row[f"tool_calls_{name}"] += validity[side][name]
        score = {"win": 1, "loss": 0, "tie": 0.5}[result["outcome"]]
        expected = 1 / (1 + 10 ** ((pair[1]["rating"] - pair[0]["rating"]) / 400))
        change = 32 * (score - expected)
        for row, sign, actual in ((pair[0], 1, score), (pair[1], -1, 1 - score)):
            row["rating"] += sign * change
            row[{1: "wins", 0: "losses", 0.5: "ties"}[actual]] += 1
    for row in rows.values():
        row["rating"] = round(row["rating"], 2)
        row["median_latency_ms"] = median(row.pop("latencies"))
        costs = row.pop("costs")
        row["median_cost_usd"] = median(costs) if costs else None
    return sorted(rows.values(), key=lambda row: (row["task_type"], -row["rating"], row["model"]))


def proposal(policy, rows, auto_routes=()):
    from services.intelligence_policy import validate_policy

    policy = validate_policy(policy)
    updated = copy.deepcopy(policy)
    candidates = {candidate["model"]: candidate for candidate in updated["candidates"]}
    changes = []
    anchors = {}
    for task in {row["task_type"] for row in rows}:
        rated = [row for row in rows if row["task_type"] == task and row["sample_count"] >= 20]
        if not rated:
            continue
        scores = [candidates[row["model"]]["task_scores"][task] for row in rated
                  if row["model"] in candidates and task in candidates[row["model"]].get("task_scores", {})]
        anchors[task] = (mean(scores) if scores else 70, mean(row["rating"] for row in rated))
    for row in rows:
        candidate = candidates.get(row["model"])
        if row["sample_count"] < 20 or candidate is None:
            continue
        task = row["task_type"]
        anchor, mean_rating = anchors[task]
        score = min(100, max(0, round(anchor + (row["rating"] - mean_rating) * SCORE_PER_ELO)))
        previous = candidate.get("task_scores", {}).get(task)
        if previous is not None:
            score = min(previous + MAX_STEP, max(previous - MAX_STEP, score))
        if previous == score:
            continue
        candidate.setdefault("task_scores", {})[task] = score
        changes.append({"model": row["model"], "task_type": task, "from": previous, "to": score})
    updated = validate_policy(updated)
    orders = []
    for route in list(auto_routes)[:128]:
        for task in sorted({row["task_type"] for row in rows}):
            ratings = {row["model"]: row["rating"] for row in rows if row["task_type"] == task and row["sample_count"] >= 20}
            if not ratings or not all(model in ratings for model in route.candidates):
                continue
            order = sorted(route.candidates, key=lambda model: -ratings[model])
            if order != list(route.candidates):
                orders.append({"route": route.id, "task_type": task, "from": list(route.candidates), "to": order})
    document = {"policy_diff": changes, "suggested_auto_route_orders": orders, "policy": updated}
    document["revision"] = hashlib.sha256(encoded({"base": policy, **document}).encode()).hexdigest()
    return document


def result_counts(results):
    counts = {"judged": 0, "failed": 0, "same_model": 0, "candidate_truncated": 0}
    for result in results:
        if result.get("candidate_truncated") or result["outcome"] == "candidate_truncated":
            counts["candidate_truncated"] += 1
        elif result["outcome"] == "same_model" or result["candidate_model"] == result["production_model"]:
            counts["same_model"] += 1
        elif result["outcome"] in {"win", "loss", "tie"}:
            counts["judged"] += 1
        else:
            counts["failed"] += 1
    return counts
