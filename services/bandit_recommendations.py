"""Bounded, content-free evidence for reviewed route-order recommendations."""

import hashlib
import logging
import math
import os
import random
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Callable

from error_handlers import APIError
from services import auto_route_d1, config_snapshots, evaluation_noise_floor as noise_floor
from services.auto_route_service import DEFAULT_AUTO_ROUTES
from services.shadow_eval_contract import ID, MODEL, TASKS

MIN_SAMPLES = 50
MAX_CELLS = 1000
MAX_OBSERVATIONS = 10000
HALF_LIFE = 7 * 86400
RESULT_TTL = 90 * 86400
NONCE_TTL = 900
MAX_NONCES = 1000
POSTERIOR_DRAWS = 1000
logger = logging.getLogger(__name__)
_warned = False
_mode_lock = threading.Lock()


def mode():
    global _warned
    value = os.environ.get("BANDIT_MODE", "").strip().lower() or "off"
    if value in {"off", "shadow", "recommendation"}:
        return value
    with _mode_lock:
        if not _warned:
            logger.warning("Invalid BANDIT_MODE; route-order recommendations are off")
            _warned = True
    return "off"


def _number(value, minimum=0, maximum=None):
    try:
        return (type(value) in {int, float} and math.isfinite(value) and value >= minimum
                and (maximum is None or value <= maximum))
    except OverflowError:
        return False


def observation_id(sample_id, model):
    return hashlib.sha256(f"{sample_id}:{model}".encode()).hexdigest()[:32]


@dataclass(frozen=True)
class Observation:
    identifier: str
    task: str
    model: str
    timestamp: float
    quality: float | None
    cost: float | None
    noise_eligible: bool


def _cell(task, model, records, feedback, now, seed):
    count = len(records)
    weights = [2 ** (-(now - record.timestamp) / HALF_LIFE) for record in records]
    mass = sum(weights)
    qualities = [feedback.get(record.identifier, (record, record.quality))[1] for record in records]
    quality_count = sum(value is not None for value in qualities)
    cost_count = sum(record.cost is not None for record in records)
    known = count > 0 and quality_count == cost_count == count
    row = {"task_type": task, "model": model, "sample_count": count, "minimum_samples": MIN_SAMPLES,
           "decayed_samples": round(mass, 6), "feedback_count": sum(record.identifier in feedback for record in records),
           "coverage": {"quality": quality_count / count if count else 0, "cost": cost_count / count if count else 0},
           "quality_mean": None, "mean_cost_usd": None, "quality_ci": None, "utility_ci": None,
           "noise_eligible": all(record.noise_eligible for record in records), "eligible": False}
    if not known:
        return row
    successes = sum(weight * quality for weight, quality in zip(weights, qualities))
    costs = [record.cost for record in records]
    average_cost = sum(weight * cost for weight, cost in zip(weights, costs)) / mass
    if not math.isfinite(average_cost):
        return row
    # Cost penalties stay bounded even for very large valid monetary observations.
    penalties = [cost / (1 + cost) for cost in costs]
    penalty = sum(weight * cost for weight, cost in zip(weights, penalties)) / mass
    variance = sum(weight * (cost - penalty) ** 2 for weight, cost in zip(weights, penalties)) / mass
    error = 1.96 * math.sqrt(variance / mass)
    digest = hashlib.sha256(f"{seed}:{task}:{model}".encode()).digest()
    # Seeded statistical draws never generate authentication or feedback tokens.
    rng = random.Random(int.from_bytes(digest, "big"))  # nosec B311
    draws = sorted(rng.betavariate(1 + successes, 1 + mass - successes) for _ in range(POSTERIOR_DRAWS))
    lower, upper = draws[24], draws[974]
    cost_lower, cost_upper = max(0, penalty - error), min(1, penalty + error)
    row.update(quality_mean=round(successes / mass, 6), mean_cost_usd=average_cost,
               quality_ci=[round(lower, 6), round(upper, 6)],
               utility_ci=[round(lower - cost_upper, 6), round(upper - cost_lower, 6)],
               eligible=count >= MIN_SAMPLES and row["noise_eligible"])
    return row


class BanditRecommendations:
    """Trusted observation boundary; no provider, dispatch or policy-write methods."""

    def __init__(self, *, clock: Callable[[], float] | None = None) -> None:
        self.clock = clock or (lambda: time.time())
        self._observations: dict[str, Observation] = {}
        self._feedback: dict[str, tuple[Observation, float]] = {}
        self._nonces: dict[str, tuple[Observation, str, float]] = {}
        self._lock = threading.RLock()
        self._cell_keys: set[tuple[str, str]] = set()

    def _prune(self, now):
        self._observations = {key: value for key, value in self._observations.items()
                              if now - RESULT_TTL <= value.timestamp <= now}
        self._cell_keys = {(value.task, value.model) for value in self._observations.values()}
        self._feedback = {key: value for key, value in self._feedback.items()
                          if self._observations.get(key) == value[0]}
        self._nonces = {key: value for key, value in self._nonces.items()
                        if value[2] > now and self._observations.get(value[0].identifier) == value[0]}

    def observe(self, *, observation_id: str, task_type: str, model: str, observed_at: float,
                quality: float | None, cost_usd: float | None, trusted: bool = False,
                noise_eligible: bool = True) -> bool:
        now = self.clock()
        if (trusted is not True or not isinstance(observation_id, str) or not ID.fullmatch(observation_id)
                or task_type not in TASKS or not config_snapshots.safe_identifier(model, MODEL)
                or not _number(observed_at, now - RESULT_TTL, now)
                or quality is not None and not _number(quality, 0, 1)
                or cost_usd is not None and not _number(cost_usd)
                or type(noise_eligible) is not bool):
            return False
        with self._lock:
            if observation_id in self._observations or len(self._observations) >= MAX_OBSERVATIONS:
                return False
            if (task_type, model) not in self._cell_keys and len(self._cell_keys) >= MAX_CELLS:
                return False
            self._observations[observation_id] = Observation(observation_id, task_type, model, observed_at,
                                                           quality, cost_usd, noise_eligible)
            self._cell_keys.add((task_type, model))
        return True

    def replace_results(self, results):
        # Rebuild from the authoritative store, so purged or changed evidence cannot survive in a cache.
        with self._lock:
            self._observations = {}
            self._cell_keys = set()
            for observation in _stored_observations(results):
                self.observe(**observation, trusted=True)
            self._prune(self.clock())

    def issue_nonce(self, identifier: str, actor: str) -> str:
        with self._lock:
            now = self.clock()
            self._prune(now)
            observation = self._observations.get(identifier)
            if observation is None or identifier in self._feedback:
                raise ValueError("Feedback observation is unavailable or already reviewed")
            if len(self._nonces) >= MAX_NONCES:
                raise ValueError("Feedback nonce limit reached")
            nonce = secrets.token_urlsafe(32)
            self._nonces[nonce] = (observation, actor, now + NONCE_TTL)
            return nonce

    def feedback(self, nonce: str, quality: float, actor: str) -> None:
        if not isinstance(nonce, str) or not _number(quality, 0, 1):
            raise ValueError("Invalid feedback")
        with self._lock:
            self._prune(self.clock())
            entry = self._nonces.get(nonce)
            if entry is None or entry[1] != actor or entry[0].identifier in self._feedback:
                raise ValueError("Feedback nonce expired, used or unavailable")
            observation = entry[0]
            self._feedback[observation.identifier] = (observation, quality)
            del self._nonces[nonce]

    def cells(self, *, seed=0):
        with self._lock:
            now = self.clock()
            self._prune(now)
            groups: dict[tuple[str, str], list[Observation]] = {}
            for observation in self._observations.values():
                groups.setdefault((observation.task, observation.model), []).append(observation)
            return [_cell(task, model, sorted(records, key=lambda value: value.identifier), self._feedback, now, seed)
                    for (task, model), records in sorted(groups.items())]

    def propose(self, *, task_type, eligible_order, base_revision, seed=0):
        if (task_type not in TASKS or not config_snapshots.revision(base_revision)
                or type(seed) is not int or not 0 <= seed < 2**32
                or not isinstance(eligible_order, (list, tuple)) or not 1 <= len(eligible_order) <= 16
                or any(not config_snapshots.safe_identifier(model, MODEL) for model in eligible_order)
                or len(set(eligible_order)) != len(eligible_order)):
            raise ValueError("Invalid bandit proposal options")
        by_model = {row["model"]: row for row in self.cells(seed=seed) if row["task_type"] == task_type}
        evidence = [by_model.get(model) or _cell(task_type, model, [], {}, self.clock(), seed) for model in eligible_order]
        after = list(eligible_order)
        moves = []
        for index in range(1, len(evidence)):
            before, candidate = evidence[index - 1:index + 1]
            if before["eligible"] and candidate["eligible"]:
                improvement = candidate["utility_ci"][0] - before["utility_ci"][1]
                if improvement > 0:
                    moves.append((improvement, -index, index))
        if moves:
            index = max(moves)[2]
            after[index - 1], after[index] = after[index], after[index - 1]
        reason = "supported_move" if moves else "confidence_overlap" if all(row["eligible"] for row in evidence) else "insufficient_evidence"
        return {"base_revision": base_revision, "task_type": task_type, "seed": seed,
                "eligible_order_before": list(eligible_order), "eligible_order_after": after, "evidence": evidence,
                "uncertainty": {"confidence": 0.95, "half_life_seconds": HALF_LIFE, "reason": reason,
                                "utility": "quality - mean(cost_usd / (1 + cost_usd))", "posterior_draws": POSTERIOR_DRAWS}}


def _noise_gate(results):
    affected = {(result.get("task_type"), result.get(f"{side}_model")) for result in results if "noise_floor" in result
                for side in ("candidate", "production")}
    try:
        records = [result for result in results if isinstance(result.get("noise_floor"), dict)
                   and type(result["noise_floor"].get("seed")) is int
                   and 0 <= result["noise_floor"]["seed"] < 2**32
                   and type(result["noise_floor"].get("bootstrap_draws")) is int
                   and noise_floor.DEFAULT_DRAWS <= result["noise_floor"]["bootstrap_draws"] <= noise_floor.MAX_DRAWS]
        # Sparse cohorts cannot pass the existing gate. Avoid spending draws on each isolated seed.
        groups = noise_floor._cohorts(records)
        eligible_samples = {sample for group in groups.values() if len(group) >= noise_floor.MIN_SAMPLES for sample in group}
        summaries = noise_floor.summarize([record for record in records if record["sample_id"] in eligible_samples])
    except (KeyError, TypeError, ValueError, ZeroDivisionError):
        return affected, set()
    allowed = set()
    for key in affected:
        cohorts = [row for row in summaries if row["task_type"] == key[0]
                   and key[1] in {row["candidate_model"], row["baseline_model"]}]
        if cohorts and all(row["eligible"] for row in cohorts):
            allowed.add(key)
    return affected, allowed


def _stored_observations(results):
    # Store metadata establishes provenance; public request bodies never reach this adapter.
    records = [result for result in list(results)[:MAX_OBSERVATIONS] if isinstance(result, dict)
               and isinstance(result.get("_id"), str) and ID.fullmatch(result["_id"])
               and isinstance(result.get("sample_id"), str) and ID.fullmatch(result["sample_id"])
               and _number(result.get("_created_at")) and result.get("task_type") in TASKS
               and all(config_snapshots.safe_identifier(result.get(f"{side}_model"), MODEL)
                       for side in ("candidate", "production"))]
    records.sort(key=lambda value: (-value["_created_at"], value["_id"]))
    affected, allowed = _noise_gate(records)
    for result in records:
        if result.get("candidate_model") == result.get("production_model"):
            continue
        quality = {"win": 1.0, "loss": 0.0, "tie": 0.5}.get(result.get("outcome"))
        validity = result.get("tool_validity")
        valid = quality is not None and not result.get("candidate_truncated") and (validity is None or isinstance(validity, dict) and all(
            isinstance(value, dict) and value.get("invalid") == 0 for value in validity.values()))
        costs = result.get("costs")
        for side in ("candidate", "production"):
            model = result.get(f"{side}_model")
            if not isinstance(model, str):
                continue
            key = (result["task_type"], model)
            cost = costs.get(side) if isinstance(costs, dict) else None
            yield {"observation_id": observation_id(result["sample_id"], model), "task_type": key[0], "model": model,
                   "observed_at": result["_created_at"], "quality": (quality if side == "candidate" else 1 - quality)
                   if quality is not None and valid else None,
                   "cost_usd": cost if _number(cost) else None, "noise_eligible": valid and (key not in affected or key in allowed)}


recommendations = BanditRecommendations()


def read_route_revision(route_id):
    """Read fresh route bytes between revision checks; never use the routing fallback cache."""
    revision = config_snapshots.call("snapshot_list")["current_revision"]
    try:
        routes = auto_route_d1._routes(auto_route_d1.snapshot_request("list"))
    except ValueError:
        raise APIError("Bandit route evidence is unavailable", 503, {"error": "bandit_storage_unavailable"}) from None
    if config_snapshots.call("snapshot_list")["current_revision"] != revision:
        raise APIError("Configuration changed; reload and review again", 409, {"error": "revision_conflict"})
    order = routes.get(route_id, (DEFAULT_AUTO_ROUTES.get(route_id), None))[0]
    if order is None:
        raise APIError("Auto route not found", 404)
    return revision, order


def proposal_options(body):
    if (not isinstance(body, dict) or set(body) - {"route_id", "task_type", "seed"}
            or not isinstance(body.get("route_id"), str) or not auto_route_d1._ROUTE_ID.fullmatch(body["route_id"])
            or body.get("task_type") not in TASKS or type(body.get("seed", 0)) is not int
            or not 0 <= body.get("seed", 0) < 2**32):
        raise APIError("Expected route_id, task_type and optional integer seed", 400)
    return body["route_id"], body["task_type"], body.get("seed", 0)
