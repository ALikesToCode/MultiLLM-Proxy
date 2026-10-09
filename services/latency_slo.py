"""Opt-in admission from bounded, paired measurements; no probes or policy writes."""
from __future__ import annotations

import json
import logging
import math
import os
import re
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field

from flask import current_app, g, has_request_context, jsonify, request

from services.intelligence_contract import GatewayError

ENV_KEYS = ("LATENCY_SLO_MODE", "LATENCY_SLO_MIN_SAMPLES", "LATENCY_SLO_MAX_MODELS", "LATENCY_SLO_POLICY_JSON")
WINDOW_SECONDS = 900
MAX_SAMPLES = 1000
MAX_OUTPUT_TOKENS = 131072
DEFAULT_OUTPUT_TOKENS = 1024
logger = logging.getLogger(__name__)
_warned: set[str] = set()
_warning_lock = threading.Lock()
_IDENTIFIER = re.compile(r"[A-Za-z0-9._:/@+-]{1,256}\Z")


def _warn_once(setting):
    with _warning_lock:
        if setting not in _warned:
            _warned.add(setting)
            logger.warning("Invalid %s; latency SLO admission disabled", setting)


def _integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def _number(value, minimum=0, maximum=1e13):
    return type(value) in (int, float) and math.isfinite(value) and minimum <= value <= maximum


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate policy key")
        result[key] = value
    return result


@dataclass(frozen=True)
class Rule:
    deadline_ms: int
    require_coverage: bool = False


@dataclass(frozen=True)
class Settings:
    mode: str = "off"
    min_samples: int = 20
    max_models: int = 128
    rules: dict = field(default_factory=dict)

    def rule_for(self, *, route="", key_id="", model=""):
        selected = [self.rules.get("routes", {}).get(name) for name in (route, model)]
        selected.append(self.rules.get("keys", {}).get(key_id))
        selected = [rule for rule in selected if rule is not None]
        if not selected:
            return None
        return Rule(min(rule.deadline_ms for rule in selected), any(rule.require_coverage for rule in selected))


def _parse_policy(raw):
    if len(raw.encode()) > 32768:
        raise ValueError("Policy too large")
    config = json.loads(raw, object_pairs_hook=_unique_object)
    if not isinstance(config, dict) or set(config) - {"routes", "keys"}:
        raise ValueError("Invalid policy")
    rules = {}
    for scope in ("routes", "keys"):
        entries = config.get(scope, {})
        if not isinstance(entries, dict) or len(entries) > 128:
            raise ValueError("Invalid scope")
        rules[scope] = {}
        for name, rule in entries.items():
            if (not _IDENTIFIER.fullmatch(name) or not isinstance(rule, dict)
                    or set(rule) - {"deadline_ms", "require_coverage"}
                    or not _integer(rule.get("deadline_ms"), 1, 300000)
                    or type(rule.get("require_coverage", False)) is not bool):
                raise ValueError("Invalid rule")
            rules[scope][name] = Rule(rule["deadline_ms"], rule.get("require_coverage", False))
    return rules


def load_settings(env=None):
    env = os.environ if env is None else env
    mode = str(env.get("LATENCY_SLO_MODE", "")).strip().lower() or "off"
    if mode == "off":
        return Settings()
    if mode not in {"reject", "reroute"}:
        _warn_once("LATENCY_SLO_MODE")
        return Settings()
    limits = {}
    for name, default, maximum in (("LATENCY_SLO_MIN_SAMPLES", 20, 1000), ("LATENCY_SLO_MAX_MODELS", 128, 512)):
        raw = str(env.get(name, "")).strip() or str(default)
        if not re.fullmatch(r"[0-9]{1,4}", raw) or not 1 <= int(raw) <= maximum:
            _warn_once(name)
            return Settings()
        limits[name] = int(raw)
    try:
        rules = _parse_policy(str(env.get("LATENCY_SLO_POLICY_JSON", "")).strip() or "{}")
    except (ValueError, TypeError, RecursionError):
        _warn_once("LATENCY_SLO_POLICY_JSON")
        return Settings()
    return Settings(mode, limits["LATENCY_SLO_MIN_SAMPLES"], limits["LATENCY_SLO_MAX_MODELS"], rules)


def requested_output(payload, default=DEFAULT_OUTPUT_TOKENS):
    values = [payload[name] for name in ("max_tokens", "max_completion_tokens") if name in payload]
    values = values or [default]
    return min(values) if all(_integer(value, 1, MAX_OUTPUT_TOKENS) for value in values) else None


class ObservationWindow:
    """Process-local FIFO model windows; reads neither mutate nor persist measurements."""
    def __init__(self, max_models=128):
        if not _integer(max_models, 1, 512):
            raise ValueError("Invalid model cap")
        self.max_models = max_models
        self._models: OrderedDict[str, deque] = OrderedDict()
        self._lock = threading.RLock()

    def clear(self):
        with self._lock:
            self._models.clear()

    def record(self, model, *, ttft_ms, tokens_per_second, now=None, max_models=None):
        timestamp = time.time() if now is None else now
        if (not isinstance(model, str) or not _IDENTIFIER.fullmatch(model)
                or not _number(timestamp) or not _number(ttft_ms, maximum=3600000)
                or not _number(tokens_per_second, minimum=1e-9, maximum=1000000)):
            return False
        with self._lock:
            cap = self.max_models if max_models is None else max_models
            if not _integer(cap, 1, 512):
                return False
            for name in list(self._models):
                recent = [sample for sample in self._models[name] if sample[0] >= timestamp - WINDOW_SECONDS]
                if recent:
                    self._models[name] = deque(recent, maxlen=MAX_SAMPLES)
                else:
                    del self._models[name]
            samples = self._models.setdefault(model, deque(maxlen=MAX_SAMPLES))
            samples.append((timestamp, ttft_ms, tokens_per_second))
            self._models.move_to_end(model)
            while len(self._models) > cap:
                self._models.popitem(last=False)
        return True

    def predict(self, model, output_tokens, *, min_samples=20, now=None):
        timestamp = time.time() if now is None else now
        with self._lock:
            samples = tuple(self._models.get(model, ()))
        recent = [sample for sample in samples if 0 <= timestamp - sample[0] <= WINDOW_SECONDS]
        age = max(0, round((timestamp - max(sample[0] for sample in samples)) * 1000)) if samples else None
        prediction = {"status": "prediction_unknown", "predicted_ms": None, "samples": len(recent),
                      "min_samples": min_samples, "coverage": min(1, len(recent) / min_samples),
                      "observation_age_ms": age, "window_ms": WINDOW_SECONDS * 1000,
                      "output_tokens": output_tokens}
        if len(recent) >= min_samples and _integer(output_tokens, 1, MAX_OUTPUT_TOKENS):
            times = sorted(ttft + output_tokens * 1000 / rate for _, ttft, rate in recent)
            prediction.update(status="prediction_known", predicted_ms=math.ceil(times[math.ceil(.95 * len(times)) - 1]))
        return prediction


observations = ObservationWindow()


def record_observation(model, *, ttft_ms, tokens_per_second, now=None):
    settings = load_settings()
    if settings.mode == "off":
        return False
    return observations.record(model, ttft_ms=ttft_ms, tokens_per_second=tokens_per_second,
                               now=now, max_models=settings.max_models)


class LatencySLOError(GatewayError):
    def __init__(self, code, prediction):
        message = ("Recent latency coverage is unavailable" if code == "latency_slo_unavailable"
                   else "Predicted completion exceeds the latency deadline")
        super().__init__(code, message, 503)
        self.prediction = prediction

    def envelope(self):
        payload = super().envelope()
        payload["error"]["prediction"] = self.prediction
        return payload


@dataclass(frozen=True)
class Decision:
    candidates: list
    action: str
    prediction: dict | None


def admit_candidates(candidates, *, settings, rule, output_tokens, auto, observations=observations, now=None):
    """Caller supplies an ordered eligible list, already restricted to approved lanes."""
    if settings.mode == "off" or rule is None:
        return Decision(candidates, "pass", None)
    primary = candidates[0] if candidates else {}
    prediction = observations.predict(primary.get("model"), output_tokens, min_samples=settings.min_samples, now=now)
    if prediction["status"] == "prediction_unknown":
        if rule.require_coverage:
            raise LatencySLOError("latency_slo_unavailable", prediction)
        return Decision(candidates, "pass", prediction)
    if prediction["predicted_ms"] <= rule.deadline_ms:
        return Decision(candidates, "pass", prediction)
    tier = primary.get("quality_tier")
    if settings.mode == "reroute" and auto and _integer(tier, 0, 100):
        safe = []
        for candidate in candidates[1:]:
            if type(candidate.get("quality_tier")) is not int or candidate["quality_tier"] != tier:
                continue
            alternate = observations.predict(candidate.get("model"), output_tokens, min_samples=settings.min_samples, now=now)
            if alternate["status"] == "prediction_known" and alternate["predicted_ms"] <= rule.deadline_ms:
                safe.append(candidate)
        if safe:
            return Decision(safe, "reroute", observations.predict(safe[0]["model"], output_tokens,
                            min_samples=settings.min_samples, now=now))
    raise LatencySLOError("latency_slo_predicted_miss", prediction)


def selection_candidates(candidates, *, route, output_tokens, auto, lane_selected=False):
    """Enforce after eligibility, including callers outside Flask."""
    context = getattr(g, "latency_slo_context", None) if has_request_context() else None
    if has_request_context() and context is None:
        return candidates
    if context is not None and auto:
        early = getattr(g, "latency_slo_decision", None)
        if early is not None and early.action == "reroute":
            approved = {item["model"] for item in early.candidates}
            candidates = [item for item in candidates if item["model"] in approved]
    if context is not None and auto and not lane_selected:
        from services.managed_turn import current_turn
        turn = current_turn()
        if turn is not None and turn.tier_metadata is not None:
            # Lane acquisition requires the original approved model to remain eligible.
            return candidates
    if context is None:
        settings = load_settings()
        rule = settings.rule_for(route=route)
    else:
        settings, rule, _ = context
        from services.generation_deadline import check_deadline
        deadline = check_deadline()
        if deadline is not None:
            rule = Rule(min(rule.deadline_ms, deadline.remaining_ms()), rule.require_coverage)
    decision = admit_candidates(candidates, settings=settings, rule=rule,
                                output_tokens=output_tokens, auto=auto,
                                now=current_app.extensions["latency_slo"]["clock"]() if context is not None else None)
    if context is not None:
        g.latency_slo_decision = decision
    return decision.candidates


def order_auto_candidates(route, candidates):
    """Generic routes have no tier evidence unless the authenticated callback supplies it."""
    if not has_request_context() or not getattr(g, "latency_slo_context", None):
        return candidates
    metadata = {item["model"]: item for item in getattr(g, "latency_slo_eligible", ())}
    decision = getattr(g, "latency_slo_decision", None)
    allowed = {item["model"] for item in decision.candidates} if decision is not None and decision.action == "reroute" else None
    eligible = [metadata.get(model, {"model": model}) for model in candidates
                if (not metadata or model in metadata) and (allowed is None or model in allowed)]
    _, _, output = g.latency_slo_context
    selected = selection_candidates(eligible, route=route, output_tokens=output, auto=True)
    return tuple(item["model"] for item in selected)


def latency_slo_request_hook():
    options = current_app.extensions["latency_slo"]
    settings = load_settings()
    if settings.mode == "off" or not options["is_managed"]() or not getattr(g, "authenticated_user", None):
        return None
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not isinstance(body.get("model"), str):
        return None
    model = body["model"]
    user = g.authenticated_user
    rule = settings.rule_for(route=request.path, model=model,
                             key_id=str(user.get("api_key_id") or user.get("id") or user.get("username") or ""))
    if rule is None:
        return None
    from services.generation_deadline import check_deadline
    deadline = check_deadline()
    if deadline is not None:
        rule = Rule(min(rule.deadline_ms, deadline.remaining_ms()), rule.require_coverage)
    output = requested_output(body)
    auto = model.startswith("auto:")
    eligible = options["candidates"](body) if auto else [{"model": model}]
    g.latency_slo_context = (settings, rule, output)
    g.latency_slo_eligible = eligible or []
    try:
        g.latency_slo_decision = admit_candidates(eligible or [], settings=settings, rule=rule,
            output_tokens=output, auto=auto, now=options["clock"]())
    except LatencySLOError as error:
        return latency_slo_error_response(error)
    return None


def latency_slo_error_response(error):
    return jsonify(error.envelope()), 503, {"Cache-Control": "no-store"}


def register_latency_slo(app, *, is_managed, candidates=lambda body: None, clock=time.time):
    from services.gateway_extensions import register_authenticated_hook
    app.extensions["latency_slo"] = {"is_managed": is_managed, "candidates": candidates, "clock": clock}
    register_authenticated_hook(app, latency_slo_request_hook)
    app.register_error_handler(LatencySLOError, latency_slo_error_response)
