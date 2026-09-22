"""Reviewed exact-model eligibility; provider-wide flags are not model evidence."""

import copy

from providers.registry import get_adapter
from services.intelligence_contract import (
    CAPABILITIES,
    TASKS,
    capabilities,
    identifier,
    integer,
)
from services.model_registry import ModelRegistry

DEFAULT_POLICY = {
    "version": 1,
    "enabled": False,
    "allow_paid_overage": False,
    "max_attempts": 3,
    "max_escalations": 1,
    "deadline_ms": 45000,
    "max_total_tokens": 131072,
    "max_output_tokens": 4096,
    "principal_daily_tokens": 262144,
    "global_daily_tokens": 1048576,
    "max_inflight": 8,
    "max_request_bytes": 1048576,
    "max_response_bytes": 4194304,
    "candidates": [],
    "media": {},
}
# These adapters expose Chat Completions directly. Native conversion handlers
# with internal retries cannot yet provide the single-attempt accounting contract.
CHAT_PROVIDERS = frozenset(
    {
        "openai",
        "openrouter",
        "linkapi",
        "aihubmix",
        "codex-easy",
        "kimi-code",
        "groq",
        "opencode",
        "mimo",
        "nanogpt",
        "navyai",
        "together",
        "chutes",
        "xai",
        "cerebras",
        "scaleway",
        "hyperbolic",
        "sambanova",
    }
)
MEDIA_PROVIDERS = frozenset({"openai", "nanogpt", "navyai"})
MODEL_FIELDS = frozenset(
    {
        "model",
        "capabilities",
        "enabled",
        "entitled",
        "privacy_allowed",
        "billing",
        "context_window",
        "max_output_tokens",
        "quality_tier",
        "task_scores",
        "latency_ms",
        "media_input_tokens",
    }
)


def validate_model(raw):
    if not isinstance(raw, dict) or set(raw) - MODEL_FIELDS:
        raise ValueError("Invalid candidate")
    result = copy.deepcopy(raw)
    identifier(result.get("model"))
    capabilities(result.get("capabilities", []))
    for key in ("enabled", "entitled", "privacy_allowed"):
        if type(result.get(key)) is not bool:
            raise ValueError("Candidate requires explicit eligibility")
    if result.get("billing") not in {"subscription", "allowance", "free", "payg"}:
        raise ValueError("Invalid billing policy")
    for key in ("context_window", "max_output_tokens"):
        integer(result.get(key), key)
    integer(result.get("quality_tier", 0), "quality_tier", minimum=0, maximum=100)
    integer(result.get("media_input_tokens", 0), "media_input_tokens", minimum=0)
    if "latency_ms" in result:
        integer(result["latency_ms"], "latency_ms")
    scores = result.get("task_scores", {})
    if not isinstance(scores, dict) or set(scores) - TASKS:
        raise ValueError("Invalid reviewed task scores")
    for score in scores.values():
        integer(score, "task score", minimum=0, maximum=100)
    return result


def validate_policy(raw):
    if not isinstance(raw, dict) or set(raw) - set(DEFAULT_POLICY):
        raise ValueError("Invalid intelligence policy")
    policy = {**copy.deepcopy(DEFAULT_POLICY), **copy.deepcopy(raw)}
    if type(policy["version"]) is not int or policy["version"] != 1:
        raise ValueError("Unsupported policy version")
    for key in ("enabled", "allow_paid_overage"):
        if type(policy[key]) is not bool:
            raise ValueError("Invalid policy flag")
    for key in DEFAULT_POLICY.keys() - {
        "version",
        "enabled",
        "allow_paid_overage",
        "candidates",
        "media",
    }:
        integer(policy[key], key, minimum=0 if key == "max_escalations" else 1)
    if (
        policy["max_attempts"] > 16
        or policy["max_escalations"] > 4
        or policy["deadline_ms"] > 120000
    ):
        raise ValueError("Policy exceeds gateway safety ceilings")
    if not isinstance(policy["candidates"], list) or len(policy["candidates"]) > 64:
        raise ValueError("Invalid candidate list")
    policy["candidates"] = [validate_model(item) for item in policy["candidates"]]
    models = [item["model"] for item in policy["candidates"]]
    if len(models) != len(set(models)):
        raise ValueError("Duplicate model")
    media = policy["media"]
    if not isinstance(media, dict) or set(media) - {
        "transcriptions",
        "speech",
        "embeddings",
    }:
        raise ValueError("Invalid media policy")
    for operation, settings in media.items():
        if not isinstance(settings, dict) or set(settings) - {
            "candidate",
            "voice",
            "dimensions",
            "max_input_bytes",
            "daily_requests",
            "principal_daily_requests",
        }:
            raise ValueError("Invalid media settings")
        settings["candidate"] = validate_model(settings.get("candidate"))
        if settings["candidate"]["model"].split(":", 1)[0] not in MEDIA_PROVIDERS:
            raise ValueError("Unsupported media adapter")
        for key in ("max_input_bytes", "daily_requests", "principal_daily_requests"):
            integer(settings.get(key), key)
        if operation == "speech" and (
            not isinstance(settings.get("voice"), str)
            or not 1 <= len(settings["voice"]) <= 128
        ):
            raise ValueError("Speech requires a pinned voice")
        if operation == "embeddings":
            integer(settings.get("dimensions"), "dimensions", maximum=65536)
    return policy


def eligible(candidate, allow_paid, config):
    provider = candidate["model"].split(":", 1)[0]
    return (
        all(candidate[key] for key in ("enabled", "entitled", "privacy_allowed"))
        and (candidate["billing"] != "payg" or allow_paid)
        and ModelRegistry.get_model_status(candidate["model"]) != "disabled"
        and get_adapter(provider, config["API_BASE_URLS"]) is not None
    )


def input_reservation(candidate, request):
    if request.required & {"vision", "audio"}:
        return max(request.input_tokens, candidate.get("media_input_tokens", 0))
    return request.input_tokens


def select_candidates(policy, request, config):
    candidates = []
    for priority, candidate in enumerate(policy["candidates"]):
        if request.explicit and candidate["model"] != request.payload["model"]:
            continue
        if candidate["model"].split(":", 1)[0] not in CHAT_PROVIDERS:
            continue
        if not eligible(
            candidate, request.allow_paid, config
        ) or not request.required <= set(candidate.get("capabilities", [])):
            continue
        if request.required & {"vision", "audio"} and not candidate.get(
            "media_input_tokens"
        ):
            continue
        if (
            request.output_tokens > candidate["max_output_tokens"]
            or input_reservation(candidate, request) + request.output_tokens
            > candidate["context_window"]
        ):
            continue
        candidates.append((priority, candidate))

    def rank(item):
        priority, candidate = item
        score = candidate.get("task_scores", {}).get(request.task, 0)
        latency = candidate.get("latency_ms", 2**31 - 1)
        if request.profile == "fast":
            return (latency, -score, priority)
        if request.profile == "quality":
            return (-score, -candidate.get("quality_tier", 0), latency, priority)
        return (priority, -score, latency)

    return [candidate for _, candidate in sorted(candidates, key=rank)]


def model_advertisement(policy, config=None):
    reviewed = [
        c
        for c in policy["candidates"]
        if c["model"].split(":", 1)[0] in CHAT_PROVIDERS
        and all(c[k] for k in ("enabled", "entitled", "privacy_allowed"))
        and (config is None or eligible(c, policy["allow_paid_overage"], config))
    ]
    supported = sorted(
        set().union(*(set(c.get("capabilities", [])) for c in reviewed)) & CAPABILITIES
    )
    return {
        "id": "auto:intelligence",
        "object": "model",
        "created": 0,
        "owned_by": "multillm",
        "status": "configured" if policy["enabled"] and reviewed else "unconfigured",
        "capabilities": supported if policy["enabled"] else [],
        "routing_version": 1,
        "availability": "unverified",
    }
