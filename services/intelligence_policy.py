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
from services.route_health import RouteHealth

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
# Gemini qualifies through its OpenAI-compatible endpoint (see intelligence_transport).
CHAT_PROVIDERS = frozenset(
    {
        "openai",
        "openrouter",
        "linkapi",
        "aihubmix",
        "codex-easy",
        "kimi-code",
        "cline-pass",
        "gemini",
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
# The fast profile estimates how long a reply takes: time to first output, then this many
# tokens (or the request's smaller output limit) at the candidate's output rate. A figure
# with no measurement or reviewed value uses the pessimistic default beside it.
FAST_REPLY_TOKENS = 512
UNKNOWN_FIRST_OUTPUT_MS = 10_000
UNKNOWN_TOKENS_PER_SECOND = 20
# Below this recent success average a candidate yields to every healthier one.
UNHEALTHY_SUCCESS = 0.5
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
        "tokens_per_second",
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
    for key in ("latency_ms", "tokens_per_second"):
        if key in result:
            integer(result[key], key)
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


def expected_reply_ms(candidate, request, now=None):
    """Recent measured speed first, then reviewed figures; None when neither exists."""
    first_ms, rate = RouteHealth.speed(candidate["model"], now=now)
    first_ms = first_ms if first_ms is not None else candidate.get("latency_ms")
    rate = rate if rate is not None else candidate.get("tokens_per_second")
    if first_ms is None and rate is None:
        return None
    tokens = min(request.output_tokens, FAST_REPLY_TOKENS)
    first_ms = UNKNOWN_FIRST_OUTPUT_MS if first_ms is None else first_ms
    rate = UNKNOWN_TOKENS_PER_SECOND if rate is None else rate
    return first_ms + tokens * 1000 / max(rate, 1)


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
        expected = expected_reply_ms(candidate, request)
        speed = (expected is None, expected or 0)
        if request.profile == "fast":
            unhealthy = RouteHealth.success(candidate["model"]) < UNHEALTHY_SUCCESS
            return (unhealthy, *speed, -score, priority)
        if request.profile == "quality":
            # Speed only orders candidates of equal score and tier; it never promotes a weaker one.
            return (-score, -candidate.get("quality_tier", 0), *speed, priority)
        return (priority, -score, *speed)

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
        {
            capability
            for candidate in reviewed
            for capability in candidate.get("capabilities", [])
            if capability in CAPABILITIES
            and (
                capability not in {"vision", "audio"}
                or candidate.get("media_input_tokens")
            )
        }
    )
    tags = supported if policy["enabled"] else []
    return {
        "id": "auto:intelligence",
        "object": "model",
        "created": 0,
        "owned_by": "multillm",
        "status": "configured" if policy["enabled"] and reviewed else "unconfigured",
        # Flags match every other /v1/models entry; the reviewed tags stay separate.
        "capabilities": {
            "supports_chat": bool(policy["enabled"] and reviewed),
            "supports_streaming": "streaming" in tags,
            "supports_tools": "tools" in tags,
            "supports_vision": "vision" in tags,
            "supports_images": False,
            "supports_video": False,
        },
        "capability_tags": tags,
        "supports_vision": "vision" in tags,
        "routing_version": 1,
        "availability": "unverified",
    }
