"""Trusted dispatch scope and classified cooldown evidence for pool adapters."""
import time
from collections.abc import Mapping
from urllib.parse import unquote, urlsplit

from flask import current_app, has_app_context

from services.model_cooldown import settings
from services.retry_advice import parse_retry_advice, retry_advice_settings
from services.upstream_outcome import classify_upstream_outcome


def selection_context(provider, model=None, *, config=None, quota_bucket=None):
    if not settings().enabled:
        return {}
    if config is None:
        config = current_app.config if has_app_context() else {}
    buckets = config.get("PROVIDER_QUOTA_BUCKETS", {})
    configured = buckets.get(provider) if isinstance(buckets, Mapping) else None
    bucket = quota_bucket if isinstance(quota_bucket, str) and quota_bucket else configured
    return {"model": model if isinstance(model, str) and model else None,
            "quota_bucket": bucket if isinstance(bucket, str) and bucket else None}


def upstream_model(body, url=""):
    model = body.get("model") if isinstance(body, Mapping) else None
    if isinstance(model, str) and model:
        return model
    path = urlsplit(url).path
    if "/models/" in path:
        return unquote(path.split("/models/", 1)[1].split(":", 1)[0].split("/", 1)[0]) or None
    return None


def dispatch_context(provider, data, url, *, config=None):
    """Do not inspect raw bodies unless scoped cooldown tracking is enabled."""
    if not settings().enabled:
        return {}
    from request_validation import decode_json_object_bytes
    try:
        body = decode_json_object_bytes(data)
    except (ValueError, TypeError):
        body = {}
    return selection_context(provider, upstream_model(body, url), config=config)


def proxy_selection_context(provider, body, url, *, config, path, method, headers):
    """Select against the model the raw NanoGPT speed policy will dispatch."""
    if not settings().enabled:
        return {}
    if (provider == "nanogpt" and method.upper() == "POST"
            and path.strip("/").lower() in {"chat/completions", "v1/chat/completions", "v1/responses"}
            and isinstance(body, dict)):
        from providers.nanogpt import apply_nanogpt_speed_routing, nanogpt_speed_routing
        from services.nanogpt_speed_breaker import NanoGPTSpeedBreaker
        suffix = nanogpt_speed_routing(config) if NanoGPTSpeedBreaker.allows_suffix() else ""
        body = apply_nanogpt_speed_routing(body, suffix, headers)
    return selection_context(provider, upstream_model(body, url), config=config)


def observation_context(response, *, cancelled=False):
    if not settings().enabled:
        return {}
    status = response.status_code
    advice_settings = retry_advice_settings()
    advice = parse_retry_advice(response.headers, now=time.time(), status_code=status,
                                max_seconds=advice_settings.max_seconds) if advice_settings.enabled else None
    return {"outcome": classify_upstream_outcome(status, cancelled=cancelled),
            "credential_wide_auth": status == 401 and not cancelled,
            "retry_after_seconds": advice.delay_seconds if advice else None}
