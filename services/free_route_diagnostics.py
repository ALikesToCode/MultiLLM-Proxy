"""Content-free explanations and retry guidance for exhausted free routes."""

MAX_DIAGNOSTIC_ROWS = 16
STATUS_REASONS = {
    401: "authentication_failed",
    402: "quota_or_billing_rejected",
    403: "access_denied",
    404: "model_unavailable",
    410: "model_unavailable",
    429: "rate_limited",
}
OUTPUT_REASONS = {
    "invalid_response",
    "invalid_json",
    "schema_mismatch",
    "stream_interrupted",
    "upstream_error",
    "response_too_large",
    "deadline_exceeded",
    "timeout",
    "connection_error",
    "credentials_unavailable",
}


def failure_detail(candidate, status, upstream_status, reason=None, retry_after=0, *, compatibility=None):
    if reason != "unsupported_parameters" and reason not in OUTPUT_REASONS:
        reason = STATUS_REASONS.get(status, "upstream_unavailable")
    detail = {
        "provider": candidate.provider,
        "model": candidate.id,
        "reason": reason,
        "status": status,
        "upstream_status": upstream_status,
        "retry_after": retry_after,
    }
    if compatibility in {"input_too_large", "image_limit", "output_format", "vision_input"}:
        detail["compatibility"] = compatibility
    return detail


def exhausted_details(configured, failures, cooldown, *, stop_reason):
    delays = {candidate.id: cooldown(candidate) for candidate in configured}
    cooling = bool(delays) and all(delays.values())
    unsupported = {
        item["model"] for item in failures if item["reason"] == "unsupported_parameters"
    }
    attempted = {item["model"] for item in failures}
    untried = {
        candidate.id
        for candidate in configured
        if not delays[candidate.id] and candidate.id not in attempted
    }
    retryable = bool(
        untried or any(delays.values()) or len(unsupported) < len(configured)
    )
    if cooling:
        code, reason, status = "free_pool_exhausted", "all_candidates_cooling", 429
    elif stop_reason in {"attempt_limit", "deadline_exceeded"}:
        code, reason, status = "free_attempt_limit", stop_reason, 503
    else:
        code, reason, status = "free_providers_failed", "providers_failed", 503
    # Do not recommend a one-second loop against a permanently incompatible
    # endpoint when the only usable alternatives are waiting on quota.
    eligible_delays = [
        delay
        for model, delay in delays.items()
        if model not in unsupported and delay > 0
    ]
    delay = min(eligible_delays) if eligible_delays and not untried else 5
    retry_after = delay if retryable else None
    cooldowns = [
        {
            "provider": candidate.provider,
            "model": candidate.id,
            "retry_after": delays[candidate.id],
        }
        for candidate in configured
        if delays[candidate.id]
    ]
    message = (
        "No free provider produced a valid response. Wait for retry_after before retrying; no paid model was used."
        if retryable
        else "No available free provider supports the requested parameters. Change the output contract or configure a compatible free provider; no paid model was used."
    )
    return status, {
        "code": code,
        "message": message,
        "reason": reason,
        "stop_reason": stop_reason,
        "retryable": retryable,
        "retry_after": retry_after,
        "attempts": len(failures),
        "failures": failures[:MAX_DIAGNOSTIC_ROWS],
        "cooldowns": cooldowns[:MAX_DIAGNOSTIC_ROWS],
        "cooldowns_truncated": len(cooldowns) > MAX_DIAGNOSTIC_ROWS,
    }
