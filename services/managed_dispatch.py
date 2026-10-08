"""Managed attempt scheduling, separate from raw dispatch and normalization."""

import math
import time
from typing import Callable

import requests
from flask import g, has_request_context

from services.retry_advice import parse_retry_advice, retry_advice_settings
from services.upstream_outcome import UpstreamOutcome
from services.upstream_transport import close_retry_response

Attempt = Callable[[int], requests.Response]
Outcome = Callable[[], UpstreamOutcome]


def retry_managed_attempt(
    attempt: Attempt,
    outcome: Outcome,
    *,
    retry_count: int,
    max_retries: int,
    retry_delay: float,
    response: requests.Response | None = None,
    deadline: float | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> requests.Response | None:
    """Dispatch again only under the existing transport's replay permission.

    A supplied deadline is monotonic. The existing cascade deadline is used when
    available; absent one, per-attempt timeouts remain the transport's policy.
    None means that the original response/error must finish normally.
    """
    classified = outcome()
    if not classified.replay_permission or retry_count >= max_retries:
        return None
    settings = retry_advice_settings()
    delay = retry_delay * (retry_count + 1)
    if settings.enabled:
        if response is not None:
            advice = parse_retry_advice(
                response.headers,
                now=time.time(),
                status_code=response.status_code,
                max_seconds=settings.max_seconds,
            )
            if advice is not None:
                delay = max(delay, advice.delay_seconds)
        if deadline is None and has_request_context():
            deadline = getattr(g, "cascade_deadline", None)
        if deadline is not None:
            if not math.isfinite(deadline) or delay >= deadline - time.monotonic():
                return None
            # Keep the original response usable if scheduling consumes the budget.
            sleep(delay)
            if time.monotonic() >= deadline:
                return None
            if response is not None:
                close_retry_response(response)
            return attempt(retry_count + 1)
    if response is not None:
        close_retry_response(response)
    sleep(delay)
    return attempt(retry_count + 1)
