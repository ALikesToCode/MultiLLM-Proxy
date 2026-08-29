"""Resource-safe helpers for consuming provider HTTP responses."""

import logging
from typing import Generator

import requests

from streaming.sse import iter_sse_data

logger = logging.getLogger(__name__)


def close_retry_response(response: requests.Response) -> None:
    """Release a retryable response without masking the original result."""
    try:
        response.close()
    except Exception as error:
        logger.warning(
            "Retry response cleanup failed type=%s",
            type(error).__name__,
        )


def iter_stream_content(response: requests.Response) -> Generator[bytes, None, None]:
    """Yield decoded upstream bytes as soon as the socket exposes them."""
    raw_response = getattr(response, "raw", None)
    raw_read1 = getattr(raw_response, "read1", None)
    if callable(raw_read1):
        while True:
            chunk = raw_read1(64 * 1024, decode_content=True)
            if not chunk:
                return
            yield chunk

    yield from response.iter_content(chunk_size=128)


def iter_stream_lines(response: requests.Response) -> Generator[str, None, None]:
    """Parse SSE responses incrementally, with a line-based fallback."""
    content_type = response.headers.get("content-type", "").lower()
    if content_type.startswith("text/event-stream") and hasattr(
        response,
        "iter_content",
    ):
        try:
            for data_payload in iter_sse_data(iter_stream_content(response)):
                yield f"data: {data_payload}"
            return
        except Exception as error:
            logger.warning(
                "SSE parser failed; falling back to line iteration type=%s",
                type(error).__name__,
            )

    yield from response.iter_lines(decode_unicode=True)
