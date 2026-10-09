"""Resource-safe helpers for consuming provider HTTP responses."""

from collections.abc import Iterator

import requests

from streaming.sse import iter_sse_data
from services.request_cancellation import CancellationIterator, bind_cancellation

def close_retry_response(response: requests.Response) -> None:
    """Release a retryable response without masking the original result."""
    bind_cancellation(response).close()


def iter_stream_content(response: requests.Response, *, pii_context=None) -> Iterator[bytes]:
    """Yield decoded upstream bytes as soon as the socket exposes them."""
    source = CancellationIterator(lambda: _stream_content(response), bind_cancellation(response))
    if pii_context is None:
        return source
    from services.pii_stream import RehydratingIterator
    return RehydratingIterator(source, pii_context, event_stream=True)


def _stream_content(response: requests.Response) -> Iterator[bytes]:
    raw_response = getattr(response, "raw", None)
    raw_read1 = getattr(raw_response, "read1", None)
    if callable(raw_read1):
        while True:
            chunk = raw_read1(64 * 1024, decode_content=True)
            if not chunk:
                return
            yield chunk

    yield from response.iter_content(chunk_size=128)


def iter_stream_lines(response: requests.Response) -> Iterator[str]:
    """Own the stream before the first read, including preflight rejection."""
    return CancellationIterator(lambda: _stream_lines(response), bind_cancellation(response))


def _stream_lines(response: requests.Response) -> Iterator[str]:
    """Parse SSE responses incrementally, with a line-based fallback."""
    content_type = response.headers.get("content-type", "").lower()
    if content_type.startswith("text/event-stream") and hasattr(
        response,
        "iter_content",
    ):
        # A failed socket read is an interrupted handoff, not a fresh read path.
        for data_payload in iter_sse_data(_stream_content(response)):
            yield f"data: {data_payload}"
        return

    yield from response.iter_lines(decode_unicode=True)
