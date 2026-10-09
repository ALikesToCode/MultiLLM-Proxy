"""One cleanup owner and content-free outcome for an upstream handoff."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any, Generic, TypeVar

from flask import Response, g, has_request_context

from services.upstream_outcome import UpstreamOutcome, classify_upstream_outcome

logger = logging.getLogger(__name__)
T = TypeVar("T")


@dataclass(frozen=True)
class CancellationOutcome:
    reason: str
    ambiguous: bool
    upstream: UpstreamOutcome
    usage_state: str = "unknown"
    usage: None = None


class CancellationContext:
    """Own close without spawning a disconnect watcher or authorizing replay."""

    def __init__(self, close: Callable[[], Any], *, on_outcome=None):
        self._close = close
        self._on_outcome = on_outcome
        self._lock = threading.Lock()
        self.handed_off = False
        self.closed = False
        self.outcome: CancellationOutcome | None = None

    def handoff(self) -> None:
        self.handed_off = True

    def _finish(self, reason: str, upstream: UpstreamOutcome) -> None:
        with self._lock:
            if self.closed:
                return
            self.closed = True
            self.outcome = CancellationOutcome(
                reason, self.handed_off and reason != "complete", upstream,
            )
        try:
            self._close()
        except Exception as error:
            logger.warning("Upstream cleanup failed type=%s", type(error).__name__)
        if self._on_outcome is not None:
            try:
                self._on_outcome(self.outcome)
            except Exception as error:
                logger.warning("Cancellation observer failed type=%s", type(error).__name__)

    def complete(self) -> None:
        self._finish("complete", classify_upstream_outcome(200))

    def cancel(self) -> None:
        self._finish("cancelled", classify_upstream_outcome(cancelled=True))

    def fail(self) -> None:
        self._finish(
            "interrupted", classify_upstream_outcome(transport_failure="interrupted"),
        )

    def close(self) -> None:
        self.cancel()


class CancellationIterator(Iterator[T], Generic[T]):
    """A closable lazy iterator, including before its generator has started."""

    def __init__(self, factory: Callable[[], Iterator[T]], context: CancellationContext,
                 *, close_source: Callable[[], Any] | None = None):
        self._factory = factory
        self.context = context
        self._source: Iterator[T] | None = None
        self._close_source = close_source
        self._closed = False

    def __iter__(self) -> CancellationIterator[T]:
        return self

    def __next__(self) -> T:
        if self._closed or self.context.closed:
            raise StopIteration
        try:
            if self._source is None:
                self._source = iter(self._factory())
            return next(self._source)
        except StopIteration:
            self.context.complete()
            self.close()
            raise
        except GeneratorExit:
            self.close()
            raise
        except BaseException:
            self.context.fail()
            self.close()
            raise

    def throw(self, error):
        # GeneratorExit from a downstream owner must never resume the socket.
        self.close()
        raise error

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        close = self._close_source or getattr(self._source, "close", None)
        try:
            if close is not None:
                close()
        except Exception as error:
            logger.warning("Stream cleanup failed type=%s", type(error).__name__)
        finally:
            self.context.close()


class RequestCancellation:
    """Request-local collaborators; renewal loss cannot authorize another dispatch."""

    def __init__(self):
        self.contexts = []
        self.lost = False
        self._lock = threading.Lock()

    def bind(self, context):
        with self._lock:
            self.contexts.append(context)
            lost = self.lost
        if lost:
            context.cancel()

    def cancel(self, error=None):
        with self._lock:
            self.lost = True
            contexts = tuple(self.contexts)
        for context in contexts:
            context.cancel()


def owned_stream_lines(upstream):
    """Preserve native line parsing while marking upstream EOF before cleanup."""
    return CancellationIterator(lambda: iter(upstream.iter_lines()), bind_cancellation(upstream))


def attach_stream_owner(downstream, upstream):
    """Own hidden upstream resources even before the lazy body starts."""
    context = bind_cancellation(upstream)
    source = downstream.response
    downstream.response = CancellationIterator(lambda: iter(source), context,
                                                close_source=getattr(source, "close", None))
    downstream.multillm_cancellation = context
    downstream.call_on_close(context.close)
    return downstream


def bind_cancellation(response, *, on_outcome=None, close_owner=None, replace_close=True) -> CancellationContext:
    """Share close ownership with existing transport, WSGI and preflight owners.

    Flask bodies must themselves own hidden provider resources. A transport
    creating a lazy generator should bind its upstream before building that body.
    """
    context = getattr(response, "multillm_cancellation", None)
    if isinstance(context, CancellationContext):
        return context
    # Test doubles and some adapters have no close(); ownership still applies.
    status = getattr(response, "status_code", None)
    rejected = type(status) is int and 400 <= status < 500
    if on_outcome is None and has_request_context() and not rejected:
        from services.request_accounting import cancellation_observer
        on_outcome = cancellation_observer()
    close = close_owner or getattr(response, "close", None)
    context = CancellationContext(close if callable(close) else (lambda: None), on_outcome=on_outcome)
    context.handoff()
    if has_request_context():
        owner = getattr(g, "gateway_cancellation", None)
        if owner is None:
            owner = g.gateway_cancellation = RequestCancellation()
        owner.bind(context)
    response.multillm_cancellation = context
    if replace_close:
        response.close = context.close
    if isinstance(response, Response):
        source = response.response
        response.response = CancellationIterator(
            lambda: iter(source), context, close_source=getattr(source, "close", None),
        )
    return context
