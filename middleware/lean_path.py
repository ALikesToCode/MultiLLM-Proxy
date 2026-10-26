"""Serve `/lean/v1/...` from the unified `/v1/...` routes in lean mode."""

from collections.abc import Callable, Iterable
from typing import Any

WSGIStartResponse = Callable[..., Any]
WSGIApplication = Callable[[dict[str, Any], WSGIStartResponse], Iterable[bytes]]

LEAN_ENVIRON_KEY = "multillm.lean"
LEAN_PREFIX = "/lean"
LEAN_PATHS = frozenset(
    {
        "/v1/chat/completions",
        "/v1/messages",
        "/v1/messages/count_tokens",
        "/v1/models",
        "/v1/responses",
    }
)


class LeanPathMiddleware:
    """Rewrite a lean path to its unified route and mark the request as lean.

    Rewriting before Flask routes the request keeps every path-based rule (rate
    limits, body limits, error envelopes, cache affinity) identical to `/v1`.
    The mark lives in the WSGI environ, which a client cannot set.
    """

    def __init__(self, application: WSGIApplication) -> None:
        self.application = application

    def __call__(
        self,
        environ: dict[str, Any],
        start_response: WSGIStartResponse,
    ) -> Iterable[bytes]:
        environ.pop(LEAN_ENVIRON_KEY, None)
        path = environ.get("PATH_INFO", "")
        if path.startswith(f"{LEAN_PREFIX}/") and path[len(LEAN_PREFIX):] in LEAN_PATHS:
            environ["PATH_INFO"] = path[len(LEAN_PREFIX):]
            environ[LEAN_ENVIRON_KEY] = True
        return self.application(environ, start_response)
