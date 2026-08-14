from collections.abc import Callable, Iterable
from typing import Any
from urllib.parse import SplitResult, urlsplit

WSGIStartResponse = Callable[..., Any]
WSGIApplication = Callable[[dict[str, Any], WSGIStartResponse], Iterable[bytes]]


def _parse_https_origin(value: str | None) -> SplitResult | None:
    if not value:
        return None

    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return None

    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        return None

    if port is not None and not 1 <= port <= 65535:
        return None
    return parsed


class TrustedExternalOriginMiddleware:
    """Restore the public HTTPS origin after the Cloudflare Container hop."""

    header_environ_key = "HTTP_X_MULTILLM_EXTERNAL_ORIGIN"

    def __init__(self, application: WSGIApplication) -> None:
        self.application = application

    def __call__(
        self,
        environ: dict[str, Any],
        start_response: WSGIStartResponse,
    ) -> Iterable[bytes]:
        parsed = _parse_https_origin(environ.get(self.header_environ_key))
        if parsed is not None:
            environ["wsgi.url_scheme"] = "https"
            environ["HTTP_HOST"] = parsed.netloc
            environ["SERVER_NAME"] = parsed.hostname
            environ["SERVER_PORT"] = str(parsed.port or 443)

        return self.application(environ, start_response)
