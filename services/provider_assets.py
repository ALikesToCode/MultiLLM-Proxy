"""Bounded asset downloads, with fresh policy admission at every redirect."""
from urllib.parse import urljoin, urlsplit

from error_handlers import APIError
from services.provider_credentials import api_origin, origin, strip_credentials
from services.provider_dispatch import provider_http

MAX_REDIRECTS = 5


def asset_http(provider, url, *, headers=None, reference=None, **options):
    # Only documented authenticated content APIs may start with credentials.
    # Status-returned xAI and private-binding assets are always public downloads.
    authenticated = provider in {"openai", "gemini"} and api_origin(provider, url)
    headers = dict(headers or {})
    for hop in range(MAX_REDIRECTS + 1):
        parsed = urlsplit(url)
        if origin(url) is None or parsed.scheme != "https" or parsed.port not in (None, 443):
            raise APIError("The provider returned an unsupported video location", 502)
        if not authenticated:
            headers = strip_credentials(headers)
        response = provider_http(provider, "GET", url, headers=headers, reference=reference,
                                 public_asset=not authenticated, **options)
        if not 300 <= response.status_code < 400:
            return response
        location = response.headers.get("Location")
        response.close()
        if not location or hop == MAX_REDIRECTS:
            raise APIError("The video download redirect could not be resolved", 502)
        destination = urljoin(url, location)
        # Once an API redirects to an asset origin, never reintroduce its secrets,
        # including if a subsequent redirect returns to the API origin.
        if origin(destination) != origin(url):
            authenticated = False
            headers = strip_credentials(headers)
        url = destination
    raise AssertionError("Unreachable redirect limit")
