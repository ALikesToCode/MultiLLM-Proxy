"""Single-request native Messages counting on explicitly configured origins."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from urllib.parse import urlsplit, urlunsplit

import requests
from urllib3.exceptions import ReadTimeoutError

from providers.registry import get_registry

MAX_RESPONSE_BYTES = 64 * 1024
COUNT_FIELDS = frozenset({"model", "messages", "system", "tools", "tool_choice", "thinking"})
COUNT_HEADERS = frozenset({"anthropic-version", "anthropic-beta", "user-agent", "x-request-id"})
CLAUDE_COUNT_PATH = "/v1/messages/count_tokens"
CLAUDE_COUNT_FIELDS = COUNT_FIELDS | {"context_management"}


class NativeTokenCountError(Exception):
    """A sanitized failure that must never become an estimated success."""

    def __init__(self, message: str, status: int = 502):
        super().__init__(message)
        self.status = status


def _endpoint_path_valid(path: object) -> bool:
    if not isinstance(path, str) or not re.fullmatch(r"/[A-Za-z0-9_~./-]+", path):
        return False
    return (
        path.endswith("/messages/count_tokens")
        and "//" not in path
        and all(segment not in {".", ".."} for segment in path.split("/"))
    )


def _configured_endpoints(base_urls: Mapping[str, str]) -> dict[str, str]:
    try:
        endpoints = json.loads(os.environ.get("NATIVE_TOKEN_COUNT_ENDPOINTS_JSON", "{}"))
    except ValueError as error:
        raise NativeTokenCountError("Invalid native token count endpoint configuration", 500) from error
    if not isinstance(endpoints, dict):
        raise NativeTokenCountError("Invalid native token count endpoint configuration", 500)
    registered = get_registry(base_urls)
    for provider, path in endpoints.items():
        if provider not in registered or not _endpoint_path_valid(path):
            raise NativeTokenCountError("Invalid native token count endpoint configuration", 500)
    return endpoints


def _count_url(base_url: str, path: str) -> str:
    try:
        origin = urlsplit(base_url)
        port = origin.port
    except ValueError as error:
        raise NativeTokenCountError("Invalid native token count provider origin", 500) from error
    if (
        origin.scheme not in {"https", "http"}
        or not origin.hostname
        or origin.username is not None
        or origin.password is not None
        or (port is not None and port <= 0)
        or any(character.isspace() for character in base_url)
        or "\\" in base_url
    ):
        raise NativeTokenCountError("Invalid native token count provider origin", 500)
    return urlunsplit((origin.scheme, origin.netloc, path, "", ""))


def _reject_nonfinite(value: str) -> None:
    raise ValueError("Nonfinite JSON value")


def _read_count(response: requests.Response) -> int:
    raw = bytearray()
    for chunk in response.iter_content(chunk_size=8192):
        if len(raw) + len(chunk) > MAX_RESPONSE_BYTES:
            raise NativeTokenCountError("Native token count response exceeds 64 KiB")
        raw.extend(chunk)
    try:
        body = json.loads(raw, parse_constant=_reject_nonfinite)
    except (ValueError, RecursionError) as error:
        raise NativeTokenCountError("Malformed native token count response") from error
    count = body.get("input_tokens") if isinstance(body, dict) else None
    if type(count) is not int or count < 0:
        raise NativeTokenCountError("Malformed native token count response")
    return count


def count_native_tokens(
    payload: dict, request_headers: Mapping[str, str], base_urls: Mapping[str, str]
) -> int | None:
    """Return None only for unsupported/unconfigured capability, never upstream failure.

    The caller must authorize the original model before entering this adapter.
    """
    # Resolve per request so configuration changes and isolated application instances
    # share no credentials or model state through this adapter.
    from services.auth_service import AuthService
    from services.model_registry import ModelRegistry

    model_id = payload.get("model")
    if not isinstance(model_id, str):
        return None
    try:
        provider, model = ModelRegistry.parse_model_id(model_id)
    except ValueError:
        return None
    if provider == "auto":
        return None
    endpoints = _configured_endpoints(base_urls)
    path = endpoints.get(provider)
    if path is None:
        return None
    url = _count_url(base_urls[provider], path)
    credential = AuthService.get_api_key(provider)
    if not credential:
        return None
    # Proxy credentials and caller-supplied provider credentials are not part of
    # this configured count adapter's header contract.
    incoming = {key: value for key, value in request_headers.items() if key.lower() in COUNT_HEADERS}
    body = {key: value for key, value in payload.items() if key in COUNT_FIELDS}
    body["model"] = model
    return _post_count(provider, url, path, credential, incoming, body)


def count_claude_prompt_tokens(
    body: Mapping, beta_header: str, base_urls: Mapping[str, str]
) -> int:
    """Count a Claude API Messages body exactly as it will be sent.

    The count includes `context_management`, so it reports the prompt after
    server-side context editing: the size the long-prompt price applies to.
    """
    from services.auth_service import AuthService

    credential = AuthService.get_api_key("anthropic")
    if not credential:
        raise NativeTokenCountError("No Claude API key is configured", 503)
    url = _count_url(base_urls["anthropic"], CLAUDE_COUNT_PATH)
    incoming = {"anthropic-beta": beta_header} if beta_header else {}
    count_body = {key: value for key, value in body.items() if key in CLAUDE_COUNT_FIELDS}
    return _post_count("anthropic", url, CLAUDE_COUNT_PATH, credential, incoming, count_body)


def _post_count(
    provider: str,
    url: str,
    path: str,
    credential: str,
    incoming: Mapping[str, str],
    body: dict,
) -> int:
    from services.proxy_service import ProxyService

    headers = ProxyService.prepare_headers(incoming, provider, credential, upstream_path=path)
    headers["Content-Type"] = "application/json"
    headers["Accept"] = "application/json"
    session = ProxyService._get_provider_session(provider, raw_passthrough=True)
    response = None
    try:
        from services.provider_dispatch import provider_http
        response = provider_http(provider, "POST", url, transport=session.request, headers=headers, json=body, stream=True,
                                allow_redirects=False, timeout=(5, 10))
        status = response.status_code
        if status >= 400:
            raise NativeTokenCountError(f"Native token count upstream returned HTTP {status}", status)
        if not 200 <= status < 300:
            raise NativeTokenCountError("Unexpected native token count upstream status")
        return _read_count(response)
    except requests.Timeout as error:
        raise NativeTokenCountError("Native token count upstream timed out", 504) from error
    except requests.RequestException as error:
        # requests wraps urllib3 read timeouts during iter_content as ConnectionError.
        if any(isinstance(detail, ReadTimeoutError) for detail in error.args):
            raise NativeTokenCountError("Native token count upstream timed out", 504) from error
        raise NativeTokenCountError("Native token count upstream connection failed") from error
    finally:
        if response is not None:
            response.close()
