"""Fixed-origin Worker bridge. Browser sessions never receive provider credentials."""

import os
from urllib.parse import urlsplit

import requests

from error_handlers import APIError


def worker_origin():
    value = os.environ.get("WORKBENCH_WORKER_URL", "").strip().rstrip("/")
    try:
        parsed = urlsplit(value)
    except ValueError:
        raise APIError("Configure WORKBENCH_WORKER_URL with a valid HTTPS Worker origin", status_code=503) from None
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
        raise APIError("Configure WORKBENCH_WORKER_URL with the trusted HTTPS Worker origin", status_code=503)
    return value


def call_worker(path, *, method="GET", payload=None, params=None, stream=False):
    if path not in {"/v1/roleplay", "/v1/roleplay/models", "/v1/roleplay/control/timeline",
                    "/v1/roleplay/control/memory", "/v1/roleplay/control/branch",
                    "/v1/roleplay/control/status", "/v1/roleplay/control/receipt", "/v1/roleplay/control/recovery"}:
        raise ValueError("Unsupported workbench operation")
    key = os.environ.get("ADMIN_API_KEY", "")
    if not key:
        raise APIError("Worker administrator credential is not configured", status_code=503)
    session = requests.Session()
    session.trust_env = False
    try:
        response = session.request(method, worker_origin() + path, json=payload, params=params,
                                   headers={"Authorization": f"Bearer {key}", "Accept": "text/event-stream" if stream else "application/json"},
                                   timeout=(10, 110), stream=True, allow_redirects=False)
        # The relay owns both objects until consumption or browser cancellation.
        original_close = response.close

        def close():
            original_close()
            session.close()

        response.close = close
        return response
    except requests.RequestException:
        session.close()
        raise APIError("Worker connection failed; no retry was started", status_code=502) from None
    except Exception:
        session.close()
        raise


def worker_json(path, *, method="GET", payload=None, params=None):
    response = call_worker(path, method=method, payload=payload, params=params)
    try:
        if not response.ok or response.is_redirect:
            raise APIError(f"Worker rejected the operation (HTTP {response.status_code}); check session, settings, and deployment",
                           status_code=response.status_code if 400 <= response.status_code < 600 else 502)
        data = bytearray()
        for chunk in response.iter_content(8192):
            data.extend(chunk)
            if len(data) > 1024 * 1024:
                raise APIError("Worker response exceeds the workbench limit", status_code=502)
        import json
        return json.loads(data)
    except (ValueError, requests.RequestException):
        raise APIError("Worker returned an invalid response", status_code=502) from None
    finally:
        response.close()
