"""Asynchronous media jobs in the Worker's D1, through `http://intelligence.internal/v1/media-jobs`.

The Worker stores jobs and starts the Workflow that runs them (worker/media-jobs.mjs), so
jobs outlive Container sleep. Each call is sent once and never replayed.
"""

from __future__ import annotations

import json
import os

import requests
from requests.adapters import HTTPAdapter

ENDPOINT = "http://intelligence.internal/v1/media-jobs"
TIMEOUT = (3, 30)
MAX_REQUEST_BYTES = 4 * 1024 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class MediaJobError(Exception):
    """A refused or failed job operation, with the Worker's status and error code."""

    def __init__(self, status: int, code: str):
        super().__init__(code)
        self.status, self.code = status, code


def enabled() -> bool:
    """The Worker binds the job Workflow and D1 (it sets MEDIA_JOBS_ENABLED for the Container)."""
    return os.environ.get("MEDIA_JOBS_ENABLED", "").strip().lower() == "true"


def call(operation: str, **fields) -> dict:
    body = json.dumps({"version": 1, "operation": operation, **fields}, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_REQUEST_BYTES:
        raise MediaJobError(413, "request_too_large")
    try:
        with requests.Session() as session:
            session.trust_env = False
            session.mount("http://", HTTPAdapter(max_retries=0))
            with session.post(ENDPOINT, data=body, timeout=TIMEOUT, allow_redirects=False, stream=True,
                              headers={"Content-Type": "application/json", "Accept": "application/json"}) as response:
                content = bytearray()
                for chunk in response.iter_content(65536):
                    content.extend(chunk)
                    if len(content) > MAX_RESPONSE_BYTES:
                        raise MediaJobError(502, "response_too_large")
                status = response.status_code
    except requests.exceptions.RequestException:
        raise MediaJobError(503, "storage_unavailable") from None
    try:
        payload = json.loads(content)
    except ValueError:
        raise MediaJobError(502, "invalid_reply") from None
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise MediaJobError(502, "invalid_reply")
    if status != 200:
        error = payload.get("error")
        code = error.get("code") if isinstance(error, dict) else None
        raise MediaJobError(status, code if isinstance(code, str) and len(code) <= 64 else "storage_unavailable")
    return payload
