import json

import requests

UPSTREAM_FAILURE_MESSAGE = "Upstream request could not be completed."
STREAM_FAILURE_MESSAGE = "Upstream stream terminated unexpectedly."


def authentication_error_response(
    provider: str,
    *,
    solution: str,
    details: str,
    model: str | None = None,
) -> requests.Response:
    """Build a provider-authentication error without reflecting upstream details."""
    access_context = f" or lacks access to model {model}" if model else ""
    payload = {
        "error": {
            "message": (
                f"Authentication failed for {provider}. The configured provider "
                f"credential was rejected{access_context}."
            ),
            "solution": solution,
            "details": details,
        }
    }
    content = json.dumps(payload).encode("utf-8")
    response = requests.Response()
    response.status_code = 401
    response._content = content
    response.headers.update(
        {
            "Content-Type": "application/json",
            "Content-Length": str(len(content)),
        }
    )
    return response


def stream_error_event(*, model: str = "upstream") -> str:
    """Return an OpenAI-compatible SSE frame with an opaque failure message."""
    payload = {
        "object": "chat.completion.chunk",
        "model": model,
        "choices": [{"delta": {"content": STREAM_FAILURE_MESSAGE}}],
    }
    return f"data: {json.dumps(payload)}\n\n"
