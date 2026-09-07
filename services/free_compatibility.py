"""Recognize bounded request/model mismatches without exposing upstream content."""

import json
import re
from itertools import chain

from flask import Response

from route_helpers import stream_upstream_response

ERROR_BYTES = 16384
_MISMATCH = re.compile(
    r"request too large for model|"
    r"too many images|supports? (?:up to |at most |a maximum of )\d+ images|"
    r"(?:maximum|max) (?:number of images|context length)|context_length_exceeded|"
    r"(?:image|vision) (?:input )?(?:is |are )?not supported|"
    r"(?:unsupported|not supported|not support|invalid)[^\n]{0,100}(?:response_format|json_schema)|"
    r"(?:response_format|json_schema)[^\n]{0,100}(?:unsupported|not supported|not support)|"
    r"no endpoints found that support",
    re.IGNORECASE,
)


def inspect_compatibility_detail(upstream):
    """Replay inspected bytes for ordinary errors, including streaming transports."""
    if upstream.status_code not in {400, 413, 422}:
        return upstream, None
    response = upstream if isinstance(upstream, Response) else stream_upstream_response(upstream)
    iterator = iter(response.iter_encoded())
    buffered = []
    size = 0
    while size <= ERROR_BYTES:
        chunk = next(iterator, None)
        if chunk is None:
            break
        buffered.append(chunk)
        size += len(chunk)
    response.response = chain(buffered, iterator)
    if size > ERROR_BYTES:
        return response, None
    try:
        payload = json.loads(b"".join(buffered))
    except (ValueError, UnicodeError):
        return response, None
    error = payload.get("error") if isinstance(payload, dict) else None
    if not isinstance(error, dict):
        return response, None
    text = " ".join(str(error.get(field, "")) for field in ("message", "code", "param"))
    if not _MISMATCH.search(text):
        return response, None
    if re.search(r"request too large for model|context length|context_length_exceeded", text, re.I):
        return response, "input_too_large"
    if re.search(r"too many images|number of images|\d+ images", text, re.I):
        return response, "image_limit"
    if re.search(r"response_format|json_schema|no endpoints found that support", text, re.I):
        return response, "output_format"
    return response, "vision_input"


def inspect_compatibility(upstream):
    """Keep the boolean inspection contract for existing callers."""
    response, reason = inspect_compatibility_detail(upstream)
    return response, reason is not None
