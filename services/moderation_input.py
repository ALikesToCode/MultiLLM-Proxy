"""Validate the gateway's bounded OpenAI-compatible moderation input."""

import base64
import binascii
import re
from urllib.parse import urlsplit

from error_handlers import APIError

MAX_MODERATION_BODY_BYTES = 32 * 1024 * 1024
MAX_MODERATION_INPUTS = 2048
MAX_IMAGE_BYTES = 20 * 1024 * 1024
_DATA_IMAGE = re.compile(r"data:image/(?:png|jpeg|webp|gif);base64,([A-Za-z0-9+/=]+)\Z")


def _image_url(value):
    if not isinstance(value, dict) or set(value) != {"url"} or not isinstance(value["url"], str):
        raise APIError("image_url must contain a url string", status_code=400)
    url = value["url"]
    if url.startswith("data:"):
        match = _DATA_IMAGE.fullmatch(url)
        if not match:
            raise APIError("Use a PNG, JPEG, WebP or GIF base64 data URL", status_code=400)
        try:
            image = base64.b64decode(match[1], validate=True)
        except binascii.Error as error:
            raise APIError("Invalid image base64", status_code=400) from error
        if not image or len(image) > MAX_IMAGE_BYTES:
            raise APIError("An inline image must hold 1 byte to 20 MiB", status_code=413 if image else 400)
        return
    try:
        parts = urlsplit(url)
        valid = parts.scheme == "https" and parts.hostname and not parts.username and not parts.password
    except ValueError:
        valid = False
    if not valid:
        raise APIError("Image URLs must use HTTPS or base64 data URLs", status_code=400)


def validate_moderation_input(value):
    """Accept text, a text batch, or one flat list of text/image parts."""
    if isinstance(value, str) and value.strip():
        return
    if not isinstance(value, list) or not value or len(value) > MAX_MODERATION_INPUTS:
        raise APIError("input must be text or an array of 1 to 2048 strings or content parts", status_code=400)
    if all(isinstance(item, str) and item.strip() for item in value):
        return
    for item in value:
        if not isinstance(item, dict):
            raise APIError("Do not mix strings and content parts in input", status_code=400)
        if item.get("type") == "text" and set(item) == {"type", "text"}:
            if not isinstance(item["text"], str) or not item["text"].strip():
                raise APIError("A text part must contain non-empty text", status_code=400)
        elif item.get("type") == "image_url" and set(item) == {"type", "image_url"}:
            _image_url(item["image_url"])
        else:
            raise APIError("Content parts must be text or image_url objects", status_code=400)


def has_images(value):
    return isinstance(value, list) and any(isinstance(item, dict) and item.get("type") == "image_url" for item in value)


def text_only_input(value):
    """NavyAI documents strings and string arrays, rather than content parts."""
    if isinstance(value, list) and value and isinstance(value[0], dict):
        return [item["text"] for item in value]
    return value
