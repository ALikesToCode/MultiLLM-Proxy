"""Extract only submitted text from the generation routes served by Flask."""

import re

_GENERATION = re.compile(r"/(?:[a-z0-9_-]+/)?(?:openai/)?(?P<operation>v1/(?:chat/completions|responses|messages|"
                         r"images/(?:generations|edits|batch|batches)|videos(?:/generations)?)|chat/completions)/?\Z")
_FREE_CHAT = re.compile(r"/v1/free/(?:[a-z0-9_-]+/)?chat/completions/?\Z")


def generation_kind(path):
    if _FREE_CHAT.fullmatch(path):
        return "completions"
    match = _GENERATION.fullmatch(path)
    if match is None:
        return None
    operation = match["operation"]
    if "images/" in operation:
        return "batch" if operation.endswith(("/batch", "/batches")) else "images"
    return "videos" if "videos" in operation else operation.rsplit("/", 1)[-1]


def _text(content):
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    return "\n".join(part["text"] for part in content if isinstance(part, dict)
                     and part.get("type") in {"text", "input_text"} and isinstance(part.get("text"), str))


def _latest_user(messages):
    if not isinstance(messages, list):
        return ""
    for message in reversed(messages):
        if isinstance(message, dict) and message.get("role") == "user":
            return _text(message.get("content"))
    return ""


def generation_texts(kind, body, form=None):
    if form is not None:
        values = [form.get("prompt", "")]
    elif not isinstance(body, dict):
        return []
    elif kind in {"completions", "messages"}:
        values = [_latest_user(body.get("messages"))]
    elif kind == "responses":
        value = body.get("input")
        if isinstance(value, list) and any(isinstance(item, dict) and "role" in item for item in value):
            values = [_latest_user(value)]
        else:
            values = [_text(value)]
    elif kind == "batch":
        defaults = body.get("defaults") if isinstance(body.get("defaults"), dict) else {}
        items = body.get("items") if isinstance(body.get("items"), list) else []
        values = [item.get("prompt", defaults.get("prompt", "")) for item in items if isinstance(item, dict)]
    else:
        values = [body.get("prompt", "")]
    return [value for value in values if isinstance(value, str) and value.strip()]
