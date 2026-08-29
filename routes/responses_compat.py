from __future__ import annotations

import time
import uuid


def responses_input_to_messages(payload: dict) -> list[dict]:
    """Translate the compatible Responses input subset into chat messages."""
    messages: list[dict] = []
    instructions = payload.get("instructions")
    if instructions:
        messages.append({"role": "system", "content": instructions})

    input_value = payload.get("input", "")
    if isinstance(input_value, str):
        messages.append({"role": "user", "content": input_value})
    elif isinstance(input_value, list):
        for item in input_value:
            if (
                isinstance(item, dict)
                and item.get("role")
                and item.get("content") is not None
            ):
                messages.append(
                    {"role": item["role"], "content": item["content"]}
                )
            elif isinstance(item, dict) and item.get("type") in {
                "message",
                "input_text",
            }:
                messages.append(
                    {
                        "role": item.get("role", "user"),
                        "content": item.get("content") or item.get("text", ""),
                    }
                )
            else:
                messages.append({"role": "user", "content": str(item)})
    else:
        messages.append({"role": "user", "content": str(input_value)})

    return messages


def chat_response_to_responses_payload(
    chat_payload: dict,
    requested_model: str,
) -> dict:
    """Translate one non-streaming Chat Completions result to Responses."""
    choices = chat_payload.get("choices") or []
    first_choice = choices[0] if choices else {}
    message = first_choice.get("message") or {}
    text = message.get("content") or ""
    return {
        "id": chat_payload.get("id", f"resp_{uuid.uuid4().hex}"),
        "object": "response",
        "created_at": int(time.time()),
        "status": "completed",
        "model": requested_model,
        "output": [
            {
                "id": f"msg_{uuid.uuid4().hex}",
                "type": "message",
                "status": "completed",
                "role": "assistant",
                "content": [
                    {
                        "type": "output_text",
                        "text": text,
                        "annotations": [],
                    }
                ],
            }
        ],
        "output_text": text,
        "usage": chat_payload.get("usage"),
    }
