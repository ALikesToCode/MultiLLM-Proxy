"""Compatibility wrappers over services.protocol_translation for older imports."""

from __future__ import annotations

from services.protocol_translation import CHAT, RESPONSES, translate_request, translate_response


def responses_input_to_messages(payload: dict) -> list[dict]:
    """Translate a Responses request's instructions and input into chat messages."""
    return translate_request(payload, RESPONSES, CHAT)["messages"]


def chat_response_to_responses_payload(
    chat_payload: dict,
    requested_model: str,
) -> dict:
    """Translate one non-streaming Chat Completions result to Responses."""
    return translate_response(chat_payload, CHAT, RESPONSES, model=requested_model)
