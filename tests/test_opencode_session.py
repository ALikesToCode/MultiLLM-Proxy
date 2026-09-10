import json
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest

from services.opencode_session import (
    MAX_SESSION_BODY_BYTES,
    with_opencode_request_session,
)
from services.proxy_service import ProxyService

AUTH = {"Authorization": "Bearer synthetic-provider-key"}
OPENING = [
    {"role": "system", "content": "Synthetic coding assistant"},
    {"role": "user", "content": "Fix the parser"},
]


def session(payload, headers=None):
    return with_opencode_request_session(
        AUTH if headers is None else headers, json.dumps(payload).encode()
    )["X-Opencode-Session"]


@pytest.mark.parametrize(
    "path", ["v1/chat/completions", "v1/messages", "v1/responses", "v1/models"]
)
def test_final_transport_always_supplies_session_without_changing_body(path):
    data = json.dumps({"messages": OPENING}).encode()
    headers = ProxyService.prepare_headers(
        {}, "opencode", "synthetic-provider-key", upstream_path=path
    )
    with patch.object(ProxyService, "_make_base_request") as send:
        ProxyService.make_request(
            "POST",
            f"https://provider.example/{path}",
            headers,
            {},
            data,
            "opencode",
            force_raw_passthrough=True,
        )
    sent = send.call_args.kwargs
    assert sent["headers"]["X-Opencode-Session"].startswith("multillm_v1_")
    assert sent["data"] is data
    assert "X-Opencode-Session" not in headers


def test_opening_is_stable_across_turns_models_retries_and_parameter_changes():
    first = session({"messages": OPENING, "model": "first", "stream": True})
    later = {
        "messages": OPENING
        + [
            {"role": "assistant", "content": "Done"},
            {"role": "user", "content": "Add tests"},
        ],
        "model": "second",
        "temperature": 0.2,
    }
    assert first == session(later) == session(later)
    assert "synthetic" not in first and "parser" not in first
    assert len(first) == len("multillm_v1_") + 64


@pytest.mark.parametrize(
    "payload",
    [
        {"session_id": "body-session"},
        {"conversation_id": "body-session"},
        {"metadata": {"session_id": "body-session"}},
        {"metadata": {"conversation_id": "body-session"}},
        {"conversation": "body-session"},
        {"conversation": {"id": "body-session"}},
    ],
)
def test_body_conversation_ids_are_stable_but_opaque(payload):
    assert session(payload) == session({**payload, "messages": OPENING})
    assert "body-session" not in session(payload)


def test_responses_string_and_message_input_use_same_anchor():
    assert session({"input": "Fix the parser"}) == session(
        {"input": [{"role": "user", "content": "Fix the parser"}]}
    )


def test_different_credentials_openings_and_instructions_do_not_share_affinity():
    baseline = session({"messages": OPENING})
    assert baseline != session(
        {"messages": OPENING}, {"Authorization": "Bearer different-key"}
    )
    assert baseline != session(
        {"messages": [{"role": "user", "content": "Unrelated task"}]}
    )
    assert baseline != session({"messages": OPENING, "system": "A different task"})
    assert baseline != session(
        {"messages": OPENING, "instructions": "Other instructions"}
    )


def test_concurrent_requests_do_not_share_mutable_state():
    payloads = [{"session_id": f"conversation-{index}"} for index in range(20)]
    with ThreadPoolExecutor(max_workers=4) as pool:
        result = list(pool.map(session, payloads))
    assert len(set(result)) == 20
    assert result == list(map(session, payloads))


@pytest.mark.parametrize(
    "name",
    [
        "x-opencode-session",
        "thread-id",
        "session-id",
        "session_id",
        "x-session-affinity",
    ],
)
def test_explicit_ids_win_even_when_body_is_unreadable(name):
    assert (
        with_opencode_request_session({**AUTH, name: "explicit"}, b"invalid")[
            "X-Opencode-Session"
        ]
        == "explicit"
    )


@pytest.mark.parametrize(
    "data",
    [
        None,
        b"",
        b"not json",
        b"[]",
        b"{}",
        b'{"messages":[]}',
        b'{"messages":[{"role":"system","content":"shared"}]}',
        b"x" * (MAX_SESSION_BODY_BYTES + 1),
    ],
)
def test_unusable_body_gets_unique_request_session(data):
    one = with_opencode_request_session(AUTH, data)["X-Opencode-Session"]
    two = with_opencode_request_session(AUTH, data)["X-Opencode-Session"]
    assert one.startswith("multillm_request_")
    assert two != one


def test_no_credentials_and_blank_explicit_header_never_produce_shared_default():
    assert session({"messages": OPENING}, {}) != session({"messages": OPENING}, {})
    assert session(
        {"messages": OPENING}, {**AUTH, "x-opencode-session": " "}
    ).startswith("multillm_v1_")


def test_existing_session_survives_repeated_transport_preparation():
    first = with_opencode_request_session(AUTH, b"{}")
    assert (
        with_opencode_request_session(first, b"{}")["X-Opencode-Session"]
        == first["X-Opencode-Session"]
    )


def test_cross_runtime_unicode_and_content_order_contract():
    payload = {
        "messages": [
            {"role": "user", "content": [{"type": "text", "text": "Fix café ☀️"}]}
        ]
    }
    assert (
        session(payload)
        == "multillm_v1_83fe68c7b57180ce4a00dad94ce61a386749ceeeab759bc938035d56734c00e2"
    )
