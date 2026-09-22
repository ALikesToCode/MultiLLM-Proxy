import json
import re
import threading
import time

import pytest
import requests

from services import intelligence_d1_store as d1
from services import intelligence_store as local_store
from services.intelligence_contract import GatewayError
from services.intelligence_store import IntelligenceStore
from tests.test_intelligence_policy import policy


class Reply:
    def __init__(
        self, document=None, *, status=200, raw=None, headers=None, chunks=None
    ):
        self.status_code = status
        self.headers = {"Content-Type": "application/json", **(headers or {})}
        self.body = json.dumps(document).encode() if raw is None else raw
        self.chunks = chunks
        self.closed = False
        self.reads = 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def iter_content(self, chunk_size):
        self.reads += 1
        yield from self.chunks if self.chunks is not None else [self.body]


class Transport:
    def __init__(self):
        self.replies = []
        self.calls = []
        self.sessions = []

    def session(self):
        owner = self

        class Session:
            trust_env = True
            closed = False

            def __init__(self):
                self.adapters = {}

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.closed = True

            def mount(self, prefix, adapter):
                self.adapters[prefix] = adapter

            def post(self, url, **kwargs):
                payload = json.loads(kwargs["data"])
                owner.calls.append((url, payload, kwargs))
                reply = owner.replies.pop(0)
                if isinstance(reply, Exception):
                    raise reply
                return reply(payload) if callable(reply) else reply

        session = Session()
        self.sessions.append(session)
        return session


@pytest.fixture
def transport(monkeypatch):
    fake = Transport()
    monkeypatch.setattr(d1.requests, "Session", fake.session)
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "d1")
    monkeypatch.setenv("INTELLIGENCE_REQUIRE_DURABLE_STORAGE", "true")
    monkeypatch.setenv("CONTROL_PLANE_DATABASE_URL", "")
    monkeypatch.delenv("INTELLIGENCE_POLICY_JSON", raising=False)

    def local_connection_forbidden(*args, **kwargs):
        pytest.fail("D1 must never use the local or PostgreSQL connection")

    monkeypatch.setattr(local_store, "connect", local_connection_forbidden)
    return fake


def unavailable(action):
    with pytest.raises(GatewayError) as raised:
        action()
    error = raised.value
    assert error.code == "intelligence_store_unavailable"
    assert error.status == 503
    assert not error.retryable and error.retry_after is None
    assert "synthetic-private-detail" not in str(error)
    return error


def test_policy_uses_private_url_and_disables_environment_redirects_and_retries(
    transport, monkeypatch
):
    monkeypatch.setenv("HTTP_PROXY", "http://synthetic.invalid")
    monkeypatch.setenv("INTELLIGENCE_STORE_URL", "https://synthetic.invalid/store")
    reply = Reply({"version": 1, "policy": policy()})
    transport.replies.append(reply)
    assert IntelligenceStore.policy() == policy()
    url, payload, options = transport.calls[0]
    assert url == "http://intelligence.internal/v1/store"
    assert payload == {"version": 1, "operation": "policy"}
    assert options["timeout"] == (2, 3)
    assert options["stream"] is True and options["allow_redirects"] is False
    assert options["headers"] == {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Accept-Encoding": "identity",
    }
    session = transport.sessions[0]
    assert session.trust_env is False
    assert session.adapters["http://"].max_retries.total == 0
    assert session.adapters["http://"].max_retries.read is False
    assert session.closed and reply.closed


def test_missing_policy_is_disabled_without_an_unpersisted_seed(transport):
    transport.replies.append(Reply({"version": 1, "policy": None}))
    assert IntelligenceStore.policy()["enabled"] is False
    assert len(transport.calls) == 1


def test_first_seed_reloads_the_winning_stored_policy_and_never_overwrites(
    transport, monkeypatch
):
    seeded = policy(global_daily_tokens=200)
    winner = policy(global_daily_tokens=100)
    monkeypatch.setenv("INTELLIGENCE_POLICY_JSON", json.dumps(seeded))
    transport.replies.extend(
        [
            Reply({"version": 1, "policy": None}),
            Reply({"version": 1, "inserted": False}),
            Reply({"version": 1, "policy": winner}),
            Reply({"version": 1, "policy": winner}),
        ]
    )
    assert IntelligenceStore.policy() == winner
    assert transport.calls[1][1] == {
        "version": 1,
        "operation": "seed",
        "policy": seeded,
    }
    monkeypatch.setenv("INTELLIGENCE_POLICY_JSON", "invalid replacement")
    assert IntelligenceStore().policy() == winner
    assert [call[1]["operation"] for call in transport.calls] == [
        "policy",
        "seed",
        "policy",
        "policy",
    ]


@pytest.mark.parametrize("seed", ["malformed", "null", '{"enabled":"true"}'])
def test_invalid_environment_seed_fails_without_a_write(transport, monkeypatch, seed):
    monkeypatch.setenv("INTELLIGENCE_POLICY_JSON", seed)
    transport.replies.append(Reply({"version": 1, "policy": None}))
    unavailable(IntelligenceStore.policy)
    assert len(transport.calls) == 1


def test_seed_must_be_read_back_without_unbounded_recursion(transport, monkeypatch):
    monkeypatch.setenv("INTELLIGENCE_POLICY_JSON", json.dumps(policy()))
    transport.replies.extend(
        [
            Reply({"version": 1, "policy": None}),
            Reply({"version": 1, "inserted": True}),
            Reply({"version": 1, "policy": None}),
        ]
    )
    unavailable(IntelligenceStore.policy)
    assert len(transport.calls) == 3


@pytest.mark.parametrize(
    "document",
    [[], "synthetic-private-detail", {"enabled": 1}, {"version": 2}, {"unknown": True}],
)
def test_malformed_stored_policy_fails_closed(transport, document):
    transport.replies.append(Reply({"version": 1, "policy": document}))
    unavailable(IntelligenceStore.policy)
    assert len(transport.calls) == 1


@pytest.mark.parametrize("inserted", [True, False])
def test_explicit_seed_validates_and_preserves_insert_only_result(transport, inserted):
    transport.replies.append(Reply({"version": 1, "inserted": inserted}))
    assert IntelligenceStore.seed({"enabled": True}) is inserted
    assert transport.calls[0][1]["policy"] == d1.validate_policy({"enabled": True})
    with pytest.raises(ValueError):
        IntelligenceStore.seed({"enabled": "true"})
    assert len(transport.calls) == 1


@pytest.mark.parametrize("kind", ["chat", "transcriptions", "speech", "embeddings"])
def test_reserve_generates_unique_ids_without_sending_policy_or_clock(transport, kind):
    transport.replies.extend([lambda body: Reply({"version": 1, "id": body["id"]})] * 2)
    first = IntelligenceStore.reserve(
        "integration:omni", 1, {"untrusted": "ignored"}, kind=kind, now=-999
    )
    second = IntelligenceStore.reserve(
        "integration:omni", 1, None, kind=kind, now=10**30
    )
    assert first != second and re.fullmatch(r"[0-9a-f]{32}", first)
    assert transport.calls[0][1] == {
        "version": 1,
        "operation": "reserve",
        "id": first,
        "principal": "integration:omni",
        "amount": 1,
        "kind": kind,
    }


@pytest.mark.parametrize("returned", ["a" * 32, "bad", None, True])
def test_reserve_must_echo_the_new_client_identifier(transport, returned):
    transport.replies.append(Reply({"version": 1, "id": returned}))
    unavailable(lambda: IntelligenceStore.reserve("caller", 10, policy()))
    assert len(transport.calls) == 1


@pytest.mark.parametrize(
    "principal,amount,kind",
    [
        ("", 1, "chat"),
        ("p" * 257, 1, "chat"),
        ("bad\nprincipal", 1, "chat"),
        ("bad\x7fprincipal", 1, "chat"),
        (None, 1, "chat"),
        ("caller", 0, "chat"),
        ("caller", -1, "chat"),
        ("caller", True, "chat"),
        ("caller", 2**53, "chat"),
        ("caller", 1.5, "chat"),
        ("caller", 1, "unknown"),
        ("caller", 1, []),
        ("caller", 2, "transcriptions"),
        ("caller", 2, "speech"),
        ("caller", 2, "embeddings"),
    ],
)
def test_invalid_reservation_is_rejected_before_transport(
    transport, principal, amount, kind
):
    unavailable(
        lambda: IntelligenceStore.reserve(principal, amount, policy(), kind=kind)
    )
    assert transport.calls == []


@pytest.mark.parametrize(
    "complete,used", [(True, 0), (True, 75), (False, 0), (False, 150)]
)
def test_settlement_transmits_exact_usage_and_keeps_public_return_contract(
    transport, complete, used
):
    identifier = "b" * 32
    transport.replies.append(Reply({"version": 1, "settled": True}))
    assert IntelligenceStore.settle(identifier, used, complete) is None
    assert transport.calls[0][1] == {
        "version": 1,
        "operation": "settle",
        "id": identifier,
        "used": used,
        "complete": complete,
    }


def test_missing_or_repeated_settlement_is_a_no_op(transport):
    transport.replies.append(Reply({"version": 1, "settled": False}))
    assert IntelligenceStore.settle("c" * 32, 0, True) is None
    assert len(transport.calls) == 1


@pytest.mark.parametrize(
    "identifier,used,complete",
    [
        ("bad", 0, True),
        ("A" * 32, 0, True),
        ("c" * 32 + "\n", 0, True),
        (None, 0, True),
        ("c" * 32, -1, True),
        ("c" * 32, True, True),
        ("c" * 32, 2**53, True),
        ("c" * 32, 0, 1),
    ],
)
def test_invalid_settlement_never_dispatches(transport, identifier, used, complete):
    unavailable(lambda: IntelligenceStore.settle(identifier, used, complete))
    assert transport.calls == []


@pytest.mark.parametrize(
    "operation,field", [("seed", "inserted"), ("settle", "settled")]
)
@pytest.mark.parametrize("value", [1, None, "true"])
def test_boolean_acknowledgements_are_strict(transport, operation, field, value):
    transport.replies.append(Reply({"version": 1, field: value}))
    action = (
        (lambda: IntelligenceStore.seed(policy()))
        if operation == "seed"
        else (lambda: IntelligenceStore.settle("d" * 32, 0, False))
    )
    unavailable(action)
    assert len(transport.calls) == 1


def test_allowance_error_preserves_safe_retry_hints(transport):
    transport.replies.append(
        Reply(
            {
                "version": 1,
                "error": {
                    "code": "allowance_exhausted",
                    "message": "synthetic-private-detail",
                },
            },
            status=429,
        )
    )
    with pytest.raises(GatewayError) as raised:
        IntelligenceStore.reserve("caller", 10, policy())
    error = raised.value
    assert error.code == "allowance_exhausted" and error.status == 429
    assert error.retryable and error.retry_after == "60"
    assert "synthetic-private-detail" not in str(error)
    assert len(transport.calls) == 1


@pytest.mark.parametrize(
    "status,code",
    [
        (400, "invalid_store_request"),
        (409, "reservation_conflict"),
        (409, "intelligence_policy_changed"),
        (429, "unknown"),
        (503, "intelligence_store_unavailable"),
    ],
)
def test_storage_errors_are_sanitized_and_never_retried(transport, status, code):
    transport.replies.append(
        Reply(
            {
                "version": 1,
                "error": {"code": code, "message": "synthetic-private-detail"},
            },
            status=status,
        )
    )
    unavailable(lambda: IntelligenceStore.reserve("caller", 10, policy()))
    assert len(transport.calls) == 1


@pytest.mark.parametrize(
    "failure",
    [
        requests.Timeout,
        requests.ConnectionError,
        requests.exceptions.ChunkedEncodingError,
    ],
)
def test_ambiguous_reserve_can_hold_allowance_and_is_never_replayed(transport, failure):
    held = {}

    def admitted_then_disconnected(body):
        held[body["id"]] = body["amount"]
        raise failure("synthetic-private-detail")

    transport.replies.append(admitted_then_disconnected)
    unavailable(lambda: IntelligenceStore.reserve("caller", 70, policy()))
    assert list(held.values()) == [70]
    assert len(transport.calls) == 1


def test_failed_settlement_never_releases_a_held_reservation(transport):
    held = {}

    def admit(body):
        held[body["id"]] = body["amount"]
        return Reply({"version": 1, "id": body["id"]})

    transport.replies.extend([admit, requests.Timeout("synthetic-private-detail")])
    identifier = IntelligenceStore.reserve("caller", 70, policy())
    unavailable(lambda: IntelligenceStore.settle(identifier, 0, True))
    assert held == {identifier: 70}
    assert [call[1]["operation"] for call in transport.calls] == ["reserve", "settle"]


@pytest.mark.parametrize(
    "raw",
    [
        b"not json",
        b"[]",
        b'{"policy":null}',
        b'{"version":true,"policy":null}',
        b'{"version":2,"policy":null}',
        b'{"version":1,"policy":NaN}',
        b'{"version":1,"policy":null,"policy":{}}',
        b'{"version":1,"policy":null,"extra":true}',
        b'{"version":1,"error":{"code":"failed"}}',
        b"\xff",
    ],
)
def test_malformed_responses_fail_closed(transport, raw):
    transport.replies.append(Reply(raw=raw))
    unavailable(IntelligenceStore.policy)
    assert len(transport.calls) == 1


@pytest.mark.parametrize(
    "headers",
    [
        {"Content-Length": "262145"},
        {"Content-Length": "-1"},
        {"Content-Length": "unknown"},
        {"Content-Encoding": "gzip"},
        {"Content-Type": "text/html"},
    ],
)
def test_unsafe_response_headers_are_rejected_before_body_read(transport, headers):
    reply = Reply({"version": 1, "policy": None}, headers=headers)
    transport.replies.append(reply)
    unavailable(IntelligenceStore.policy)
    assert reply.reads == 0 and reply.closed


def test_response_body_is_bounded_even_when_content_length_lies(transport):
    reply = Reply(
        headers={"Content-Length": "1"}, chunks=[b" " * 131072, b" " * 131073]
    )
    transport.replies.append(reply)
    unavailable(IntelligenceStore.policy)
    assert reply.closed and len(transport.calls) == 1


def test_redirect_is_not_followed(transport):
    transport.replies.append(
        Reply(
            {"version": 1, "error": {"code": "redirect"}},
            status=302,
            headers={"Location": "https://synthetic.invalid"},
        )
    )
    unavailable(IntelligenceStore.policy)
    assert len(transport.calls) == 1


def test_wall_deadline_bounds_stalled_headers_without_replaying(transport, monkeypatch):
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    monkeypatch.setattr(d1, "_DEADLINE_SECONDS", 0.05)

    def stalled(body):
        entered.set()
        release.wait(timeout=2)
        finished.set()
        return Reply({"version": 1, "policy": None})

    transport.replies.append(stalled)
    started = time.monotonic()
    try:
        unavailable(IntelligenceStore.policy)
        assert entered.is_set() and time.monotonic() - started < 1
        assert len(transport.calls) == 1
    finally:
        release.set()
        assert finished.wait(timeout=2)


def test_transport_capacity_exhaustion_does_not_dispatch(transport, monkeypatch):
    monkeypatch.setattr(d1, "_TRANSPORT_SLOTS", threading.BoundedSemaphore(0))
    unavailable(IntelligenceStore.policy)
    assert transport.calls == []


@pytest.mark.parametrize("backend", ["postgres", "sqlite", "unknown", "D1"])
def test_unknown_explicit_backend_cannot_fall_back(transport, monkeypatch, backend):
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", backend)
    for action in (
        IntelligenceStore.policy,
        lambda: IntelligenceStore.seed(policy()),
        lambda: IntelligenceStore.reserve("caller", 1, policy()),
        lambda: IntelligenceStore.settle("a" * 32, 0, True),
    ):
        unavailable(action)
    assert transport.calls == []


def test_d1_has_no_direct_local_connection_escape(transport):
    unavailable(IntelligenceStore.connect)
    assert transport.calls == []


@pytest.mark.parametrize(
    "status,operation,document",
    [
        (200, "lookup", {"version": 1, "principal": None}),
        (201, "provision", {"version": 1, "credentialVersion": 1}),
    ],
)
def test_auth_uses_only_the_second_fixed_endpoint_and_retains_bounded_error_codes(
    transport,
    status,
    operation,
    document,
):
    transport.replies.append(Reply(document, status=status))
    assert (
        d1.request_private_intelligence(
            {"operation": operation, "version": 999}, endpoint="auth"
        )
        == document
    )
    assert transport.calls[0][0] == "http://intelligence.internal/v1/auth"
    assert transport.calls[0][1]["version"] == 1
    transport.replies.append(
        Reply(
            {
                "version": 1,
                "error": {
                    "code": "credential_conflict",
                    "message": "synthetic-private-detail",
                },
            },
            status=409,
        )
    )
    with pytest.raises(d1.PrivateIntelligenceError) as raised:
        d1.request_private_intelligence({"operation": "lookup"}, endpoint="auth")
    assert raised.value.status == 409 and raised.value.code == "credential_conflict"
    assert "synthetic-private-detail" not in str(raised.value)


def test_store_rejects_auth_only_created_status(transport):
    transport.replies.append(Reply({"version": 1, "policy": policy()}, status=201))
    unavailable(IntelligenceStore.policy)
    assert len(transport.calls) == 1


@pytest.mark.parametrize(
    "endpoint,payload",
    [
        ("https://synthetic.invalid", {}),
        ([], {}),
        ("../auth", {}),
        ("store", {"data": "x" * 262144}),
        ("store", {"value": float("nan")}),
        ("store", None),
    ],
)
def test_private_transport_rejects_invalid_targets_and_payloads_without_sending(
    transport, endpoint, payload
):
    unavailable(lambda: d1.request_private_intelligence(payload, endpoint=endpoint))
    assert transport.calls == []
