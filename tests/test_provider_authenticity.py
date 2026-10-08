"""Offline diagnostics with synthetic keys, catalog data and completions."""

import copy
import io
import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from scripts import provider_authenticity as cli
from services.provider_authenticity import (
    ConfigError,
    MAX_RESPONSE_BYTES,
    RequestsTransport,
    diagnostic_plan,
    evaluate_chat,
    run_diagnostics,
    validate_target,
)

BASE = "https://gateway.example"
MODEL = "nanogpt:example-model"
NONCES = ("a" * 32, "b" * 32)
PRIVATE = "synthetic-private-canary"


def catalog():
    return {"object": "list", "data": [{"id": MODEL}]}


def completion(nonce=NONCES[0], **fields):
    return {
        "id": "chatcmpl-fixture",
        "object": "chat.completion",
        "created": 123,
        "model": MODEL,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": nonce},
                     "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30},
        **fields,
    }


class FakeResponse:
    def __init__(self, body=None, *, status=200, raw=None, read_error=None, close_error=None):
        self.status_code = status
        self.raw = raw if raw is not None else json.dumps(body).encode()
        self.read_error = read_error
        self.close_error = close_error
        self.closed = 0

    def iter_content(self, chunk_size):
        if self.read_error:
            raise self.read_error
        for start in range(0, len(self.raw), chunk_size):
            yield self.raw[start:start + chunk_size]

    def close(self):
        self.closed += 1
        if self.close_error:
            raise self.close_error


class FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, copy.deepcopy(kwargs)))
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def run(responses, *, generation=False, nonce_factory=None):
    client = FakeTransport(responses)
    nonces = iter(NONCES)
    report = run_diagnostics(
        BASE, MODEL, client=client, api_key=PRIVATE, allow_generation=generation,
        nonce_factory=nonce_factory or (lambda: next(nonces)),
    )
    return report, client


def valid_responses():
    return [FakeResponse(catalog()), *[FakeResponse(completion(n)) for n in NONCES]]


def test_default_is_one_metadata_request_and_inconclusive():
    response = FakeResponse(catalog())
    report, client = run([response])
    assert report["verdict"] == "unknown"
    assert report["claim"] == "model_identity"
    assert report["generation_requests"] == 0
    assert report["coverage"] == ["catalog_claim"]
    assert "identity_not_verified" in report["limitations"]
    assert len(client.calls) == 1
    assert client.calls[0][0:2] == ("GET", BASE + "/v1/models")
    assert response.closed == 1


def test_plan_and_explicit_probes_have_finite_caps():
    plan = diagnostic_plan(allow_generation=True)
    assert plan["request_budget"] == 3
    assert plan["generation_request_budget"] == 2
    assert plan["max_tokens_per_request"] == 64
    assert plan["max_output_tokens"] == 128
    assert plan["timeout_seconds"] == 10
    assert plan["projected_cost"] is None
    assert diagnostic_plan()["generation_request_budget"] == 0
    responses = valid_responses()
    report, client = run(responses, generation=True)
    assert report["verdict"] == "supported"
    assert report["claim"] == "chat_protocol_conformance"
    assert report["requests"] == 3 and report["generation_requests"] == 2
    assert all(r.closed == 1 for r in responses)
    for method, url, kwargs in client.calls:
        assert kwargs["timeout"] == 10
        assert kwargs["allow_redirects"] is False and kwargs["stream"] is True
        assert kwargs["headers"]["Authorization"] == "Bearer " + PRIVATE
        if method == "POST":
            assert url == BASE + "/v1/chat/completions"
            assert kwargs["json"]["model"] == MODEL
            assert kwargs["json"]["max_tokens"] == 64
            assert kwargs["json"]["stream"] is False
    prompts = [call[2]["json"]["messages"][0]["content"] for call in client.calls[1:]]
    assert NONCES[0] in prompts[0] and NONCES[1] in prompts[1]
    serialized = json.dumps(report)
    for secret in (PRIVATE, *NONCES, *prompts, MODEL):
        assert secret not in serialized
    assert "identity_not_verified" in report["limitations"]
    assert "billing_not_verified" in report["limitations"]


def test_spoofed_model_and_self_identification_are_only_claims():
    report, _ = run([FakeResponse(catalog())])
    assert report["verdict"] == "unknown"
    observed = evaluate_chat(completion("I am the advertised model", model=PRIVATE), NONCES[0], 2)
    assert observed["nonce_matches"] is False
    assert observed["model_claim_hash"] and PRIVATE not in json.dumps(observed)
    report, _ = run([FakeResponse(catalog()), FakeResponse(completion(model=PRIVATE)),
                     FakeResponse(completion(NONCES[1], model=PRIVATE))], generation=True)
    assert report["verdict"] == "supported"
    assert report["claim"] == "chat_protocol_conformance"
    assert "model_claim_differs" in report["limitations"]
    assert "identity_not_verified" in report["limitations"]


@pytest.mark.parametrize("change", [
    {"object": "text_completion"}, {"id": None}, {"created": True},
    {"model": ""}, {"choices": []}, {"choices": [{}]},
    {"choices": [{"index": 0, "message": {"role": "user", "content": PRIVATE},
                  "finish_reason": "stop"}]},
    {"choices": [{"index": 0, "message": {"role": "assistant", "content": {}},
                  "finish_reason": "stop"}]},
    {"error": {"message": PRIVATE}},
])
def test_invalid_success_envelopes_contradict_only_schema(change):
    report, client = run([FakeResponse(catalog()), FakeResponse(completion(**change))], generation=True)
    assert report["verdict"] == "contradicted"
    assert "chat_envelope_schema" in report["contradictions"]
    assert len(client.calls) == 2
    assert PRIVATE not in json.dumps(report)


@pytest.mark.parametrize("usage", [None, {}, {"prompt_tokens": 20},
    {"prompt_tokens": 20, "completion_tokens": 10}])
def test_missing_or_partial_usage_stays_unknown(usage):
    report, _ = run([FakeResponse(catalog()), FakeResponse(completion(usage=usage)),
                     FakeResponse(completion(NONCES[1], usage=usage))], generation=True)
    assert report["verdict"] == "unknown"
    assert "usage_incomplete" in report["limitations"]
    assert not report["contradictions"]


@pytest.mark.parametrize("usage", [
    "private-text", {"prompt_tokens": True}, {"completion_tokens": -1},
    {"prompt_tokens": "20"}, {"total_tokens": float("inf")},
    {"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 29},
    {"completion_tokens": 65},
])
def test_invalid_usage_is_narrow_contradiction(usage):
    report, _ = run([FakeResponse(catalog()), FakeResponse(completion(usage=usage))], generation=True)
    assert report["verdict"] == "contradicted"
    assert "usage_plausibility" in report["contradictions"]
    assert "private-text" not in json.dumps(report)


def test_nonce_mismatch_and_replay_are_narrow_contradictions():
    for second in (PRIVATE, NONCES[0]):
        report, client = run([FakeResponse(catalog()), FakeResponse(completion()),
                             FakeResponse(completion(second))], generation=True)
        assert report["verdict"] == "contradicted"
        assert "synthetic_nonce_echo" in report["contradictions"]
        assert len(client.calls) == 3
        assert PRIVATE not in json.dumps(report)


def test_changed_model_claim_is_reported_without_identity_inference():
    report, _ = run([FakeResponse(catalog()), FakeResponse(completion()),
                     FakeResponse(completion(NONCES[1], model=PRIVATE))], generation=True)
    assert report["verdict"] == "contradicted"
    assert "repeated_model_claim_consistency" in report["contradictions"]
    assert "identity_not_verified" in report["limitations"]


def test_repeated_envelope_shape_consistency_has_coverage():
    report, _ = run(valid_responses(), generation=True)
    assert "repeated_envelope_consistency" in report["coverage"]
    assert report["observations"][-1]["envelope_consistent"] is True


@pytest.mark.parametrize("status", [301, 307, 400, 401, 403, 404, 429, 500, 503])
@pytest.mark.parametrize("stage", ["metadata", "chat"])
def test_http_errors_are_unknown_terminal_and_content_free(status, stage):
    responses = [] if stage == "metadata" else [FakeResponse(catalog())]
    bad = FakeResponse({"error": PRIVATE}, status=status)
    responses.append(bad)
    report, client = run(responses, generation=True)
    assert report["verdict"] == "unknown"
    assert len(client.calls) == (1 if stage == "metadata" else 2)
    assert bad.closed == 1
    assert PRIVATE not in json.dumps(report)
    assert f"http_{status}" in report["limitations"]


@pytest.mark.parametrize("error", [requests.Timeout(PRIVATE), requests.ConnectionError(PRIVATE),
    ValueError(PRIVATE), RuntimeError(PRIVATE)])
@pytest.mark.parametrize("stage", ["metadata", "first_chat", "second_chat"])
def test_exceptions_never_become_supported_or_leak_text(error, stage):
    responses = valid_responses()[:{"metadata": 0, "first_chat": 1, "second_chat": 2}[stage]]
    responses.append(error)
    report, client = run(responses, generation=True)
    assert report["verdict"] == "unknown"
    assert PRIVATE not in json.dumps(report)
    assert len(client.calls) <= 3


@pytest.mark.parametrize("stage", ["metadata", "chat"])
@pytest.mark.parametrize("kind", ["oversized", "read_error", "close_error", "malformed"])
def test_body_bounds_cleanup_and_read_failures(stage, kind):
    kwargs = {
        "oversized": {"raw": b"x" * (MAX_RESPONSE_BYTES + 1)},
        "read_error": {"read_error": requests.Timeout(PRIVATE)},
        "close_error": {"close_error": RuntimeError(PRIVATE)},
        "malformed": {"raw": PRIVATE.encode()},
    }[kind]
    response = FakeResponse(catalog() if stage == "metadata" else completion(), **kwargs)
    responses = [response] if stage == "metadata" else [FakeResponse(catalog()), response]
    report, _ = run(responses, generation=True)
    assert response.closed == 1
    assert report["verdict"] != "supported"
    assert PRIVATE not in json.dumps(report)
    if kind == "malformed" and stage == "chat":
        assert "chat_json_envelope" in report["contradictions"]


@pytest.mark.parametrize("payload", [None, [], {}, {"data": {}}, {"data": [{}]},
    {"data": []}, {"data": [{"id": "other:model"}]}])
def test_invalid_or_absent_catalog_is_unknown_and_prevents_spending(payload):
    report, client = run([FakeResponse(payload)], generation=True)
    assert report["verdict"] == "unknown"
    assert report["generation_requests"] == 0
    assert len(client.calls) == 1


@pytest.mark.parametrize("url", [
    "http://gateway.example", "ftp://gateway.example", "https://u:p@gateway.example",
    "https://gateway.example?key=" + PRIVATE, "https://gateway.example#" + PRIVATE,
    "https://gateway.example?", "https://gateway.example#", "https://[broken",
    "https://gateway.example:invalid", "https://gateway.example/../private",
    "https://gateway.example/%2e%2e/private", "https://gateway.example\\private",
    "https://gateway.example\n", "https:///missing",
])
def test_bad_urls_fail_before_any_dispatch(url):
    client = FakeTransport([])
    with pytest.raises(ConfigError):
        run_diagnostics(url, MODEL, client=client, api_key=PRIVATE, allow_generation=True)
    assert not client.calls


@pytest.mark.parametrize("model", ["auto:text", "free:text", "intelligence:auto", "bare",
    ":empty", "p:", "P:example", "p:has space", "p:bad\n", "p:auto:text"])
def test_non_explicit_or_routing_models_are_rejected(model):
    client = FakeTransport([])
    with pytest.raises(ConfigError):
        run_diagnostics(BASE, model, client=client, api_key=PRIVATE)
    assert not client.calls


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "127.0.0.2", "[::1]"])
def test_loopback_http_needs_explicit_opt_in(host):
    url = f"http://{host}:5000"
    with pytest.raises(ConfigError):
        validate_target(url, MODEL)
    assert validate_target(url, MODEL, allow_loopback_http=True) == url


@pytest.mark.parametrize("host", ["localhost.evil.test", "10.0.0.1", "0.0.0.0", "[::]"])
def test_loopback_opt_in_never_allows_remote_http(host):
    with pytest.raises(ConfigError):
        validate_target(f"http://{host}", MODEL, allow_loopback_http=True)


def test_base_path_is_preserved_without_double_slash():
    client = FakeTransport([FakeResponse(catalog())])
    run_diagnostics(BASE + "/gateway/", MODEL, client=client, api_key=PRIVATE)
    assert client.calls[0][1] == BASE + "/gateway/v1/models"


def test_repeated_nonce_factory_is_config_error_with_no_dispatch():
    client = FakeTransport([])
    with pytest.raises(ConfigError):
        run_diagnostics(BASE, MODEL, client=client, api_key=PRIVATE,
                        allow_generation=True, nonce_factory=lambda: NONCES[0])
    assert not client.calls


def test_requests_collaborator_disables_retries_redirects_and_ambient_auth():
    session = MagicMock()
    with patch("services.provider_authenticity.requests.Session", return_value=session):
        transport = RequestsTransport()
    assert session.trust_env is False
    assert session.mount.call_count == 2
    for call in session.mount.call_args_list:
        assert call.args[1].max_retries.total == 0
    response = FakeResponse(catalog())
    session.request.return_value = response
    run_diagnostics(BASE, MODEL, client=transport, api_key=PRIVATE)
    assert session.request.call_count == 1
    assert session.request.call_args.kwargs["allow_redirects"] is False
    assert session.request.call_args.kwargs["timeout"] == 10
    transport.close()
    session.close.assert_called_once()


def invoke(responses, *flags, key=PRIVATE):
    output, errors = io.StringIO(), io.StringIO()
    nonces = iter(NONCES)
    client = FakeTransport(responses)
    code = cli.main(["--base-url", BASE, "--model", MODEL, *flags], client=client,
                    environ={"MULTILLM_API_KEY": key}, stdout=output, stderr=errors,
                    nonce_factory=lambda: next(nonces))
    return code, output.getvalue(), errors.getvalue(), client


@pytest.mark.parametrize("generation,expected", [(False, 3), (True, 0)])
def test_cli_plan_is_printed_before_dispatch_and_json_is_separate(generation, expected):
    output, errors = io.StringIO(), io.StringIO()
    nonces = iter(NONCES)
    client = FakeTransport(valid_responses() if generation else [FakeResponse(catalog())])
    original = client.request

    def checked_request(*args, **kwargs):
        assert json.loads(errors.getvalue())["phase"] == "plan"
        assert output.getvalue() == ""
        return original(*args, **kwargs)

    client.request = checked_request
    code = cli.main(["--base-url", BASE, "--model", MODEL,
                     *(["--allow-generation"] if generation else [])],
                    client=client, environ={"MULTILLM_API_KEY": PRIVATE},
                    stdout=output, stderr=errors, nonce_factory=lambda: next(nonces))
    assert code == expected
    assert json.loads(output.getvalue())["verdict"] == ("supported" if generation else "unknown")
    assert PRIVATE not in output.getvalue() + errors.getvalue()


def test_cli_contradiction_and_error_exit_codes():
    code, output, errors, _ = invoke([FakeResponse(catalog()), FakeResponse(completion(PRIVATE))],
                                     "--allow-generation")
    assert code == 2 and json.loads(output)["verdict"] == "contradicted"
    assert PRIVATE not in output + errors
    for flags, key in [((), ""), (("--key", PRIVATE), PRIVATE),
                       (("--model", "auto:text"), PRIVATE),
                       (("--base-url", "https://u:" + PRIVATE + "@host"), PRIVATE)]:
        code, output, errors, client = invoke([], *flags, key=key)
        assert code == 1 and not client.calls
        assert PRIVATE not in output + errors


def test_cli_errors_and_response_extras_are_redacted():
    for response in (requests.Timeout(PRIVATE), FakeResponse({"data": [], "key": PRIVATE}),
                     FakeResponse(catalog(), read_error=RuntimeError(PRIVATE))):
        code, output, errors, _ = invoke([response])
        assert code == 3 and json.loads(output)["verdict"] == "unknown"
        assert PRIVATE not in output + errors
    responses = valid_responses()
    responses[1] = FakeResponse(completion(extra={"key": PRIVATE},
                                          usage={"prompt_tokens": 20, "completion_tokens": 10,
                                                 "total_tokens": 30, "private": PRIVATE}))
    code, output, errors, _ = invoke(responses, "--allow-generation")
    assert code == 0
    for private in (PRIVATE, *NONCES):
        assert private not in output + errors


def test_no_app_import_or_policy_writes_are_needed():
    with patch("builtins.open", side_effect=AssertionError("filesystem access")), \
         patch("requests.sessions.Session.request", side_effect=AssertionError("network access")):
        report, _ = run(valid_responses(), generation=True)
    assert report["verdict"] == "supported"


@pytest.mark.parametrize("finish", ["length", "content_filter"])
def test_incomplete_output_keeps_nonce_evidence_inconclusive(finish):
    first = completion(PRIVATE)
    first["choices"][0]["finish_reason"] = finish
    report, _ = run([FakeResponse(catalog()), FakeResponse(first),
                     FakeResponse(completion(NONCES[1]))], generation=True)
    assert report["verdict"] == "unknown"
    assert "output_incomplete" in report["limitations"]
    assert "synthetic_nonce_echo" not in report["contradictions"]


def test_slow_response_stops_with_cleanup_and_no_generation():
    response = FakeResponse(catalog())
    with patch("services.provider_authenticity.time.monotonic", side_effect=[0, 11]):
        report, client = run([response], generation=True)
    assert report["verdict"] == "unknown"
    assert "timeout" in report["limitations"]
    assert response.closed == 1 and len(client.calls) == 1


def test_exact_response_bound_is_accepted():
    raw = json.dumps(catalog()).encode()
    response = FakeResponse(raw=raw + b" " * (MAX_RESPONSE_BYTES - len(raw)))
    report, _ = run([response])
    assert report["coverage"] == ["catalog_claim"]
    assert response.closed == 1


@pytest.mark.parametrize("status", ["200", True, 600, -1])
def test_invalid_transport_status_is_unknown(status):
    report, client = run([FakeResponse(catalog(), status=status)], generation=True)
    assert report["verdict"] == "unknown" and len(client.calls) == 1
    assert "invalid_http_status" in report["limitations"]


def test_cli_owned_client_is_closed_and_credentials_remain_private():
    output, errors = io.StringIO(), io.StringIO()
    client = FakeTransport([FakeResponse(catalog())])
    client.close = MagicMock()
    with patch.object(cli, "RequestsTransport", return_value=client):
        code = cli.main(["--base-url", BASE, "--model", MODEL],
                        environ={"MULTILLM_API_KEY": PRIVATE}, stdout=output, stderr=errors)
    assert code == 3
    client.close.assert_called_once()
    assert PRIVATE not in output.getvalue() + errors.getvalue()


def test_bad_nonce_factory_exception_is_redacted_before_dispatch():
    client = FakeTransport([])
    output, errors = io.StringIO(), io.StringIO()

    def failure():
        raise RuntimeError(PRIVATE)

    code = cli.main(["--base-url", BASE, "--model", MODEL, "--allow-generation"],
                    client=client, environ={"MULTILLM_API_KEY": PRIVATE},
                    stdout=output, stderr=errors, nonce_factory=failure)
    assert code == 1 and not client.calls
    assert PRIVATE not in output.getvalue() + errors.getvalue()


@pytest.mark.parametrize("usage", [
    {"prompt_tokens": 0, "completion_tokens": 10, "total_tokens": 10},
    {"prompt_tokens": 20, "completion_tokens": 0, "total_tokens": 20},
])
def test_zero_token_claim_for_nonempty_synthetic_exchange_is_implausible(usage):
    report, _ = run([FakeResponse(catalog()), FakeResponse(completion(usage=usage))], generation=True)
    assert report["verdict"] == "contradicted"
    assert "usage_plausibility" in report["contradictions"]


def test_invalid_unicode_claim_cannot_escape_redacted_evaluation():
    report, _ = run([FakeResponse(catalog()), FakeResponse(completion(model="\ud800"))], generation=True)
    assert report["verdict"] == "unknown"
    assert "invalid_response_text" in report["limitations"]
    assert "\\ud800" not in json.dumps(report)
