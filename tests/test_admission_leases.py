"""Shared admission clients and response lifecycle with an injected private authority."""
import json
from concurrent.futures import ThreadPoolExecutor
from threading import Lock

import pytest
from flask import Flask, Response

from middleware.admission import dispatch_with_admission
from services.admission_leases import AdmissionClient, AdmissionError, AdmissionIdentity, admission_settings


def identity(request_id="r1", principal_hash="a" * 64, model_group="heavy", deadline_ms=1_100_000):
    return AdmissionIdentity(principal_hash, model_group, request_id, deadline_ms)


class Authority:
    def __init__(self):
        self.calls = []
        self.leases = {}
        self.lock = Lock()
        self.now = 1_000_000
        self.down = False

    def __call__(self, payload):
        with self.lock:
            self.calls.append(payload)
            if self.down:
                raise OSError("unavailable")
            key = (payload["principal_hash"], payload["model_group"])
            operation = payload["operation"]
            if operation == "acquire":
                if key in self.leases:
                    raise AdmissionError("admission_denied", 429, 30)
                lease = {"lease_id": payload["request_id"].encode().hex().ljust(32, "0"),
                         "expires_at": min(self.now + 30000, payload["deadline_ms"])}
                self.leases[key] = lease
                return {"version": 1, "lease": lease}
            if operation == "release":
                return {"version": 1, "released": self.leases.pop(key, None) is not None}
            lease = self.leases[key]
            lease["expires_at"] = min(self.now + 30000, payload["deadline_ms"])
            return {"version": 1, "lease": lease}


@pytest.fixture
def authority():
    return Authority()


def client(authority, **kwargs):
    return AdmissionClient({"ADMISSION_ENABLED": "true", "ADMISSION_LIMITS_JSON": '{"model_groups":{"heavy":1}}'},
                           call=authority, clock=lambda: authority.now, background=False, **kwargs)


@pytest.mark.parametrize("env", [{}, {"ADMISSION_ENABLED": ""}, {"ADMISSION_ENABLED": "bad"},
    {"ADMISSION_ENABLED": "true", "ADMISSION_LIMITS_JSON": "bad"},
    {"ADMISSION_ENABLED": "true", "ADMISSION_LIMITS_JSON": "{}"}])
def test_disabled_unlimited_no_calls_no_headers_and_same_response(env, authority):
    admission = AdmissionClient(env, call=authority, background=False)
    response = Response("same", headers={"X-Provider": "raw"})
    assert dispatch_with_admission(None, lambda: response, admission) is response
    assert list(response.headers) == [("X-Provider", "raw"), ("Content-Type", "text/html; charset=utf-8"), ("Content-Length", "4")]
    assert authority.calls == []


def test_two_flask_clients_share_limit_and_release_once(authority):
    left, right = client(authority), client(authority)
    def acquire(args):
        admission, context = args
        try:
            return admission.acquire(context)
        except AdmissionError as error:
            return error
    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(acquire, [(left, identity()), (right, identity("r2"))]))
    lease = next(item for item in results if not isinstance(item, AdmissionError))
    denial = next(item for item in results if isinstance(item, AdmissionError))
    assert (denial.status, denial.retry_after) == (429, 30)
    lease.release()
    lease.release()
    assert [call["operation"] for call in authority.calls].count("release") == 1
    assert right.acquire(identity("r3")) is not None


def test_renewal_and_deadline_release_once(authority):
    admission = client(authority)
    lease = admission.acquire(identity())
    authority.now += 10000
    admission.renew_due()
    assert lease.expires_at == 1_040_000
    authority.now = 1_100_000
    admission.renew_due()
    assert lease.closed
    lease.release()
    assert [call["operation"] for call in authority.calls] == ["acquire", "renew", "release"]


def test_authority_failure_and_renewal_loss_are_503(authority):
    admission = client(authority)
    authority.down = True
    with pytest.raises(AdmissionError) as error:
        admission.acquire(identity())
    assert error.value.status == 503
    authority.down = False
    lease = admission.acquire(identity())
    authority.down = True
    authority.now += 10000
    admission.renew_due()
    with pytest.raises(AdmissionError) as error:
        lease.check()
    assert error.value.status == 503
    assert lease.closed


@pytest.mark.parametrize("context", [identity(principal_hash="raw-key"), identity(model_group="bad group"),
                                      identity(request_id=""), identity(deadline_ms=0)])
def test_spoofed_or_invalid_identity_never_calls_authority(authority, context):
    with pytest.raises(AdmissionError):
        client(authority).acquire(context)
    assert authority.calls == []


def test_registered_route_denial_outage_headers_and_spoofed_public_headers(authority):
    admission = client(authority)
    held = admission.acquire(identity("held"))
    app = Flask(__name__)
    @app.post("/generate")
    def generate():
        return dispatch_with_admission(identity("trusted"), lambda: Response("upstream"), admission)
    with app.test_client() as browser:
        response = browser.post("/generate", headers={"X-Principal": "b" * 64, "X-Model-Group": "small"})
        assert response.status_code == 429
        assert response.headers["Retry-After"] == "30"
        assert response.json["error"]["code"] == "admission_denied"
        assert authority.calls[-1]["principal_hash"] == "a" * 64
        held.release()
        authority.down = True
        assert browser.post("/generate").status_code == 503


def test_completion_errors_and_unstarted_stream_close_release_once(authority):
    admission = client(authority)
    response = dispatch_with_admission(identity(), lambda: Response("body"), admission)
    assert response.get_data() == b"body"
    assert not authority.leases
    def broken():
        raise RuntimeError("response error")
    with pytest.raises(RuntimeError):
        dispatch_with_admission(identity("error"), broken, admission)
    source_closed = []
    class Source:
        def __iter__(self): return self
        def __next__(self): return b"data: same\n\n"
        def close(self): source_closed.append(True)
    response = dispatch_with_admission(identity("cancel"), lambda: Response(Source()), admission)
    response.close()
    response.close()
    assert source_closed == [True]
    assert not authority.leases
    assert [call["operation"] for call in authority.calls].count("release") == 3


def test_stream_iteration_error_and_bytes_preserved(authority):
    admission = client(authority)
    def source():
        yield b"data: unchanged\n\n"
        raise RuntimeError("upstream error")
    response = dispatch_with_admission(identity(), lambda: Response(source(), headers={"X-Provider": "raw"}), admission)
    iterator = iter(response.response)
    assert next(iterator) == b"data: unchanged\n\n"
    with pytest.raises(RuntimeError): next(iterator)
    response.close()
    assert not authority.leases
    assert response.headers["X-Provider"] == "raw"
    assert [call["operation"] for call in authority.calls].count("release") == 1


def test_standalone_requires_explicit_private_url_and_invalid_config_logs_once(authority, caplog, monkeypatch):
    monkeypatch.setattr("services.admission_leases._warned", False)
    admission = AdmissionClient({"ADMISSION_ENABLED": "true", "ADMISSION_LIMITS_JSON": '{"principal":1}'}, clock=lambda: authority.now, background=False)
    with pytest.raises(AdmissionError) as error: admission.acquire(identity())
    assert error.value.status == 503
    for _ in range(2):
        assert not admission_settings({"ADMISSION_ENABLED": "true", "ADMISSION_LIMITS_JSON": "secret malformed"}).enabled
    assert caplog.text.count("Invalid admission configuration") == 1
    assert "secret malformed" not in caplog.text
    for url in ["https://public.example/v1/admission", "http://127.0.0.1/v1/admission?x=1", "http://user:pass@localhost/v1/admission"]:
        admission = AdmissionClient({"ADMISSION_ENABLED": "true", "ADMISSION_LIMITS_JSON": '{"principal":1}',
                                     "ADMISSION_AUTHORITY_URL": url}, clock=lambda: authority.now, background=False)
        with pytest.raises(AdmissionError): admission.acquire(identity())


def test_no_identity_content_or_limit_override_in_wire_payload(authority):
    lease = client(authority).acquire(identity())
    assert set(authority.calls[0]) == {"version", "operation", "principal_hash", "model_group", "request_id", "deadline_ms"}
    lease.release()
    assert "raw-key" not in json.dumps(authority.calls)


@pytest.mark.parametrize("status,retry,expected", [(200, None, 200), (429, "7", 429), (503, None, 503),
                                                   (429, "bad", 503), (302, None, 503)])
def test_private_transport_single_submission_bounded_status_and_no_redirects(monkeypatch, status, retry, expected):
    calls = []
    value = {"version": 1, "lease": {"lease_id": "f" * 32, "expires_at": 1_030_000}}
    if status != 200: value = {"version": 1, "error": {"code": "admission_denied" if status == 429 else "down"}}
    class Reply:
        status_code = status
        headers = {"Content-Type": "application/json", **({"Retry-After": retry} if retry else {})}
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def iter_content(self, chunk_size): yield json.dumps(value).encode()
    class Session:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def post(self, url, **kwargs):
            assert self.trust_env is False
            calls.append((url, kwargs))
            return Reply()
    monkeypatch.setattr("services.admission_leases.requests.Session", Session)
    admission = AdmissionClient({"ADMISSION_ENABLED": "true", "ADMISSION_LIMITS_JSON": '{"principal":1}',
                                 "ADMISSION_AUTHORITY_URL": "http://127.0.0.1/v1/admission"},
                                clock=lambda: 1_000_000, background=False)
    if expected == 200:
        lease = admission.acquire(identity())
        assert lease.expires_at == 1_030_000
    else:
        with pytest.raises(AdmissionError) as error: admission.acquire(identity())
        assert error.value.status == expected
        if expected == 429: assert error.value.retry_after == 7
    assert len(calls) == 1
    assert calls[0][1]["allow_redirects"] is False
    assert calls[0][1]["timeout"] == (2, 3)
    assert calls[0][1]["json"]["principal_hash"] == "a" * 64


def test_renewal_loss_invokes_cancellation_once_and_rejects_remaining_stream(authority):
    admission = client(authority)
    lost, closed = [], []
    class Source:
        def __iter__(self): return self
        def __next__(self): return b"chunk"
        def close(self): closed.append(True)
    response = dispatch_with_admission(identity(), lambda: Response(Source()), admission, on_lost=lost.append)
    assert next(iter(response.response)) == b"chunk"
    authority.down = True
    authority.now += 10000
    admission.renew_due()
    admission.renew_due()
    with pytest.raises(AdmissionError): next(iter(response.response))
    response.close()
    assert len(lost) == 1
    assert closed == [True]
    assert [call["operation"] for call in authority.calls].count("release") == 1


def test_loss_during_dispatch_closes_response_and_returns_503(authority):
    admission = client(authority)
    closed = []
    def dispatch():
        authority.now = 1_100_000
        admission.renew_due()
        response = Response("late")
        response.call_on_close(lambda: closed.append(True))
        return response
    response = dispatch_with_admission(identity(), dispatch, admission)
    assert response.status_code == 503
    assert closed == [True]
    assert not authority.leases


def test_renewal_scheduler_is_single_and_disabled_configuration_never_starts_it(authority, monkeypatch):
    starts = []
    class Thread:
        def __init__(self, **kwargs): assert kwargs["daemon"] is True
        def is_alive(self): return True
        def start(self): starts.append(True)
    monkeypatch.setattr("services.admission_leases._scheduler", None)
    monkeypatch.setattr("services.admission_leases.threading.Thread", Thread)
    assert AdmissionClient({}, call=authority).acquire(None) is None
    assert starts == []
    env = {"ADMISSION_ENABLED": "true", "ADMISSION_LIMITS_JSON": '{"principal":2}'}
    first = AdmissionClient(env, call=authority, clock=lambda: authority.now).acquire(identity())
    second = AdmissionClient(env, call=authority, clock=lambda: authority.now).acquire(identity("small", model_group="small"))
    assert starts == [True]
    first.release()
    second.release()



def test_cancellation_callback_runs_after_unlock_and_release(authority):
    admission = client(authority)
    observed = []
    pool = ThreadPoolExecutor(1)
    def callback(error):
        def check():
            with pytest.raises(AdmissionError): lease.check()
            return lease.closed
        observed.append(pool.submit(check).result(timeout=1))
    lease = admission.acquire(identity(), on_lost=callback)
    authority.down = True
    authority.now += 10000
    admission.renew_due()
    pool.shutdown(wait=True)
    assert observed == [True]
