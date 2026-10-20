"""Unlisted modules and alternate clients cannot escape runtime admission."""
import socket
import _socket
from contextlib import closing

import pytest

from services.dispatch_network import network_admitted
from services.provider_dispatch import provider_http


def test_urllib3_bypass_in_an_unlisted_module_fails_before_connection():
    namespace = {}
    exec(compile("import urllib3\ndef send():\n return urllib3.PoolManager(retries=False).request('GET', 'http://127.0.0.1:9')",
                 "unlisted_transport.py", "exec"), namespace)
    with pytest.raises(AssertionError, match="outside provider chokepoint"):
        namespace["send"]()


@pytest.mark.parametrize("call", [lambda: socket.create_connection(("127.0.0.1", 9)),
    lambda: socket.socket().connect(("127.0.0.1", 9)), lambda: socket.socket().connect_ex(("127.0.0.1", 9))])
def test_lowest_socket_layers_require_admission(call):
    with pytest.raises(AssertionError, match="outside provider chokepoint"):
        call()


@pytest.mark.parametrize("method", ["connect", "connect_ex"])
def test_extension_socket_bypass_is_audited_before_loopback_connection(method, verified_transport_principal):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(0.02)
        with closing(_socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as client:
            assert not network_admitted()
            with pytest.raises(AssertionError, match="outside provider chokepoint"):
                getattr(client, method)(server.getsockname())
        with pytest.raises(TimeoutError):
            server.accept()

        def admitted(**kwargs):
            with closing(_socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as client:
                assert network_admitted()
                assert getattr(client, method)(server.getsockname()) in (None, 0)
                client.sendall(b"synthetic")
            connection, _ = server.accept()
            with connection:
                assert connection.recv(9) == b"synthetic"
        provider_http("xai", "GET", "https://api.x.ai/v1/models", transport=admitted)
    assert not network_admitted()


def test_capability_exists_only_during_admitted_transport(verified_transport_principal):
    assert not network_admitted()
    def send(**kwargs):
        assert network_admitted()
        raise RuntimeError("synthetic transport failure")
    with pytest.raises(RuntimeError):
        provider_http("xai", "GET", "https://api.x.ai/v1/models", transport=send)
    assert not network_admitted()


from tests.dispatch_fixture import verified_transport_principal  # noqa: E402, F401
