"""Unlisted modules and alternate clients cannot escape runtime admission."""
import socket

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


def test_capability_exists_only_during_admitted_transport(verified_transport_principal):
    assert not network_admitted()
    def send(**kwargs):
        assert network_admitted()
        raise RuntimeError("synthetic transport failure")
    with pytest.raises(RuntimeError):
        provider_http("xai", "GET", "https://api.x.ai/v1/models", transport=send)
    assert not network_admitted()


from tests.dispatch_fixture import verified_transport_principal  # noqa: E402, F401
