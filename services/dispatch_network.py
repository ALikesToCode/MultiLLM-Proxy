"""A short-lived network capability issued only after dispatch admission."""
from contextlib import contextmanager
from contextvars import ContextVar

_active = ContextVar("admitted_provider_network", default=False)


def network_admitted(address=None):
    scope = _active.get()
    if not scope or not scope["active"]:
        return False
    destination = scope.get("destination")
    if destination is None:
        return True
    if not isinstance(address, tuple) or address[1] != destination[1]:
        return False
    if address[:2] == destination:
        return True
    # Resolve only when a real connection is attempted; mocked transports and
    # disabled exporters must retain their existing no-network behavior.
    import socket
    try:
        addresses = scope.get("resolved")
        if addresses is None:
            addresses = {item[4][:2] for item in socket.getaddrinfo(*destination, type=socket.SOCK_STREAM)}
            scope["resolved"] = addresses
        return address[:2] in addresses
    except OSError:
        return False


@contextmanager
def admitted_network():
    scope = {"active": True}
    token = _active.set(scope)
    try:
        yield
    finally:
        scope["active"] = False
        _active.reset(token)


@contextmanager
def control_network(url):
    """Explicit non-provider control traffic, confined to its configured endpoint."""
    from urllib.parse import urlsplit
    target = urlsplit(url)
    port = target.port or (443 if target.scheme == "https" else 80)
    scope = {"active": True, "destination": (target.hostname, port)}
    token = _active.set(scope)
    try:
        yield
    finally:
        scope["active"] = False
        _active.reset(token)
