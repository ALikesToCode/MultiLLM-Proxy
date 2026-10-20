import os

# NanoGPT speed routing is a deployment choice that a developer may enable in a
# local .env, but it switches the text endpoint off subscription and rewrites
# model ids. Pin it off before `config` is first imported so the suite asserts
# the repository default; tests that need it override app.config directly.
os.environ["NANOGPT_SPEED_ROUTING"] = ""
# The usage ledger writes behind requests from a background thread. Tests that exercise
# it enable it with their own storage; everywhere else it stays off so no test writes
# to the repository's instance directory or waits on a flush.
os.environ.setdefault("USAGE_LEDGER_ENABLED", "false")
# Provider model catalogs refresh from a background thread against real provider APIs.
# Tests that exercise it enable it with patched transports.
os.environ.setdefault("PROVIDER_CATALOG_AUTO_REFRESH", "false")

import pytest


def pytest_sessionstart(session):
    """Audit the extension socket too, including connections from alternate clients."""
    import sys
    from services.dispatch_network import network_admitted

    def audit(event, args):
        if event == "socket.connect" and not network_admitted(args[1]):
            raise AssertionError("Outbound connection outside provider chokepoint")

    # Audit hooks cannot be removed. Keep enforcement active for this process,
    # including collection, fixture teardown and background completions.
    sys.addaudithook(audit)


@pytest.fixture(autouse=True)
def _fresh_public_capability_cache():
    # The models.dev index is cached per process; each test sees its own fixtures.
    from services.provider_capability_discovery import reset_public_capability_cache

    reset_public_capability_cache()
    yield
    reset_public_capability_cache()


@pytest.fixture(autouse=True)
def _outbound_connections_require_dispatch(monkeypatch):
    """All HTTP clients, including unlisted modules and SDKs, meet this boundary."""
    import socket
    from services.dispatch_network import network_admitted

    def guard(original):
        def checked(*args, **kwargs):
            address = args[1] if args and isinstance(args[0], socket.socket) else (args[0] if args else kwargs.get("address"))
            if not network_admitted(address):
                raise AssertionError("Outbound connection outside provider chokepoint")
            return original(*args, **kwargs)
        return checked

    monkeypatch.setattr(socket, "create_connection", guard(socket.create_connection))
    monkeypatch.setattr(socket.socket, "connect", guard(socket.socket.connect))
    monkeypatch.setattr(socket.socket, "connect_ex", guard(socket.socket.connect_ex))
