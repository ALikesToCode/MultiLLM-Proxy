"""Explicit durable identity for isolated provider transport tests."""

import pytest

from services.dispatch_policy import envelope
from services.provider_dispatch import dispatch_as


@pytest.fixture
def verified_transport_principal(monkeypatch):
    from services.auth_service import AuthService

    # Exercise real admission with an explicitly unrestricted stored account.
    # Policy and authentication regressions use their own stores instead.
    monkeypatch.setattr(AuthService, "_load_user_by_username", lambda username: {
        "username": username,
        "data_policy": envelope({"official_only": None, "forced_provider_preferences": None}),
    })
    with dispatch_as({"username": "synthetic-transport"}):
        yield
