import json
from unittest.mock import patch

import pytest
from flask import Flask

from services import knowledge_client
from services.retention_policy import RetentionPolicy

USER = {"username": "synthetic-reader", "scopes": ["knowledge:read"]}


def _capture():
    received = []

    def submit(body, stopped, deadline, results):
        received.append(json.loads(body))
        results.put(({"ok": True}, None))
        knowledge_client._SLOTS.release()
    return received, submit


@pytest.fixture(autouse=True)
def connected(monkeypatch):
    monkeypatch.setenv("KNOWLEDGE_SERVICE_ENABLED", "true")


def test_disabled_retention_keeps_the_envelope_unchanged():
    received, submit = _capture()
    with patch.object(knowledge_client, "_submit", side_effect=submit), \
            patch.object(knowledge_client, "protect_payload", side_effect=lambda payload, **_: payload), \
            patch.object(knowledge_client.retention_policy, "request_policy", return_value=RetentionPolicy()):
        knowledge_client.dispatch("handoffs.save", USER, {"title": "t", "markdown": "m"})
        knowledge_client.dispatch("search", USER, {"query": "q"})
    assert all("retention_policy" not in envelope for envelope in received)
    assert set(received[1]) == {"version", "operation", "principal", "payload", "secret_scan_mode", "secret_scan_checked"}


def test_enabled_retention_sends_the_trusted_snapshot():
    received, submit = _capture()
    with patch.object(knowledge_client, "_submit", side_effect=submit), \
            patch.object(knowledge_client, "protect_payload", side_effect=lambda payload, **_: payload), \
            patch.object(knowledge_client.retention_policy, "request_policy", return_value=RetentionPolicy("zero", True, "r1")):
        knowledge_client.dispatch("search", USER, {"query": "q"})
    with patch.object(knowledge_client, "_submit", side_effect=submit), \
            patch.object(knowledge_client, "protect_payload", side_effect=lambda payload, **_: payload), \
            patch.object(knowledge_client.retention_policy, "request_policy", return_value=RetentionPolicy("inherit", True, "r1")):
        knowledge_client.dispatch("handoffs.save", USER, {"title": "t", "markdown": "m"})
    assert received[0]["retention_policy"] == {"mode": "zero", "enabled": True}
    assert received[1]["retention_policy"] == {"mode": "inherit", "enabled": True}


def test_zero_retention_refuses_handoff_save_before_scan_or_transport():
    with patch.object(knowledge_client, "_submit") as transport, \
            patch.object(knowledge_client, "protect_payload") as scan, \
            patch.object(knowledge_client.retention_policy, "request_policy", return_value=RetentionPolicy("zero", True, "r1")):
        with pytest.raises(knowledge_client.KnowledgeError) as raised:
            knowledge_client.dispatch("handoffs.save", USER, {"title": "t", "markdown": "secret body"})
    assert (raised.value.code, raised.value.status) == ("retention_forbidden", 409)
    transport.assert_not_called()
    scan.assert_not_called()


def test_caller_opt_out_header_reaches_the_envelope(monkeypatch):
    monkeypatch.setenv("CONTENT_RETENTION_ENABLED", "true")
    monkeypatch.setenv("CONTENT_RETENTION_POLICY_JSON", "")
    received, submit = _capture()
    app = Flask(__name__)
    with app.test_request_context("/v1/knowledge/search", headers={"X-MultiLLM-Retention": "zero"}), \
            patch.object(knowledge_client, "_submit", side_effect=submit), \
            patch.object(knowledge_client, "protect_payload", side_effect=lambda payload, **_: payload):
        from flask import g
        g.authenticated_user = {"username": "synthetic-reader", "id": 7}
        with patch("route_helpers.request_api_key", return_value="synthetic-key"):
            knowledge_client.dispatch("search", USER, {"query": "q"})
    assert received[0]["retention_policy"] == {"mode": "zero", "enabled": True}
