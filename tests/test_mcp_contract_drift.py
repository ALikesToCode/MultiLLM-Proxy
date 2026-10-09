"""Offline contract checks use shared vectors and synthetic dispatch."""
import copy
import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from routes import knowledge_mcp
from services import mcp_contract_drift as drift
from services.knowledge_client import KnowledgeError
from scripts import build_knowledge_mcp_catalogue as build

BASELINE = Path(__file__).resolve().parents[1] / "docs/mcp-contract-baseline.json"
TOOL = {"name": "knowledge_example", "inputSchema": {"type": "object", "properties": {"query": {"type": ["string", "null"]}}, "required": []}}


def test_shared_canonical_vectors_and_number_equivalence():
    for vector in json.loads(BASELINE.read_text())["vectors"]:
        assert drift.canonical_contract(vector["definition"], vector["contract_version"]) == vector["canonical"]
        assert drift.contract_digest(vector["definition"], vector["contract_version"]) == vector["digest"]
    assert drift.canonical_value(1) == drift.canonical_value(1.0)
    assert drift.canonical_value(0) == drift.canonical_value(-0.0)


def test_order_unknown_fields_and_array_order():
    changed = copy.deepcopy(TOOL)
    changed["inputSchema"] = dict(reversed(list(changed["inputSchema"].items())))
    assert drift.contract_digest(TOOL) == drift.contract_digest(changed)
    changed["inputSchema"]["x-vendor"] = {"opaque": [1, 2]}
    assert drift.contract_digest(TOOL) != drift.contract_digest(changed)
    first = drift.contract_digest(changed)
    changed["inputSchema"]["x-vendor"]["opaque"].reverse()
    assert first != drift.contract_digest(changed)
    assert drift.contract_digest(TOOL, "2") != drift.contract_digest(TOOL)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), 2**53, "\ud800"])
def test_non_interoperable_values_rejected(value):
    with pytest.raises(ValueError):
        drift.canonical_value(value)


@pytest.mark.parametrize("change,classification", [
    (lambda s: s["properties"].update(optional={"type": "string"}), "compatible"),
    (lambda s: s["required"].append("query"), "breaking"),
    (lambda s: s["properties"]["query"].update(type="string"), "breaking"),
    (lambda s: s["properties"].pop("query"), "breaking"),
    (lambda s: s.update(**{"x-vendor": "new"}), "review-required"),
    (lambda s: s.update(anyOf=[{"type": "string"}]), "review-required"),
])
def test_diff_classification(change, classification):
    changed = copy.deepcopy(TOOL)
    change(changed["inputSchema"])
    report = drift.diff_contracts([TOOL], [changed])
    assert report["classification"] == classification
    assert report["changes"]


def test_tool_removal_output_drift_and_unknown_changes_need_review():
    assert drift.diff_contracts([TOOL], [])["classification"] == "breaking"
    changed = {**TOOL, "outputSchema": {"type": "string"}}
    assert drift.diff_contracts([TOOL], [changed])["classification"] == "review-required"
    assert drift.diff_contracts([TOOL], [TOOL])["classification"] == "compatible"
    assert drift.diff_contracts([TOOL], [TOOL], old_version="1", new_version="2")["classification"] == "review-required"


@pytest.mark.parametrize("value", [None, "", "false", "0", "bad", " true-ish "])
def test_flag_defaults_and_warns_without_values(value, caplog, monkeypatch):
    monkeypatch.setattr(drift, "_warned", False)
    assert not drift.digests_enabled(value)
    if value and value not in ("false", "0"):
        assert "MCP_CONTRACT_DIGESTS_ENABLED" in caplog.text
        assert value not in caplog.text
        caplog.clear()
        assert not drift.digests_enabled(value)
        assert not caplog.text


def test_default_catalogue_byte_equality_and_scope_filtered_discovery(monkeypatch):
    monkeypatch.delenv("MCP_CONTRACT_DIGESTS_ENABLED", raising=False)
    assert knowledge_mcp.catalogue_json() == knowledge_mcp.CATALOGUE_PATH.read_text()
    reader = knowledge_mcp.discovery_contract(["knowledge:read"], {"core"}, enabled=True)
    assert [t["name"] for t in reader["tools"]] == ["knowledge_context", "knowledge_search", "knowledge_artifact"]
    assert reader["_meta"]["contract_digest"] == drift.catalogue_digest(reader["tools"])
    assert all("contract_digest" in t["_meta"] for t in reader["tools"])
    manager = knowledge_mcp.discovery_contract(["knowledge:manage"], enabled=True)
    assert all(t["name"] not in {"knowledge_context", "knowledge_search"} for t in manager["tools"])
    assert manager["_meta"]["contract_digest"] != reader["_meta"]["contract_digest"]
    plain = knowledge_mcp.discovery_contract(["knowledge:read"], {"core"}, enabled=False)
    assert "_meta" not in plain and all("_meta" not in t for t in plain["tools"])


def test_pin_guard_before_dispatch_with_off_and_unpinned_bypass(monkeypatch):
    dispatch = Mock(return_value={"ok": True})
    name = "knowledge_context"
    def call(pin):
        knowledge_mcp.check_contract_pin(name, pin)
        return dispatch()
    monkeypatch.setenv("MCP_CONTRACT_DIGESTS_ENABLED", "true")
    with pytest.raises(KnowledgeError) as caught:
        call("0" * 64)
    assert caught.value.code == "mcp_contract_mismatch" and caught.value.status == 409
    dispatch.assert_not_called()
    tool = next(e["definition"] for e in knowledge_mcp.catalogue()["tools"] if e["definition"]["name"] == name)
    call(drift.contract_digest(tool))
    call(None)
    monkeypatch.setenv("MCP_CONTRACT_DIGESTS_ENABLED", "")
    call("malformed-pin")
    assert dispatch.call_count == 3


def test_offline_baseline_deterministic_and_diff_does_not_write_catalogue(tmp_path, capsys):
    original = knowledge_mcp.CATALOGUE_PATH.read_bytes()
    path = tmp_path / "baseline.json"
    assert build.main(["--baseline", str(path)]) == 0
    first = path.read_bytes()
    assert build.main(["--baseline", str(path)]) == 0
    assert path.read_bytes() == first
    assert build.main(["--diff", str(path)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["classification"] == "compatible"
    saved = json.loads(path.read_text())
    saved["tools"].append({"definition": {"name": "removed", "inputSchema": {}}, "digest": "old"})
    path.write_text(json.dumps(saved))
    assert build.main(["--diff", str(path)]) == 1
    assert json.loads(capsys.readouterr().out)["classification"] == "breaking"
    assert knowledge_mcp.CATALOGUE_PATH.read_bytes() == original


def test_checked_in_baseline_matches_current_contract():
    assert drift.baseline_json([e["definition"] for e in knowledge_mcp.catalogue()["tools"]]) == BASELINE.read_text()


@pytest.fixture
def registered_mcp(monkeypatch):
    from flask import Flask, g
    from routes import knowledge

    app = Flask(__name__)
    app.config.update(SECRET_KEY="synthetic-contract-test", TESTING=True)
    monkeypatch.setattr(knowledge, "api_authenticate_only", lambda **kwargs: lambda fn: fn)
    knowledge.register_knowledge_routes(app, Mock(exempt=lambda fn: fn))
    user = {"username": "reader", "scopes": ["knowledge:read"]}

    @app.before_request
    def identity():
        g.authenticated_user = user

    dispatch = Mock(return_value={"status": "ok"})
    monkeypatch.setattr(knowledge, "dispatch", dispatch)
    monkeypatch.delenv("MCP_CONTRACT_DIGESTS_ENABLED", raising=False)
    return app.test_client(), user, dispatch


def post_mcp(client, method, params=None, pin=None, path="/mcp"):
    headers = {} if pin is None else {"X-MultiLLM-MCP-Contract": pin}
    return client.post(path, json={"jsonrpc": "2.0", "id": 7, "method": method, "params": params or {}}, headers=headers)


@pytest.mark.parametrize("flag", [None, "", "false", "0", "malformed"])
def test_registered_default_mcp_paths_ignore_pin_and_keep_bytes(registered_mcp, monkeypatch, flag):
    from routes import knowledge
    client, user, dispatch = registered_mcp
    requests = [("tools/list", {}), ("tools/call", {"name": "knowledge_context", "arguments": {"query": "limits"}})]
    expected = [post_mcp(client, method, params) for method, params in requests]
    assert expected[0].json == {"jsonrpc": "2.0", "id": 7, "result": {"tools": [
        entry["definition"] for entry in knowledge._CATALOGUE["tools"] if entry["scope"] == "knowledge:read"]}}
    if flag is not None:
        monkeypatch.setenv("MCP_CONTRACT_DIGESTS_ENABLED", flag)
    monkeypatch.setattr(drift, "contract_digest", Mock(side_effect=AssertionError("unexpected hash")))
    for (method, params), plain in zip(requests, expected):
        for pin in [None, "", "bad", "0" * 64]:
            actual = post_mcp(client, method, params, pin)
            assert actual.status_code == plain.status_code == 200
            assert actual.data == plain.data
            assert list(actual.headers) == list(plain.headers)
    assert dispatch.call_count == 5
    dispatch.assert_called_with("context", user, {"query": "limits"})


@pytest.mark.parametrize("scopes,admin,toolset", [
    (["knowledge:read"], False, None), (["knowledge:manage"], False, None),
    ([], True, None), (["admin"], False, None), (["knowledge:read"], False, "core"),
])
def test_registered_enabled_discovery_filters_before_hashing(registered_mcp, monkeypatch, scopes, admin, toolset):
    from routes import knowledge
    client, user, dispatch = registered_mcp
    user.update(scopes=scopes, is_admin=admin)
    monkeypatch.setenv("MCP_CONTRACT_DIGESTS_ENABLED", "true")
    path = "/mcp" if toolset is None else f"/mcp?toolsets={toolset}"
    response = post_mcp(client, "tools/list", path=path)
    expected = [e["definition"] for e in knowledge._CATALOGUE["tools"]
                if (admin or "admin" in scopes or e["scope"] in scopes)
                and (toolset is None or e["toolset"] == toolset)]
    assert response.status_code == 200
    result = response.json["result"]
    assert result == drift.discovery_contract(
        knowledge._CATALOGUE["tools"], ["admin"] if admin else scopes,
        None if toolset is None else {toolset}, enabled=True)
    assert result["_meta"]["contract_digest"] == drift.catalogue_digest(expected)
    assert [t["name"] for t in result["tools"]] == [t["name"] for t in expected]
    dispatch.assert_not_called()


@pytest.mark.parametrize("name,arguments", [
    ("knowledge_context", {"query": "limits"}), ("knowledge_exa_search", {"query": "limits"}),
    ("knowledge_alexandria_inspect", {"id": "item-1"}), ("knowledge_policy_update", {}),
    ("knowledge_skills_sync", {}), ("knowledge_handoff_get", {}),
])
@pytest.mark.parametrize("pin", ["", "bad", "0" * 64])
def test_registered_pin_mismatch_is_http_409_before_dispatch(registered_mcp, monkeypatch, name, arguments, pin):
    client, user, dispatch = registered_mcp
    user["is_admin"] = True
    monkeypatch.setenv("MCP_CONTRACT_DIGESTS_ENABLED", "true")
    response = post_mcp(client, "tools/call", {"name": name, "arguments": arguments}, pin)
    assert response.status_code == 409
    assert response.json == {"jsonrpc": "2.0", "id": 7, "error": {
        "code": "mcp_contract_mismatch", "message": "The pinned MCP tool contract has changed. Refresh discovery."}}
    assert response.headers["Cache-Control"] == "no-store"
    dispatch.assert_not_called()


def test_registered_matching_unpinned_and_changed_contract_calls(registered_mcp, monkeypatch):
    from routes import knowledge
    client, _, dispatch = registered_mcp
    params = {"name": "knowledge_context", "arguments": {"query": "limits"}}
    expected = post_mcp(client, "tools/call", params)
    monkeypatch.setenv("MCP_CONTRACT_DIGESTS_ENABLED", "true")
    tool = post_mcp(client, "tools/list").json["result"]["tools"][0]
    old_pin = tool["_meta"]["contract_digest"]
    assert post_mcp(client, "tools/call", params, old_pin).data == expected.data
    assert post_mcp(client, "tools/call", params).data == expected.data
    changed = copy.deepcopy(knowledge._TOOLS["knowledge_context"]["definition"])
    changed["inputSchema"]["x-revision"] = 2
    monkeypatch.setitem(knowledge._TOOLS["knowledge_context"], "definition", changed)
    assert post_mcp(client, "tools/call", params, old_pin).status_code == 409
    assert post_mcp(client, "tools/call", params).data == expected.data
    assert post_mcp(client, "tools/call", params, drift.contract_digest(changed)).data == expected.data
    assert dispatch.call_count == 5


def test_registered_authorization_precedes_pin_check(registered_mcp, monkeypatch):
    client, _, dispatch = registered_mcp
    monkeypatch.setenv("MCP_CONTRACT_DIGESTS_ENABLED", "true")
    monkeypatch.setattr(drift, "contract_digest", Mock(side_effect=AssertionError("unauthorized hash")))
    denied = post_mcp(client, "tools/call", {"name": "knowledge_policy_update"}, "bad")
    assert denied.status_code == 200
    assert "insufficient_scope" in denied.json["result"]["content"][0]["text"]
    dispatch.assert_not_called()


@pytest.mark.parametrize("previous", [[], {}, {"format": "wrong", "tools": []}, {"format": drift.FORMAT, "tools": [None]}])
def test_invalid_baseline_reports_error_without_writing(tmp_path, previous, capsys):
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(previous))
    original = path.read_bytes()
    assert build.main(["--diff", str(path)]) == 2
    assert path.read_bytes() == original
    assert "Contract baseline operation failed" in capsys.readouterr().err


def test_canonical_bounds_are_enforced():
    deep = None
    for _ in range(66):
        deep = [deep]
    for value in [deep, [None] * 65537, "x" * drift.MAX_CANONICAL_BYTES, 10**1000]:
        with pytest.raises(ValueError):
            drift.canonical_value(value)


def test_output_widening_requires_review_and_boolean_input_narrowing_breaks():
    old = {**TOOL, "outputSchema": {"type": "string"}}
    new = {**TOOL, "outputSchema": {"type": ["string", "null"]}}
    assert drift.diff_contracts([old], [new])["classification"] == "review-required"
    assert drift.diff_contracts([{**TOOL, "inputSchema": True}], [{**TOOL, "inputSchema": False}])["classification"] == "breaking"


def test_baseline_modes_cannot_overwrite_worker_catalogue(capsys):
    for option in ("--baseline", "--diff"):
        assert build.main([option, str(knowledge_mcp.CATALOGUE_PATH)]) == 2
    assert "cannot overwrite" in capsys.readouterr().err
