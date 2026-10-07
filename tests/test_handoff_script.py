"""Handoff recovery uses only synthetic transcripts, keys and loopback HTTP."""
from datetime import datetime, timedelta, timezone
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import pytest
from scripts import handoff
import handoff_contracts as contracts
import handoff_transcripts as transcripts

ROOT = Path(__file__).resolve().parents[1]
HOOK_PATH = ROOT / "scripts/hooks/handoff_hint.py"
spec = importlib.util.spec_from_file_location("handoff_hint", HOOK_PATH)
hook = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hook)


def args(**extra):
    return SimpleNamespace(cwd="/synthetic/project", base_url=None, key_file=None, summarize=None,
                           **extra)


def payload(**extra):
    return {"project": "synthetic/repo", "branch": "feature", "title": "Fixture",
            "sections": {"goal": "Continue the fixture", "state": "Checks complete"},
            "source": {"agent": "codex"}, **extra}


def record(now=None):
    now = now or datetime.now(timezone.utc)
    return {**payload(), "id": "synthetic-id", "created_at": now.isoformat(),
            "expires_at": (now + timedelta(days=14)).isoformat()}


@pytest.fixture
def server():
    state = {"calls": [], "summary": {"goal": "Summarized fixture", "next_steps": ["Review"]},
             "record": record(), "delay": 0, "status": 200, "redirect": None}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def send(self, value):
            time.sleep(state["delay"])
            self.send_response(state["status"])
            self.send_header("Content-Type", "application/json")
            if state["redirect"]:
                self.send_header("Location", state["redirect"])
            self.end_headers()
            try:
                self.wfile.write(json.dumps(value).encode())
            except (BrokenPipeError, ConnectionResetError):
                pass

        def do_GET(self):
            state["calls"].append((self.path, self.headers.get("Authorization"), None))
            self.send({"record": state["record"], "trust": "operator"})

        def do_POST(self):
            value = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            state["calls"].append((self.path, self.headers.get("Authorization"), value))
            if self.path == "/v1/chat/completions":
                self.send({"choices": [{"message": {"content": json.dumps(state["summary"])}}]})
            else:
                self.send({"id": "synthetic-id", "expires_at": "2026-10-21T00:00:00Z"})

    http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    http.daemon_threads = True
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    state["base"] = f"http://127.0.0.1:{http.server_port}"
    yield state
    http.shutdown()
    http.server_close()
    thread.join(2)


def test_claude_fact_extraction_ignores_outputs_and_keeps_last_three_users():
    with patch.object(transcripts, "git", side_effect=lambda _cwd, *a: "fixture-head" if a == ("rev-parse", "HEAD") else " M src/a.py" if a == ("status", "--short") else "feature"):
        result = transcripts.extract(ROOT / "tests/fixtures/handoff_claude.jsonl", "/synthetic/project")
    assert result["source"] == {"agent": "claude", "thread_id": "synthetic-claude"}
    assert result["branch"] == "feature"
    s = result["sections"]
    assert [item["path"] for item in s["files"]] == ["src/a.py", "src/b.py", "src/c.py", "analysis.ipynb"]
    assert s["goal"] == "Ship fixture four"
    assert s["decisions"] == ["User: Review fixture two", "User: Review fixture three", "User: Ship fixture four"]
    assert s["state"] == "Fixture complete; review is pending."
    assert s["commands"][0] == {"command": "synthetic-test --fail", "outcome": "Exit 3"}
    assert "fixture-head" in json.dumps(s)
    assert "TOOL_OUTPUT_MUST_NOT_LEAK" not in json.dumps(result)
    contracts.validate_payload(payload(**result))


def test_codex_fact_extraction_handles_patch_and_json_arguments():
    with patch.object(transcripts, "git", return_value="feature"):
        result = transcripts.extract(ROOT / "tests/fixtures/handoff_codex.jsonl", "/synthetic/project")
    assert result["source"]["agent"] == "codex"
    assert [item["path"] for item in result["sections"]["files"]] == ["src/parser.py", "src/old.py", "src/new.py", "src/gone.py"]
    assert result["sections"]["state"] == "Parser written; one check failed."
    assert result["sections"]["commands"][0] == {"command": "synthetic-check", "outcome": "Exit 2"}
    assert "TOOL_OUTPUT_MUST_NOT_LEAK" not in json.dumps(result)


def test_codex_shell_sessions_preserve_failures_and_use_structured_exit_status():
    facts = transcripts.Facts()
    facts.tool("exec_command", {"cmd": "synthetic-long-check"}, "start")
    facts.output("start", json.dumps({"session_id": 17, "output": "not copied"}))
    facts.tool("write_stdin", {"session_id": 17}, "poll")
    facts.output("poll", {"session_id": 17, "exit_code": 7, "output": "not copied"})
    assert list(facts.failures) == [{"command": "synthetic-long-check", "outcome": "Exit 7"}]
    facts.tool("exec_command", {"cmd": "synthetic-success"}, "ok")
    facts.output("ok", json.dumps({"exit_code": 0, "output": "Exit code: 9"}))
    assert len(facts.failures) == 1
    for index in range(150):
        facts.tool("exec_command", {"cmd": "synthetic-check"}, str(index))
        facts.output(str(index), {"session_id": index})
    assert len(facts.sessions) == 100


def test_secret_redaction_happens_before_truncation_and_in_every_fact(tmp_path):
    secret = "AK" + "IA" + "AB12CD34EF56GH78"
    path = tmp_path / "synthetic.jsonl"
    items = [
        {"type": "user", "message": {"content": "x" * 490 + secret}},
        {"type": "assistant", "message": {"content": [{"type": "text", "text": "Done " + secret},
            {"type": "tool_use", "name": "Edit", "input": {"file_path": "src/" + secret}}]}},
    ]
    path.write_text("\n".join(json.dumps(item) for item in items))
    with patch.object(transcripts, "git", return_value=secret):
        result = transcripts.extract(path, tmp_path)
    assert secret not in json.dumps(result)
    assert "[REDACTED:" in json.dumps(result)
    assert secret not in contracts.render(contracts.validate_payload(transcripts.sanitized(payload(summary=secret))))


@pytest.mark.parametrize("origin,expected", [
    ("git@github.com:synthetic/repo.git", "synthetic/repo"),
    ("https://github.com/synthetic/repo.git", "synthetic/repo"),
    ("ssh://git@code.example:2222/synthetic/repo.git", "synthetic/repo"),
    ("https://code.example/synthetic/repo", "synthetic/repo"),
    ("", "project"), ("invalid", "project"),
])
def test_project_identity(origin, expected):
    assert transcripts.project_identity("/synthetic/project", origin) == expected


def test_discovers_newest_matching_transcript_across_agents(tmp_path):
    cwd = "/synthetic/project"
    claude = tmp_path / ".claude/projects/-synthetic-project/one.jsonl"
    codex = tmp_path / ".codex/sessions/2026/10/07/rollout-one.jsonl"
    unrelated = codex.with_name("rollout-unrelated.jsonl")
    claude.parent.mkdir(parents=True)
    codex.parent.mkdir(parents=True)
    claude.write_text("{}\n")
    codex.write_text(json.dumps({"type": "session_meta", "payload": {"cwd": cwd}}))
    unrelated.write_text(json.dumps({"type": "session_meta", "payload": {"cwd": "/other"}}))
    import os
    os.utime(claude, (1, 1))
    os.utime(codex, (2, 2))
    os.utime(unrelated, (3, 3))
    assert transcripts.discover(cwd, tmp_path) == (codex, "codex")
    assert transcripts.discover(cwd, tmp_path, "claude") == (claude, "claude")
    with pytest.raises(ValueError):
        transcripts.discover("/missing", tmp_path)


@pytest.mark.parametrize("extra", [{"ttl_days": True}, {"ttl_days": 0}, {"title": "x" * 201}, {"summary": "x" * 4001},
                                  {"branch": None}, {"source": {"agent": "unknown"}},
                                  {"sections": {"goal": None}}, {"sections": {"files": None}},
                                  {"sections": {"files": [{"path": "src/a", "change": "x" * 501}]}},
                                  {"sections": {"commands": ["invalid"]}},
                                  {"sections": {"files": [{"path": "p" * 500, "change": "c" * 500}] * 100}}])
def test_local_validation_rejects_invalid_contract(extra):
    with pytest.raises(ValueError):
        contracts.validate_payload(payload(**extra))


def test_local_validation_allows_empty_bounded_strings():
    value = contracts.validate_payload(payload(title="", sections={"files": [{"path": "", "change": ""}], "commands": [{"command": "", "outcome": ""}]}))
    assert value["title"] == ""
    assert value["sections"]["files"][0]["path"] == ""


def test_transcript_line_and_scan_bounds_fail_closed(tmp_path, monkeypatch):
    path = tmp_path / "synthetic.jsonl"
    path.write_text("{" + "x" * 100 + "}\n")
    monkeypatch.setattr(transcripts, "MAX_LINE_BYTES", 50)
    with pytest.raises(ValueError):
        list(transcripts.records(path))
    assert transcripts.clean("x" * 100) == "[oversized fact omitted]"
    assert len(contracts.render(payload(summary="🧭" * 4000)).encode()) <= 4500


def test_summarize_validation_and_transport_failures_keep_deterministic_sections(server, monkeypatch):
    monkeypatch.setenv("MULTILLM_KNOWLEDGE_API_KEY", "synthetic-private-credential")
    options = args()
    options.base_url = server["base"]
    options.summarize = "synthetic-model"
    value = contracts.validate_payload(payload())
    assert handoff.summarize(options, value)["sections"]["goal"] == "Summarized fixture"
    sent = server["calls"][-1][2]
    assert sent["model"] == "synthetic-model"
    assert len(sent["messages"][1]["content"]) <= 30000
    for invalid in [{"goal": "x" * 501}, {"unsupported": True}, ["not an object"], {"next_steps": ["step"] * 31}]:
        server["summary"] = invalid
        assert handoff.summarize(options, value) == value
    server["status"] = 503
    assert handoff.summarize(options, value) == value
    server["status"] = 200
    server["summary"] = {"goal": "AK" + "IA" + "AB12CD34EF56GH78"}
    assert "[REDACTED:" in handoff.summarize(options, value)["sections"]["goal"]


def test_cli_build_print_save_and_load_with_fake_gateway(server, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("MULTILLM_KNOWLEDGE_API_KEY", "synthetic-private-credential")
    base = ["--cwd", str(tmp_path), "--base-url", server["base"]]
    transcript = ROOT / "tests/fixtures/handoff_codex.jsonl"
    with patch.object(transcripts, "git", return_value="feature"), patch.object(handoff, "project_identity", return_value="synthetic/repo"):
        assert handoff.main(["build", *base, "--transcript", str(transcript)]) == 0
    value = capsys.readouterr().out
    saved = tmp_path / "synthetic-handoff.json"
    saved.write_text(value)
    assert handoff.main(["print", *base, "--input", str(saved)]) == 0
    assert "Parser written" in capsys.readouterr().out
    assert handoff.main(["save", *base, "--input", str(saved)]) == 0
    assert json.loads(capsys.readouterr().out)["id"] == "synthetic-id"
    assert server["calls"][-1][0] == "/v1/knowledge/handoffs"
    with patch.object(handoff, "project_identity", return_value="synthetic/repo"), patch.object(handoff, "git", return_value="feature"):
        assert handoff.main(["load", *base]) == 0
    assert "Fixture" in capsys.readouterr().out
    assert "project=synthetic%2Frepo&branch=feature" in server["calls"][-1][0]
    with patch("sys.stdin", io.StringIO(value)):
        assert handoff.main(["print", *base, "--input", "-"]) == 0
    assert "synthetic-private-credential" not in capsys.readouterr().out


def test_cli_errors_never_echo_key_or_response(monkeypatch, capsys):
    monkeypatch.setenv("MULTILLM_KNOWLEDGE_API_KEY", "synthetic-private-credential")
    with patch.object(handoff, "load", side_effect=ValueError("synthetic-private-credential")):
        assert handoff.main(["load"]) == 1
    assert "synthetic-private-credential" not in capsys.readouterr().err
    for base in ["http://public.example", "https://user:secret@public.example", "https://public.example?key=x", "https://public.example/v1"]:
        options = args()
        options.base_url = base
        with pytest.raises(ValueError):
            handoff.connection(options)


def test_http_redirect_does_not_forward_credentials(server, monkeypatch):
    monkeypatch.setenv("MULTILLM_KNOWLEDGE_API_KEY", "synthetic-private-credential")
    server["status"] = 302
    server["redirect"] = server["base"] + "/should-not-follow"
    with pytest.raises(Exception):
        handoff.request_json(server["base"], "synthetic-private-credential", "/original")
    assert len(server["calls"]) == 1


@pytest.mark.parametrize("agent", ["claude", "codex"])
def test_hook_official_output_formats_and_age(agent):
    now = datetime.now(timezone.utc)
    options = args()
    options.agent = agent
    event = {"hook_event_name": "SessionStart", "cwd": "/synthetic/project", "source": "startup"}
    for age, shown in [(0, True), (47, True), (48, False), (49, False), (-1, False)]:
        value = record(now - timedelta(hours=age))
        result = hook.hint(event, options, fetch=lambda *_a, **_k: {"record": value}, now=now)
        assert bool(result) == shown
        if result:
            assert result == {"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": contracts.render(value)}}
    assert hook.hint({**event, "hook_event_name": "Stop"}, options, fetch=lambda *_a, **_k: {}) is None
    assert hook.hint(event, options, fetch=lambda *_a, **_k: {"record": None}) is None


@pytest.mark.parametrize("agent", ["claude", "codex"])
def test_hook_process_outputs_context_and_stays_silent_on_timeout_error(server, tmp_path, monkeypatch, agent):
    monkeypatch.setenv("MULTILLM_KNOWLEDGE_API_KEY", "synthetic-private-credential")
    command = [sys.executable, "-I", str(HOOK_PATH), "--agent", agent, "--base-url", server["base"]]
    event = json.dumps({"hook_event_name": "SessionStart", "cwd": str(tmp_path)})
    result = subprocess.run(command, input=event, text=True, capture_output=True, timeout=3)
    assert result.returncode == 0 and not result.stderr
    assert json.loads(result.stdout)["hookSpecificOutput"]["hookEventName"] == "SessionStart"
    for status, delay in [(503, 0), (200, 2)]:
        server.update(status=status, delay=delay)
        start = time.monotonic()
        result = subprocess.run(command, input=event, text=True, capture_output=True, timeout=3)
        assert time.monotonic() - start < 1.3
        assert result.returncode == 0 and not result.stdout and not result.stderr
    result = subprocess.run([sys.executable, "-I", str(HOOK_PATH), "--unknown"], input="invalid", text=True, capture_output=True, timeout=3)
    assert result.returncode == 0 and not result.stdout and not result.stderr
