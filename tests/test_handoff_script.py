"""Handoff recovery uses only synthetic transcripts, keys and loopback HTTP."""
from datetime import datetime, timedelta, timezone
import importlib.util
import io
import json
import re
import shlex
from pathlib import Path
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock, patch

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
    return SimpleNamespace(cwd="/synthetic/project", base_url=None, key_file=None, chat_key_file=None, summarize=None,
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
    state = {"calls": [], "user_agents": [], "summary": {"goal": "Summarized fixture", "next_steps": ["Review"]},
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
            state["user_agents"].append(self.headers.get("User-Agent"))
            state["calls"].append((self.path, self.headers.get("Authorization"), None))
            self.send({"record": state["record"], "trust": "operator"})

        def do_POST(self):
            state["user_agents"].append(self.headers.get("User-Agent"))
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
    assert s["goal"] == "Build the first fixture"
    assert result["summary"] == s["state"]
    assert "FAKE_INJECTED" not in json.dumps(result)
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
    assert result["sections"]["goal"] == "Add the synthetic parser"
    assert "FAKE_INJECTED" not in json.dumps(result)
    assert [item["path"] for item in result["sections"]["files"]] == ["src/parser.py", "src/old.py", "src/new.py", "src/gone.py"]
    assert result["sections"]["state"] == "Parser written; one check failed."
    assert result["sections"]["commands"][0] == {"command": "synthetic-check", "outcome": "Exit 2"}
    assert "TOOL_OUTPUT_MUST_NOT_LEAK" not in json.dumps(result)


def test_codex_code_mode_exec_patches_are_recovered(tmp_path):
    escaped = 'await tools.apply_patch("*** Begin Patch\\n*** Update File: src/app.py\\n@@\\n-a\\n+b\\n*** End Patch")'
    template = "await tools.apply_patch(`*** Begin Patch\n*** Add File: src/new.py\n+x\n*** End Patch`)"
    lines = [{"type": "session_meta", "payload": {"id": "synthetic", "cwd": "/synthetic/project"}},
             *({"type": "response_item", "payload": {"type": "custom_tool_call", "name": "exec", "call_id": f"exec-{index}",
                                                      "input": source}} for index, source in enumerate((escaped, template)))]
    transcript = tmp_path / "rollout.jsonl"
    transcript.write_text("\n".join(json.dumps(line) for line in lines) + "\n")
    with patch.object(transcripts, "git", return_value=""):
        result = transcripts.extract(transcript, "/synthetic/project")
    assert result["sections"]["files"] == [{"path": "src/app.py", "change": "Update File"},
                                           {"path": "src/new.py", "change": "Add File"}]


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


@pytest.mark.parametrize("agent", ["claude", "codex"])
@pytest.mark.parametrize("record_symlink", [False, True])
def test_discovery_matches_resolved_cwd_and_selects_newest(tmp_path, agent, record_symlink):
    project = tmp_path / "project"
    project.mkdir()
    alias = tmp_path / "project-link"
    alias.symlink_to(project, target_is_directory=True)
    recorded, cwd = (alias, project) if record_symlink else (project, alias)
    directory = (tmp_path / ".claude/projects/shortened" if agent == "claude" else
                 tmp_path / ".codex/sessions/2026/10/07")
    directory.mkdir(parents=True)
    def metadata(path):
        return ({"cwd": str(path)} if agent == "claude" else
                {"type": "session_meta", "payload": {"cwd": str(path)}})
    older = directory / "rollout-01.jsonl"
    newest = directory / "rollout-02.jsonl"
    older.write_text(json.dumps(metadata(cwd)))
    newest.write_text(json.dumps(metadata(recorded)))
    import os
    os.utime(older, (1, 1))
    os.utime(newest, (2, 2))
    assert transcripts.discover(cwd, tmp_path, agent) == (newest, agent)


@pytest.mark.parametrize("recorded", [None, 17, [], {}, "", "bad\x00path"])
@pytest.mark.parametrize("codex", [False, True])
def test_discovery_ignores_malformed_recorded_cwd(tmp_path, recorded, codex):
    path = tmp_path / "synthetic.jsonl"
    item = {"cwd": recorded}
    if codex:
        item = {"type": "session_meta", "payload": item}
    path.write_text(json.dumps(item) + "\n")
    assert not transcripts.prefix_matches(path, tmp_path, 5, codex=codex)


def test_discovery_ignores_unresolvable_recorded_cwd(tmp_path):
    loop = tmp_path / "loop"
    loop.symlink_to(loop)
    assert not transcripts.cwd_matches(str(loop), tmp_path)


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


def test_transcript_skips_oversized_lines_and_scan_bounds_fail_closed(tmp_path, monkeypatch):
    path = tmp_path / "synthetic.jsonl"
    path.write_text("{" + "x" * 100 + "}\n")
    monkeypatch.setattr(transcripts, "MAX_LINE_BYTES", 50)
    assert list(transcripts.records(path)) == []
    assert transcripts.clean("x" * 100) == "[oversized fact omitted]"
    assert len(contracts.render(payload(summary="🧭" * 4000)).encode()) <= 4500


@pytest.mark.parametrize("agent", ["claude", "codex"])
def test_oversized_middle_line_preserves_facts_before_and_after(tmp_path, monkeypatch, agent):
    monkeypatch.setattr(transcripts, "MAX_LINE_BYTES", 256)
    def message(role, text):
        return ({"type": role, "message": {"content": text}} if agent == "claude" else
                {"type": "response_item", "payload": {"type": "message", "role": role, "content": text}})
    before = message("user", "Recover the synthetic task")
    oversized = message("user", "Skipped fact " + "x" * 2000)
    after = message("assistant", "Synthetic recovery complete")
    path = tmp_path / "synthetic.jsonl"
    path.write_text("\n".join(json.dumps(item) for item in (before, oversized, after)))
    assert list(transcripts.records(path)) == [before, after]
    with patch.object(transcripts, "git", return_value=""):
        value = transcripts.extract(path, tmp_path, agent)
    assert value["sections"]["goal"] == "Recover the synthetic task"
    assert value["sections"]["state"] == "Synthetic recovery complete"
    assert value["sections"]["decisions"] == ["User: Recover the synthetic task"]


@pytest.mark.parametrize("aligned", [False, True])
def test_oversized_transcript_recovers_tail_goal_and_final(tmp_path, monkeypatch, aligned):
    def message(role, text):
        return json.dumps({"type": "response_item", "payload": {
            "type": "message", "role": role, "content": text}}).encode() + b"\n"
    tail = message("user", "Recent synthetic task") + message("assistant", "Recent synthetic state")
    prefix = message("user", "Old synthetic task") + b"x" * 1000 + b"\n"
    path = tmp_path / "synthetic.jsonl"
    path.write_bytes(prefix + tail)
    monkeypatch.setattr(transcripts, "MAX_LINE_BYTES", 256)
    monkeypatch.setattr(transcripts, "MAX_TRANSCRIPT_BYTES", len(tail) + (0 if aligned else 100))
    with patch.object(transcripts, "git", return_value=""):
        value = transcripts.extract(path, tmp_path, "codex")
    assert value["sections"]["goal"] == "Recent synthetic task"
    assert value["sections"]["state"] == "Recent synthetic state"
    assert "Old synthetic task" not in json.dumps(value)


@pytest.mark.parametrize("tail_only", [False, True])
def test_transcript_reads_are_bounded_while_discarding_long_lines(monkeypatch, tail_only):
    monkeypatch.setattr(transcripts, "MAX_LINE_BYTES", 64)
    first, last = b'{"fact":"before"}\n', b'{"fact":"after"}\n'
    data = first + b"x" * 1000 + b"\n" + last
    if tail_only:
        monkeypatch.setattr(transcripts, "MAX_TRANSCRIPT_BYTES", 500)
    reads = []
    class BoundedStream(io.BytesIO):
        def read(self, size=-1):
            reads.append(size)
            assert 0 < size <= transcripts.MAX_LINE_BYTES + 1
            return super().read(size)

        def readline(self, size=-1):
            reads.append(size)
            assert 0 < size <= transcripts.MAX_LINE_BYTES + 1
            return super().readline(size)

    with patch.object(Path, "open", return_value=BoundedStream(data)):
        values = list(transcripts.records("/synthetic/transcript.jsonl"))
    assert values == ([{"fact": "after"}] if tail_only else [{"fact": "before"}, {"fact": "after"}])
    assert len(reads) > 3


def test_oversized_final_line_without_newline_is_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(transcripts, "MAX_LINE_BYTES", 64)
    path = tmp_path / "synthetic.jsonl"
    path.write_bytes(b'{"fact":"before"}\n' + b"x" * 1000)
    assert list(transcripts.records(path)) == [{"fact": "before"}]


def test_summarize_validation_and_transport_failures_keep_deterministic_sections(server, monkeypatch):
    monkeypatch.setenv("MULTILLM_API_KEY", "synthetic-chat-credential")
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
@pytest.mark.parametrize("mode", ["pointer", "full"])
def test_hook_official_output_formats_and_age(agent, mode):
    now = datetime.now(timezone.utc)
    options = args()
    options.agent, options.mode = agent, mode
    event = {"hook_event_name": "SessionStart", "cwd": "/synthetic/project", "source": "startup"}
    for age, shown in [(0, True), (47, True), (48, False), (49, False), (-1, False)]:
        value = record(now - timedelta(hours=age))
        result = hook.hint(event, options, fetch=lambda *_a, **_k: {"record": value}, now=now)
        assert bool(result) == shown
        if result:
            assert result == {"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": contracts.render(value) if mode == "full" else hook.pointer(value, age * 3600)}}
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
    for status, delay in [(503, 0), (200, 3)]:
        server.update(status=status, delay=delay)
        start = time.monotonic()
        result = subprocess.run(command, input=event, text=True, capture_output=True, timeout=5)
        assert time.monotonic() - start < 2
        assert result.returncode == 0 and not result.stdout and not result.stderr
    result = subprocess.run([sys.executable, "-I", str(HOOK_PATH), "--unknown"], input="invalid", text=True, capture_output=True, timeout=3)
    assert result.returncode == 0 and not result.stdout and not result.stderr


def test_summary_and_save_use_distinct_keys_and_every_request_has_user_agent(server, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("MULTILLM_KNOWLEDGE_API_KEY", "synthetic-knowledge-credential")
    monkeypatch.setenv("MULTILLM_API_KEY", "synthetic-chat-credential")
    transcript = ROOT / "tests/fixtures/handoff_codex.jsonl"
    command = ["save", "--cwd", str(tmp_path), "--base-url", server["base"],
               "--transcript", str(transcript), "--summarize", "synthetic-model"]
    assert handoff.main(command) == 0
    assert [(path, key) for path, key, _ in server["calls"]] == [
        ("/v1/chat/completions", "Bearer synthetic-chat-credential"),
        ("/v1/knowledge/handoffs", "Bearer synthetic-knowledge-credential")]
    assert handoff.main(["load", "--cwd", str(tmp_path), "--base-url", server["base"]]) == 0
    assert server["calls"][-1][1] == "Bearer synthetic-knowledge-credential"
    assert server["user_agents"] == ["multillm-handoff/1"] * 3
    output = capsys.readouterr()
    assert "credential" not in output.out + output.err


def test_missing_chat_key_skips_summary_without_using_knowledge_key(server, monkeypatch, capsys):
    monkeypatch.delenv("MULTILLM_API_KEY", raising=False)
    monkeypatch.setenv("MULTILLM_KNOWLEDGE_API_KEY", "synthetic-knowledge-credential")
    options = args()
    options.base_url, options.summarize = server["base"], "synthetic-model"
    value = contracts.validate_payload(payload())
    assert handoff.summarize(options, value) == value
    assert server["calls"] == []
    assert capsys.readouterr().err == "summarize skipped: no chat key\n"


def test_summary_includes_long_closing_report(server, monkeypatch):
    monkeypatch.setenv("MULTILLM_API_KEY", "synthetic-chat-credential")
    options = args()
    options.base_url, options.summarize = server["base"], "synthetic-model"
    value = contracts.validate_payload(payload(summary="closing report " * 200))
    handoff.summarize(options, value)
    facts = json.loads(server["calls"][-1][2]["messages"][1]["content"])
    assert facts["summary"] == value["summary"]


@pytest.mark.parametrize("key", ["x" * 4097, "fake\nvalue", "fake\rvalue"])
def test_chat_key_validation_matches_knowledge_key(monkeypatch, key):
    for env, label in [("MULTILLM_API_KEY", "chat"), ("MULTILLM_KNOWLEDGE_API_KEY", "Knowledge")]:
        monkeypatch.setenv(env, key)
        with pytest.raises(ValueError):
            handoff.private_key(env, None, label)


def test_chat_key_file_uses_same_private_loader_without_reading_operator_files(monkeypatch):
    monkeypatch.setenv("MULTILLM_API_KEY", "synthetic-environment-credential")
    with patch.object(Path, "open", return_value=io.StringIO("synthetic-file-credential\n")) as opened:
        assert handoff.private_key("MULTILLM_API_KEY", "/synthetic/chat-key", "chat") == "synthetic-file-credential"
    opened.assert_called_once()
    assert handoff.parser().parse_args(["build", "--chat-key-file", "/synthetic/chat-key"]).chat_key_file == "/synthetic/chat-key"


@pytest.mark.parametrize("cwd", ["/synthetic/dotted.repo", "/synthetic/under_scored repo"])
def test_claude_discovery_encodes_every_non_alphanumeric_character(tmp_path, cwd):
    import re
    path = tmp_path / ".claude/projects" / re.sub(r"[^A-Za-z0-9]", "-", cwd) / "fixture.jsonl"
    path.parent.mkdir(parents=True)
    path.write_text("{}\n")
    assert transcripts.discover(cwd, tmp_path, "claude") == (path, "claude")


def test_claude_discovery_falls_back_to_bounded_cwd_prefix(tmp_path, monkeypatch):
    cwd = "/synthetic/long.dotted_repo"
    directory = tmp_path / ".claude/projects/shortened"
    directory.mkdir(parents=True)
    unrelated = directory / "unrelated.jsonl"
    unrelated.write_text(json.dumps({"cwd": "/other"}))
    path = directory / "matching.jsonl"
    path.write_text("{}\n" * 19 + json.dumps({"type": "user", "cwd": cwd}))
    assert transcripts.discover(cwd, tmp_path, "claude") == (path, "claude")
    path.write_text("{}\n" * 20 + json.dumps({"cwd": cwd}))
    with pytest.raises(ValueError):
        transcripts.discover(cwd, tmp_path, "claude")
    path.write_text("x" * (transcripts.MAX_LINE_BYTES + 1) + "\n" + json.dumps({"cwd": cwd}))
    with pytest.raises(ValueError):
        transcripts.discover(cwd, tmp_path, "claude")
    monkeypatch.setattr(transcripts, "MAX_FILES_DISCOVERED", 1)
    with patch.object(Path, "glob", return_value=iter([unrelated, path])):
        with pytest.raises(ValueError):
            transcripts.discover(cwd, tmp_path, "claude")


def test_codex_discovery_visits_newest_dates_and_sessions_before_file_cap(tmp_path, monkeypatch):
    cwd = "/synthetic/project"
    paths = []
    for date, name in [("2025/12/31", "old"), ("2026/09/30", "old"),
                       ("2026/10/06", "old"), ("2026/10/07", "01"), ("2026/10/07", "02")]:
        path = tmp_path / ".codex/sessions" / date / f"rollout-{name}.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"type": "session_meta", "payload": {"cwd": cwd}}))
        paths.append(path)
    monkeypatch.setattr(transcripts, "MAX_FILES_DISCOVERED", 4)
    with patch.object(transcripts, "prefix_matches", wraps=transcripts.prefix_matches) as inspected:
        assert transcripts.discover(cwd, tmp_path, "codex") == (paths[-1], "codex")
    assert inspected.call_count == 1
    assert inspected.call_args.args[0] == paths[-1]


@pytest.mark.parametrize("agent", ["claude", "codex"])
def test_extract_retains_first_goal_and_long_redacted_closing_summary(tmp_path, agent):
    secret = "AK" + "IA" + "AB12CD34EF56GH78"
    final = "Closing synthetic report " * 220 + secret
    def message(role, text):
        return ({"type": role, "message": {"content": text}} if agent == "claude" else
                {"type": "response_item", "payload": {"type": "message", "role": role, "content": text}})
    items = [message("user", "First task " + "x" * 600)]
    items += [message("user", f"Follow up {i}") for i in range(5)]
    items += [message("assistant", final)]
    path = tmp_path / "synthetic.jsonl"
    path.write_text("\n".join(json.dumps(item) for item in items))
    with patch.object(transcripts, "git", return_value=""):
        result = transcripts.extract(path, tmp_path, agent)
    assert result["sections"]["goal"] == ("First task " + "x" * 600)[:500]
    assert result["sections"]["decisions"] == [f"User: Follow up {i}" for i in (2, 3, 4)]
    assert result["sections"]["state"] == result["summary"][:500]
    assert len(result["summary"]) == 4000
    assert secret not in json.dumps(result)
    # The redacted closing report remains available beyond the 500-character state.
    items[-1] = message("assistant", "closing " * 100 + secret)
    path.write_text("\n".join(json.dumps(item) for item in items))
    with patch.object(transcripts, "git", return_value=""):
        assert "[REDACTED:" in transcripts.extract(path, tmp_path, agent)["summary"]


@pytest.mark.parametrize("agent", ["claude", "codex"])
def test_no_operator_user_facts_uses_default_goal(tmp_path, agent):
    path = tmp_path / "synthetic.jsonl"
    value = {"type": "user", "message": {"content": "<task-notification>Fake</task-notification>"}}
    if agent == "codex":
        value = {"type": "response_item", "payload": {"type": "message", "role": "developer", "content": "Fake"}}
    path.write_text(json.dumps(value))
    with patch.object(transcripts, "git", return_value=""):
        result = transcripts.extract(path, tmp_path, agent)
    assert result["sections"]["goal"] == "Continue the task"
    assert result["sections"]["decisions"] == []


@pytest.mark.parametrize("source,shown", [("startup", True), ("clear", True), ("resume", False),
                                         ("compact", False), ("unknown", False), (None, False)])
def test_hook_only_fetches_for_new_sessions(source, shown):
    event = {"hook_event_name": "SessionStart", "cwd": "/synthetic/project", "source": source}
    fetch = lambda *_a, **_k: {"record": record()}
    fetched = Mock(side_effect=fetch)
    assert bool(hook.hint(event, args(), fetch=fetched)) == shown
    assert fetched.call_count == int(shown)
    assert hook.hint({key: value for key, value in event.items() if key != "source"}, args(), fetch=fetch)


def test_hook_default_pointer_and_full_mode_show_saved_branch_after_fallback():
    value = record()
    value["branch"] = "saved-main"
    now = datetime.now(timezone.utc)
    options = args()
    event = {"hook_event_name": "SessionStart", "cwd": "/synthetic/project"}
    fetched = lambda *_a, **_k: {"record": value}
    pointer = hook.hint(event, options, fetch=fetched, now=now)["hookSpecificOutput"]["additionalContext"]
    assert "(saved-main)" in pointer and '"branch": "saved-main"' in pointer
    assert "knowledge_handoff_get" in pointer
    assert "Goal:" not in pointer
    assert len(pointer.encode()) <= 600
    options.mode = "full"
    assert hook.hint(event, options, fetch=fetched, now=now)["hookSpecificOutput"]["additionalContext"] == contracts.render(value)


@pytest.mark.parametrize("unicode", [False, True])
def test_hook_pointer_utf8_budget_and_title_clip(unicode):
    value = record()
    value.update(project=("🧭" if unicode else "p") * 200, branch=("枝" if unicode else "b") * 200,
                 title="t" * 200)
    text = hook.pointer(value, 47 * 3600)
    assert len(text.encode()) <= 600
    assert "t" * 121 not in text
    assert "scripts/handoff.py load" in text
    assert "�" not in text


@pytest.mark.parametrize("clipped_pointer", [False, True])
def test_hook_pointer_command_is_absolute_and_works_from_operator_cwd(tmp_path, clipped_pointer):
    value = record()
    if clipped_pointer:
        value.update(project="🧭" * 200, branch="枝" * 200, title="Title " * 30)
    text = hook.pointer(value, 3600)
    command = shlex.split(re.search(r"run (python3 .+? load)\.", text).group(1))
    assert command[0] == "python3" and command[-1] == "load"
    script = Path(command[1])
    assert script.is_absolute() and script == ROOT / "scripts/handoff.py" and script.is_file()
    assert len(text.encode("utf-8")) <= 600
    result = subprocess.run([*command, "--help"], cwd=tmp_path, text=True, capture_output=True, timeout=3)
    assert result.returncode == 0 and "usage:" in result.stdout and not result.stderr


def test_hook_pointer_quotes_script_paths_and_reserves_command_budget(tmp_path, monkeypatch):
    checkout = tmp_path / ("synthetic checkout's " + "x" * 80)
    script = checkout / "scripts/handoff.py"
    script.parent.mkdir(parents=True)
    script.write_text("# Synthetic hook target\n")
    monkeypatch.setattr(hook, "ROOT", checkout)
    value = record()
    value.update(project="🧭" * 200, branch="枝" * 200, title="🧭" * 200)
    text = hook.pointer(value, 47 * 3600)
    command = shlex.split(re.search(r"run (python3 .+? load)\.", text).group(1))
    assert command == ["python3", str(script), "load"]
    assert script.is_absolute() and script.is_file()
    assert len(text.encode("utf-8")) <= 600 and "�" not in text
