"""Local-only client tests with temporary libraries and a synthetic HTTP server."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


sync = module("skills_sync", "scripts/skills_sync.py")
hook = module("skill_hint", "scripts/hooks/skill_hint.py")


def library(tmp_path, name="testing", description="Test behavior"):
    root = tmp_path / "library"
    directory = root / name
    directory.mkdir(parents=True)
    (directory / "SKILL.md").write_text(f"---\nname: {name}\ndescription: {description}\n---\n# Guide\nRead [reference](references/guide.md) and `scripts/run.py`.\n")
    (directory / "references").mkdir()
    (directory / "references/guide.md").write_text("Reference text")
    (directory / "scripts").mkdir()
    (directory / "scripts/run.py").write_text("print('synthetic')")
    return root, directory


def test_plan_frontmatter_references_hashes_and_root_scoped_deletion(tmp_path):
    root, directory = library(tmp_path)
    (directory / "unreferenced.txt").write_text("unused")
    plan = sync.build_plan({"agents": root}, {"agents": ["old"], "codex": ["other"]})
    assert plan["delete"] == ["old"]
    assert plan["rejected"] == []
    assert [file["path"] for file in plan["skills"][0]["files"]] == ["SKILL.md", "references/guide.md", "scripts/run.py"]
    assert all(len(file["sha256"]) == 64 for file in plan["skills"][0]["files"])
    assert sync.frontmatter('---\nname: "Test"\ndescription: >-\n  A long\n  description\n---') == {"name": "Test", "description": "A long description"}
    assert sync.frontmatter("---\nname: 'Test'\ndescription: 'description'\n---")["name"] == "Test"
    assert sync.build_plan({"agents": tmp_path / "missing"}, {"agents": ["old"]})["delete"] == []


def test_secret_rejection_missing_files_and_symlink_escape_disable_pruning(tmp_path):
    root, directory = library(tmp_path)
    token = "gh" + "p_" + "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5"
    (directory / "scripts/run.py").write_text(token)
    plan = sync.build_plan({"agents": root}, {"agents": ["old", "testing"]})
    assert plan["skills"] == [] and plan["delete"] == []
    assert plan["rejected"][0]["reason"] == "secret_detected:scripts/run.py:github_token"
    assert token not in json.dumps(plan)
    outside = tmp_path / "outside.py"
    outside.write_text("synthetic")
    (directory / "scripts/run.py").unlink()
    (directory / "scripts/run.py").symlink_to(outside)
    assert sync.build_plan({"agents": root}, {})["rejected"][0]["reason"] == "path_traversal"


def test_size_limits_duplicates_and_batch_bounds(tmp_path):
    root, directory = library(tmp_path)
    (directory / "scripts/run.py").write_bytes(b"x" * (262144 + 1))
    assert sync.build_plan({"agents": root}, {})["rejected"][0]["reason"] == "skill_limits"
    (directory / "scripts/run.py").write_text("safe")
    plan = sync.build_plan({"agents": root, "codex": root}, {})
    assert len(plan["skills"]) == 1
    assert plan["rejected"][0]["reason"] == "duplicate_slug"
    batches = list(sync.batches({"skills": plan["skills"] * 33, "delete": ["old"]}))
    assert [len(batch["skills"]) for batch in batches] == [16, 16, 1, 0]


@pytest.fixture
def fake_server():
    received = []
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            received.append(self.path)
            encoded = json.dumps([{"skill_id": "testing", "name": "Testing", "description": "Test behavior", "score": 1}]).encode()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(encoded)
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            received.append(body)
            results = [{"skill_id": skill["skill_id"], "status": "created"} for skill in body["skills"]]
            results += [{"skill_id": identity, "status": "deleted"} for identity in body.get("delete", [])]
            encoded = json.dumps({"results": results}).encode()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(encoded)
        def log_message(self, *_args):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}", received
    server.shutdown()
    server.server_close()
    thread.join()


def test_sync_dry_run_never_reads_key_or_calls_server_then_records_success(tmp_path, fake_server, monkeypatch, capsys):
    base_url, received = fake_server
    root, _directory = library(tmp_path)
    state = tmp_path / "receipts.json"
    state.write_text(json.dumps({"agents": ["old"], "codex": ["other"]}))
    arguments = ["--root", "agents=" + str(root), "--base-url", base_url, "--state-file", str(state)]
    assert sync.main(arguments + ["--dry-run", "--key-file", str(tmp_path / "does-not-exist")]) == 0
    assert received == []
    assert '"delete"' in capsys.readouterr().out
    monkeypatch.setenv("MULTILLM_KNOWLEDGE_API_KEY", "synthetic-sync-key")
    assert sync.main(arguments) == 0
    assert len(received) == 2
    assert json.loads(state.read_text()) == {"agents": ["testing"], "codex": ["other"]}
    output = capsys.readouterr().out
    assert "synthetic-sync-key" not in output
    assert '"created": 1' in output and '"deleted": 1' in output


@pytest.mark.parametrize("event,agent", [({"prompt": "Test regression behavior", "hook_event_name": "UserPromptSubmit"}, "claude"),
                                        ({"prompt": "Test regression behavior", "turn_id": "synthetic-turn"}, "codex")])
def test_hook_official_json_formats_and_auto_detection(event, agent, monkeypatch):
    monkeypatch.setenv("MULTILLM_BASE_URL", "https://gateway.example")
    monkeypatch.setenv("MULTILLM_KNOWLEDGE_API_KEY", "synthetic-hook-key")
    fetcher = lambda *_args: [{"skill_id": "testing", "name": "Testing", "description": "Test behavior", "score": 1}]
    output = hook.hint(event, fetcher=fetcher)
    assert output == hook.hint(event, agent, fetcher=fetcher)
    specific = output["hookSpecificOutput"]
    assert specific["hookEventName"] == "UserPromptSubmit"
    assert specific["additionalContext"] == "Relevant skills: Testing - Test behavior (load with knowledge_skills_get skill_id=testing)"


def test_hook_silence_timeout_total_budget_and_token_bound(monkeypatch):
    monkeypatch.setenv("MULTILLM_BASE_URL", "https://gateway.example")
    monkeypatch.setenv("MULTILLM_KNOWLEDGE_API_KEY", "synthetic-hook-key")
    event = {"prompt": "Test regression behavior"}
    assert hook.hint({"prompt": "tiny"}) is None
    assert hook.hint(event, fetcher=lambda *_args: []) is None
    assert hook.hint(event, fetcher=lambda *_args: [{"score": 0.1}]) is None
    def fail(*_args):
        raise OSError("synthetic private detail")
    assert hook.hint(event, fetcher=fail) is None
    def slow(*_args):
        time.sleep(1.5)
        return []
    start = time.monotonic()
    assert hook.hint(event, fetcher=slow) is None
    assert time.monotonic() - start < 0.9
    records = [{"skill_id": "testing", "name": "Testing", "description": "Testing reference guide " * 20, "score": 1}] * 3
    text = hook.context(records)
    assert len(text.encode()) <= 600
    assert len(text) / 4 <= 150
    unicode_text = hook.context([{**item, "description": "测试" * 100} for item in records])
    assert len(unicode_text.encode()) <= 600
    process = subprocess.run([sys.executable, "-I", str(ROOT / "scripts/hooks/skill_hint.py")], input="bad json", text=True, capture_output=True, timeout=2)
    assert process.returncode == 0 and process.stdout == "" and process.stderr == ""


def test_nested_relative_references_and_atomic_receipts(tmp_path):
    root, directory = library(tmp_path)
    (directory / "references/guide.md").write_text("Read [script](../scripts/run.py)")
    assert len(sync.build_plan({"agents": root}, {})["skills"][0]["files"]) == 3
    (directory / "references/guide.md").write_text("Read [escape](../../outside.txt)")
    assert sync.build_plan({"agents": root}, {"agents": ["old"]})["delete"] == []


def test_hook_cli_invalid_arguments_are_silent():
    process = subprocess.run([sys.executable, "-I", str(ROOT / "scripts/hooks/skill_hint.py"), "--agent", "invalid"],
                             input="{}", text=True, capture_output=True, timeout=2)
    assert process.returncode == 0 and process.stdout == "" and process.stderr == ""


def test_hook_real_rest_find_uses_fast_limit_three(fake_server, monkeypatch):
    base_url, received = fake_server
    monkeypatch.setenv("MULTILLM_BASE_URL", base_url)
    monkeypatch.setenv("MULTILLM_KNOWLEDGE_API_KEY", "synthetic-hook-key")
    result = hook.hint({"prompt": "Test regression behavior"})
    assert "Relevant skills: Testing" in result["hookSpecificOutput"]["additionalContext"]
    assert received == ["/v1/knowledge/skills?query=Test+regression+behavior&mode=fast&limit=3"]


def test_plan_never_exceeds_global_capacity_and_delete_batches(tmp_path, monkeypatch):
    root, _directory = library(tmp_path)
    library(tmp_path, name="second")
    monkeypatch.setattr(sync, "MAX_SKILLS", 1)
    plan = sync.build_plan({"agents": root}, {"agents": ["old"]})
    assert len(plan["skills"]) == 1 and plan["delete"] == []
    assert plan["rejected"][0]["reason"] == "skills_limit"
    assert [batch["delete"] for batch in sync.batches({"skills": [], "delete": ["one", "two"]})] == [["one"], ["two"]]
