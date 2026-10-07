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


def test_secret_rejection_disables_pruning_and_symlink_escape_is_skipped(tmp_path):
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
    plan = sync.build_plan({"agents": root}, {})
    assert len(plan["skills"]) == 1 and plan["rejected"] == []
    assert plan["skipped_files"] == 1
    assert [file["path"] for file in plan["skills"][0]["files"]] == ["SKILL.md", "references/guide.md"]


def test_size_limits_duplicates_and_batch_bounds(tmp_path):
    root, directory = library(tmp_path)
    (directory / "scripts/run.py").write_bytes(b"x" * (262144 + 1))
    assert sync.build_plan({"agents": root}, {})["rejected"][0]["reason"] == "skill_limits"
    (directory / "scripts/run.py").write_text("safe")
    plan = sync.build_plan({"agents": root, "codex": root}, {})
    assert len(plan["skills"]) == 1
    assert plan["rejected"] == [] and plan["duplicates"] == 1 and plan["conflicts"] == []
    batches = list(sync.batches({"skills": plan["skills"] * 33, "delete": ["old"]}))
    assert [len(batch["skills"]) for batch in batches] == [16, 16, 1, 0]


@pytest.fixture
def fake_server():
    received = []
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            received.append(body)
            assert self.headers["User-Agent"] == "multillm-skills/1"
            if self.path == "/v1/knowledge/skills/find":
                assert body == {"query": "Test regression behavior", "mode": "fast", "limit": 3, "min_confidence": "high"}
                assert "query" not in self.path
                result = [{"skill_id": "testing", "name": "Testing", "description": "Test behavior", "confidence": "high", "score": 0.01}]
            else:
                assert self.path == "/v1/knowledge/skills"
                results = [{"skill_id": skill["skill_id"], "status": "created"} for skill in body["skills"]]
                results += [{"skill_id": identity, "status": "deleted"} for identity in body.get("delete", [])]
                result = {"results": results}
            encoded = json.dumps(result).encode()
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
    fetcher = lambda *_args: [{"skill_id": "testing", "name": "Testing", "description": "Test behavior", "confidence": "high", "score": 1}]
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
    records = [{"skill_id": "testing", "name": "Testing", "description": "Testing reference guide " * 20, "confidence": "high", "score": 1}] * 3
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
    plan = sync.build_plan({"agents": root}, {"agents": ["old"]})
    assert plan["delete"] == ["old"] and len(plan["skills"]) == 1 and plan["rejected"] == []


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
    assert received == [{"query": "Test regression behavior", "mode": "fast", "limit": 3, "min_confidence": "high"}]


def test_plan_never_exceeds_global_capacity_and_delete_batches(tmp_path, monkeypatch):
    root, _directory = library(tmp_path)
    library(tmp_path, name="second")
    monkeypatch.setattr(sync, "MAX_SKILLS", 1)
    plan = sync.build_plan({"agents": root}, {"agents": ["old"]})
    assert len(plan["skills"]) == 1 and plan["delete"] == []
    assert plan["rejected"][0]["reason"] == "skills_limit"
    assert [batch["delete"] for batch in sync.batches({"skills": [], "delete": ["one", "two"]})] == [["one"], ["two"]]


def test_external_mentions_nested_mentions_and_duplicate_conflicts(tmp_path):
    root, directory = library(tmp_path)
    with (directory / "SKILL.md").open("a") as handle:
        handle.write("Mention `/etc/hosts`, `~/.config/x`, and [other](../other-skill/SKILL.md).")
    (directory / "references/guide.md").write_text("Mention `/tmp/x` and `../../outside.txt`.")
    plan = sync.build_plan({"agents": root}, {})
    assert len(plan["skills"]) == 1 and plan["rejected"] == [] and plan["skipped_files"] == 0
    assert len(plan["skills"][0]["files"]) == 3
    other, _ = library(tmp_path / "other", description="Different content")
    plan = sync.build_plan({"agents": root, "claude": root, "codex": other}, {})
    assert len(plan["skills"]) == 1 and plan["rejected"] == [] and plan["duplicates"] == 1
    assert plan["conflicts"] == [{"skill_id": "testing", "reason": "duplicate_conflict", "kept_root": "agents", "skipped_root": "codex"}]


def test_client_key_file_precedence_default_state_and_permissions(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sync.Path, "home", lambda: tmp_path / "home")
    monkeypatch.setenv("MULTILLM_KNOWLEDGE_API_KEY", "synthetic-stale-key")
    monkeypatch.setenv("MULTILLM_BASE_URL", "https://unused.example")
    key_file = tmp_path / "synthetic-key-file"
    key_file.write_text("synthetic-rotated-key\n")
    root, _ = library(tmp_path)
    seen = []
    def submit(url, key, payload):
        seen.append((url, key))
        return [{"skill_id": item["skill_id"], "status": "created"} for item in payload["skills"]]
    monkeypatch.setattr(sync, "sync_batch", submit)
    assert sync.main(["--root", "agents=" + str(root), "--key-file", str(key_file), "--base-url", "https://chosen.example"]) == 0
    assert seen == [("https://chosen.example", "synthetic-rotated-key")]
    state = tmp_path / "home/.config/multillm/skills-sync-state.json"
    assert json.loads(state.read_text()) == {"agents": ["testing"]}
    assert state.stat().st_mode & 0o777 == 0o600
    assert state.parent.stat().st_mode & 0o777 == 0o700
    fetcher = lambda prompt, url, key: seen.append((url, key)) or []
    assert hook.hint({"prompt": "Test regression behavior"}, key_file=key_file, base_url="https://chosen.example", fetcher=fetcher) is None
    assert seen[-1] == ("https://chosen.example", "synthetic-rotated-key")
    assert hook.hint({"prompt": "Test regression behavior"}, key_file=tmp_path / "missing", fetcher=fetcher) is None
    assert "synthetic-rotated-key" not in capsys.readouterr().out


def test_key_file_read_obeys_hook_total_deadline(tmp_path, monkeypatch):
    monkeypatch.setenv("MULTILLM_BASE_URL", "https://unused.example")
    def slow(*args, **kwargs):
        time.sleep(1.5)
        raise OSError("synthetic read error")
    monkeypatch.setattr(hook.Path, "open", slow)
    start = time.monotonic()
    assert hook.hint({"prompt": "Test regression behavior"}, key_file=tmp_path / "synthetic") is None
    assert time.monotonic() - start < 0.9


def test_sync_batch_byte_boundary_and_maximal_binary_skill(tmp_path, monkeypatch):
    import base64
    chunk = base64.b64encode(b"x" * 262144).decode()
    files = [{"path": "SKILL.md", "content": "x" * 65536, "sha256": "0" * 64}]
    files += [{"path": f"assets/{i}.bin", "content_base64": chunk, "sha256": "0" * 64} for i in range(19)]
    files += [{"path": "assets/final.bin", "content_base64": base64.b64encode(b"x" * 196608).decode(), "sha256": "0" * 64}]
    skill = {"skill_id": "maximal", "name": "maximal", "description": "Synthetic", "root": "agents", "files": files}
    assert sum(len(base64.b64decode(f["content_base64"])) if "content_base64" in f else len(f["content"]) for f in files) == 5 * 1024 * 1024
    assert sync.MAX_BATCH_BYTES == 8 * 1024 * 1024 - 4096
    assert list(sync.batches({"skills": [skill], "delete": []})) == [{"skills": [skill]}]
    exact = len(json.dumps({"skills": [skill]}).encode())
    monkeypatch.setattr(sync, "MAX_BATCH_BYTES", exact)
    assert len(list(sync.batches({"skills": [skill, skill], "delete": []}))) == 2
    monkeypatch.setattr(sync, "MAX_BATCH_BYTES", exact - 1)
    with pytest.raises(sync.PlanError, match="batch_bytes_limit"):
        list(sync.batches({"skills": [skill], "delete": []}))


def test_summary_lists_safe_rejections_conflicts_and_skip_counts(tmp_path, monkeypatch, capsys):
    root, directory = library(tmp_path)
    other, _ = library(tmp_path / "other", description="Different")
    library(tmp_path, name="unsafe")
    token = "gh" + "p_" + "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5"
    (root / "unsafe/scripts/run.py").write_text(token)
    (directory / "scripts/run.py").unlink()
    (directory / "scripts/run.py").symlink_to(tmp_path / "outside")
    (tmp_path / "outside").write_text("safe")
    monkeypatch.setenv("MULTILLM_KNOWLEDGE_API_KEY", "synthetic-key")
    monkeypatch.setattr(sync, "sync_batch", lambda *_args: [{"skill_id": "testing", "status": "rejected", "reason": "root_conflict"}])
    assert sync.main(["--root", "agents=" + str(root), "--root", "codex=" + str(other), "--base-url", "https://unused.example", "--state-file", str(tmp_path / "state")]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["synced"]["rejected"] == 1 and summary["skipped_files"] == 1
    assert summary["conflicts"][0]["reason"] == "duplicate_conflict"
    assert [(item["skill_id"], item["reason"]) for item in summary["rejected"]] == [("unsafe", "secret_detected:scripts/run.py:github_token"), ("testing", "root_conflict")]
    assert token not in json.dumps(summary)


def test_skill_entry_symlink_escape_is_never_read(tmp_path):
    root, directory = library(tmp_path)
    original = directory / "SKILL.md"
    original.unlink()
    outside = tmp_path / "outside-skill"
    outside.write_text("invalid frontmatter must never be read")
    original.symlink_to(outside)
    plan = sync.build_plan({"agents": root}, {"agents": ["old"]})
    assert plan["skills"] == [] and plan["rejected"] == [] and plan["delete"] == []
    assert plan["skipped_files"] == 1


def test_json_escaped_text_uses_base64_without_losing_reference_collection(tmp_path):
    root, directory = library(tmp_path)
    (directory / "scripts/run.py").write_text("\x00" * 262144)
    plan = sync.build_plan({"agents": root}, {})
    file = next(f for f in plan["skills"][0]["files"] if f["path"] == "scripts/run.py")
    assert "content_base64" in file and "content" not in file
    assert len(list(sync.batches(plan))) == 1
