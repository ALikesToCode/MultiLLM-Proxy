from scripts.build_release_metadata import fingerprint
from services.release_status import deployment_status


def test_deployment_requires_independent_build_and_protocol_match(monkeypatch):
    monkeypatch.setattr("services.release_status.container_release", lambda: {"build_id": "container-build", "compatibility": 1})
    assert deployment_status({"build_id": "worker-build", "compatibility": 1})["state"] == "pending_or_mixed"
    assert deployment_status({"build_id": "container-build", "compatibility": 1})["state"] == "matched"
    assert deployment_status({"build_id": "container-build", "compatibility": 2})["state"] != "matched"
    assert deployment_status({"build_id": None})["state"] == "unverified"


def test_fingerprint_tracks_sources_not_generated_stamp_or_private_configuration(tmp_path):
    for name in ("cloudflare-worker.mjs", "Dockerfile", "requirements.lock"):
        (tmp_path / name).write_text("synthetic fixture\n")
    (tmp_path / "worker").mkdir()
    before = fingerprint(tmp_path)
    (tmp_path / "worker/build-id.mjs").write_text("generated fingerprint\n")
    (tmp_path / ".env").write_text("SYNTHETIC_ONLY=not-a-real-secret\n")
    assert fingerprint(tmp_path) == before
    (tmp_path / "worker/runtime.mjs").write_text("export const compatibility = 1;\n")
    assert fingerprint(tmp_path) != before


def test_fingerprint_tracks_tool_contracts_migrations_and_worker_configuration(tmp_path):
    for name in ("cloudflare-worker.mjs", "Dockerfile", "requirements.lock"):
        (tmp_path / name).write_text("synthetic fixture\n")
    contract = tmp_path / "worker/knowledge/native-tools.json"
    contract.parent.mkdir(parents=True)
    contract.write_text("{}\n")
    (tmp_path / "intelligence-migrations").mkdir()
    fingerprints = [fingerprint(tmp_path)]
    contract.write_text('{"exa_search": {}}\n')
    fingerprints.append(fingerprint(tmp_path))
    (tmp_path / "intelligence-migrations/0001_example.sql").write_text("CREATE TABLE example (id INTEGER);\n")
    fingerprints.append(fingerprint(tmp_path))
    (tmp_path / "wrangler.knowledge.jsonc").write_text("{}\n")
    fingerprints.append(fingerprint(tmp_path))
    assert len(set(fingerprints)) == 4


def test_fingerprint_tracks_published_skill_content(tmp_path):
    for name in ("cloudflare-worker.mjs", "Dockerfile", "requirements.lock"):
        (tmp_path / name).write_text("synthetic fixture\n")
    skill = tmp_path / "skills/multillm-knowledge/SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("Initial client instructions\n")
    before = fingerprint(tmp_path)
    skill.write_text("Updated client instructions\n")
    assert fingerprint(tmp_path) != before
