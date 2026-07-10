from pathlib import Path


def test_docker_context_excludes_runtime_state_and_local_tool_artifacts():
    repo_root = Path(__file__).resolve().parents[1]
    dockerignore_lines = {
        line.strip()
        for line in (repo_root / ".dockerignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }

    required_patterns = {
        "instance/",
        "*.db",
        "*.db-*",
        "*.sqlite",
        "*.sqlite-*",
        "*.sqlite3",
        "*.sqlite3-*",
        ".wrangler/",
        "*.log",
        ".coverage",
        "coverage.xml",
        "htmlcov/",
    }

    assert required_patterns <= dockerignore_lines
