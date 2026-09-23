"""Public setup must stay discoverable without opening account or management data."""

import json
import tomllib
from html import unescape
from pathlib import Path
from unittest.mock import patch

import pytest
from flask import Flask
from flask_wtf.csrf import CSRFProtect

from error_handlers import init_error_handlers
from routes.core import register_core_routes
from routes.knowledge import register_knowledge_routes


@pytest.fixture
def client():
    app = Flask(__name__, template_folder=str(Path(__file__).resolve().parents[1] / "templates"))
    app.config.update(SECRET_KEY="synthetic-onboarding-session", API_BASE_URLS={}, TESTING=True)
    init_error_handlers(app)
    csrf = CSRFProtect(app)
    register_core_routes(app)
    register_knowledge_routes(app, csrf)
    with patch("routes.core.AuthService.is_authenticated", return_value=False):
        yield app.test_client()


@pytest.mark.parametrize("path,content_type", [
    ("/agent-onboarding", "text/html"), ("/llms.txt", "text/markdown"),
    ("/llm.txt", "text/markdown"), ("/llms-full.txt", "text/markdown"),
    ("/agent-onboarding/SKILL.md", "text/markdown"),
    ("/agent-onboarding/prompt.txt", "text/plain"),
    ("/agent-onboarding/config.json", "application/json"),
])
def test_public_onboarding_needs_no_login_or_provider_call(client, path, content_type):
    with patch("routes.knowledge.dispatch") as dispatch:
        response = client.get(path, base_url="https://gateway.example")
    assert response.status_code == 200
    assert response.content_type.startswith(content_type)
    assert "https://gateway.example/mcp" in response.get_data(as_text=True)
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    dispatch.assert_not_called()


def test_discovery_and_skill_download_agree(client):
    config = client.get("/agent-onboarding/config.json", base_url="https://gateway.example").json
    assert config["url"] == "https://gateway.example/mcp"
    assert config["authentication"] == {"type": "bearer", "env": "MULTILLM_KNOWLEDGE_API_KEY"}
    assert len(config["tools"]) == 13
    assert len({tool["name"] for tool in config["tools"]}) == 13
    assert sum(tool["scope"] == "knowledge:manage" for tool in config["tools"]) == 6
    assert len(config["providers"]) == 7
    skill = client.get("/agent-onboarding/SKILL.md?download=1", base_url="https://gateway.example")
    assert skill.data.startswith(b"---\nname: multillm-knowledge\n")
    assert 'attachment; filename="SKILL.md"' == skill.headers["Content-Disposition"]
    assert skill.data == client.get("/llms-full.txt", base_url="https://gateway.example").data
    assert client.get("/llm.txt").data == client.get("/llms.txt").data


def test_client_configs_reference_environment_credentials(client):
    html = client.get("/agent-onboarding", base_url="https://gateway.example").get_data(as_text=True)
    def snippet(identifier):
        return unescape(html.split(f'<pre id="{identifier}">', 1)[1].split("</pre>", 1)[0])
    codex = tomllib.loads(snippet("codex-mcp-config"))["mcp_servers"]["multillm-knowledge"]
    claude = json.loads(snippet("claude-mcp-config"))["mcpServers"]["multillm-knowledge"]
    assert codex["url"] == claude["url"] == "https://gateway.example/mcp"
    assert codex["bearer_token_env_var"] == "MULTILLM_KNOWLEDGE_API_KEY"
    assert claude["headers"]["Authorization"] == "Bearer ${MULTILLM_KNOWLEDGE_API_KEY}"


def test_public_allowlist_does_not_open_private_routes(client):
    assert client.get("/knowledge").status_code == 302
    for path in ("/v1/knowledge/status", "/v1/knowledge/artifacts/source-1", "/admin/knowledge/status", "/mcp"):
        assert client.get(path, headers={"Accept": "application/json"}).status_code == 401
    assert client.get("/agent-onboarding/private.json").status_code != 200
    assert client.get("/agent-onboarding/../../.env").status_code != 200
