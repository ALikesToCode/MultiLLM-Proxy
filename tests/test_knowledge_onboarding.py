"""Public setup must stay discoverable without opening account or management data."""

import json
import shlex
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
    assert len(config["tools"]) == 30
    assert len({tool["name"] for tool in config["tools"]}) == 30
    assert {"knowledge_exa_search", "knowledge_firecrawl_crawl", "knowledge_context7_docs",
            "knowledge_deepwiki_ask", "knowledge_mintlify_context"} <= {tool["name"] for tool in config["tools"]}
    assert sum(tool["scope"] == "knowledge:manage" for tool in config["tools"]) == 6
    assert len(config["providers"]) == 7
    skill = client.get("/agent-onboarding/SKILL.md?download=1", base_url="https://gateway.example")
    assert skill.data.startswith(b"---\nname: multillm-knowledge\n")
    assert 'attachment; filename="SKILL.md"' == skill.headers["Content-Disposition"]
    assert skill.data == client.get("/llms-full.txt", base_url="https://gateway.example").data
    assert client.get("/llm.txt").data == client.get("/llms.txt").data


def test_media_skill_and_llms_txt_teach_agents_to_generate_images_and_video(client):
    skill = client.get("/agent-onboarding/media/SKILL.md?download=1", base_url="https://gateway.example")
    assert skill.status_code == 200 and skill.content_type.startswith("text/markdown")
    text = skill.get_data(as_text=True)
    assert text.startswith("---\nname: multillm-media\n")
    assert "`MULTILLM_BASE_URL=https://gateway.example`" in text
    for endpoint in ("/v1/images/generations", "/v1/images/batch", "/v1/videos", "/v1/media/providers", "auto:image", "auto:video"):
        assert endpoint in text, endpoint
    assert 'attachment; filename="SKILL.md"' == skill.headers["Content-Disposition"]
    llms = client.get("/llms.txt", base_url="https://gateway.example").get_data(as_text=True)
    assert "https://gateway.example/agent-onboarding/media/SKILL.md" in llms
    assert "POST https://gateway.example/v1/videos" in llms and "GET /v1/videos/{id}" in llms


def test_chat_skill_and_llms_txt_teach_agents_to_call_chat_models_from_code(client):
    skill = client.get("/agent-onboarding/chat/SKILL.md?download=1", base_url="https://gateway.example")
    assert skill.status_code == 200 and skill.content_type.startswith("text/markdown")
    text = skill.get_data(as_text=True)
    assert text.startswith("---\nname: multillm-chat\n")
    assert "`MULTILLM_BASE_URL=https://gateway.example`" in text
    for fact in ("/v1/models", "/v1/chat/completions", "/v1/responses", "auto:glm-5.2", "free:text", "max_retries=0"):
        assert fact in text, fact
    assert 'attachment; filename="SKILL.md"' == skill.headers["Content-Disposition"]
    llms = client.get("/llms.txt", base_url="https://gateway.example").get_data(as_text=True)
    assert llms.startswith("# MultiLLM Proxy")
    for link in ("https://gateway.example/agent-onboarding/chat/SKILL.md", "https://gateway.example/agent-onboarding/SKILL.md",
                 "OpenAI SDK base URL `https://gateway.example/v1`", "POST https://gateway.example/v1/chat/completions"):
        assert link in llms, link


def test_mcp_skill_and_config_teach_agents_to_connect_the_gateway_mcp(client):
    with patch("routes.knowledge.dispatch") as dispatch:
        skill = client.get("/agent-onboarding/mcp/SKILL.md?download=1", base_url="https://gateway.example")
        config = client.get("/agent-onboarding/mcp/config.json", base_url="https://gateway.example").json
        llms = client.get("/llms.txt", base_url="https://gateway.example").get_data(as_text=True)
    dispatch.assert_not_called()
    assert skill.status_code == 200 and skill.content_type.startswith("text/markdown")
    assert 'attachment; filename="SKILL.md"' == skill.headers["Content-Disposition"]
    text = skill.get_data(as_text=True)
    assert text.startswith("---\nname: multillm-mcp\n")
    assert "<gateway-origin>" not in text
    for fact in ('url = "https://gateway.example/v1/mcp"', "claude mcp add --transport http",
                 "'Authorization: Bearer ${MULTILLM_API_KEY}'", 'bearer_token_env_var = "MULTILLM_API_KEY"',
                 "Bearer ${env:MULTILLM_API_KEY}", "list_models", "create_video", "never retries"):
        assert fact in text, fact
    assert config["url"] == "https://gateway.example/v1/mcp"
    assert config["authentication"] == {"type": "bearer", "env": "MULTILLM_API_KEY"}
    assert config["protocol_versions"] == ["2025-06-18"]
    scopes = {tool["name"]: tool["scope"] for tool in config["tools"]}
    assert scopes == {"list_models": "models", "chat": "chat", "generate_image": "chat", "generate_images_batch": "chat",
                      "create_video": "chat", "get_video": "chat", "media_providers": "chat"}
    for fact in ("https://gateway.example/v1/mcp", "https://gateway.example/agent-onboarding/mcp/SKILL.md",
                 "https://gateway.example/agent-onboarding/mcp/config.json", "accept function `tools`"):
        assert fact in llms, fact


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


def test_one_line_client_commands_keep_the_credential_as_a_reference(client):
    html = client.get("/agent-onboarding", base_url="https://gateway.example").get_data(as_text=True)
    def command(identifier):
        return shlex.split(unescape(html.split(f'<pre id="{identifier}">', 1)[1].split("</pre>", 1)[0]))
    assert command("codex-mcp-command") == [
        "codex", "mcp", "add", "multillm-knowledge", "--url", "https://gateway.example/mcp",
        "--bearer-token-env-var", "MULTILLM_KNOWLEDGE_API_KEY",
    ]
    claude = command("claude-mcp-command")
    assert claude[:4] == ["claude", "mcp", "add-json", "multillm-knowledge"]
    assert claude[5:] == ["--scope", "project"]
    server = json.loads(claude[4])
    assert server == {"type": "http", "url": "https://gateway.example/mcp",
                      "headers": {"Authorization": "Bearer ${MULTILLM_KNOWLEDGE_API_KEY}"}}


def test_setup_page_links_every_machine_readable_resource(client):
    html = client.get("/agent-onboarding", base_url="https://gateway.example").get_data(as_text=True)
    for path in ("/llms.txt", "/llm.txt", "/llms-full.txt", "/agent-onboarding/SKILL.md",
                 "/agent-onboarding/prompt.txt", "/agent-onboarding/config.json"):
        assert f'href="https://gateway.example{path}"' in html
        assert client.get(path, base_url="https://gateway.example").status_code == 200
