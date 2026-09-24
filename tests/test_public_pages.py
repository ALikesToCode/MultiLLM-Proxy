"""The public product overview explains the gateway without exposing deployment state."""

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
    app.config.update(SECRET_KEY="synthetic-public-session", API_BASE_URLS={}, TESTING=True)
    init_error_handlers(app)
    csrf = CSRFProtect(app)
    register_core_routes(app)
    register_knowledge_routes(app, csrf)
    with patch("routes.core.AuthService.is_authenticated", return_value=False):
        yield app.test_client()


def test_overview_is_public_and_links_setup_paths(client):
    response = client.get("/about", base_url="https://gateway.example")
    assert response.status_code == 200
    assert response.content_type.startswith("text/html")
    assert response.headers["Cache-Control"] == "no-store"
    html = response.get_data(as_text=True)
    for link in ('href="/agent-onboarding"', 'href="/llms.txt"', 'href="/login"'):
        assert link in html
    for topic in ("auto:", "provider:model", "Alexandria", "https://gateway.example/mcp"):
        assert topic in html


def test_overview_lists_integrations_without_configuration_state(client):
    with patch("services.auth_service.AuthService.get_api_key", return_value="synthetic-secret-value"):
        html = client.get("/about").get_data(as_text=True)
    assert "OpenRouter" in html and "NanoGPT" in html
    assert "synthetic-secret-value" not in html
    for private_state in ("Key missing", "not configured", "no credential", 'class="status-pill'):
        assert private_state not in html


def test_dashboard_root_stays_login_protected(client):
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["Location"].startswith("/login")
    assert 'href="/about"' in client.get("/login").get_data(as_text=True)
