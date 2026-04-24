import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class FakeOpenRouterResponse:
    def __init__(self, content=b'{"ok": true}', status_code=200, headers=None, chunks=None):
        self.content = content
        self.status_code = status_code
        self.headers = headers or {"Content-Type": "application/json"}
        self._chunks = chunks or [content]
        self.closed = False

    def iter_content(self, chunk_size=None):
        yield from self._chunks

    def close(self):
        self.closed = True


class OpenRouterDashboardSecurityTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.env_patch = patch.dict(
            os.environ,
            {
                "ADMIN_USERNAME": "admin",
                "ADMIN_API_KEY": "admin-test-key",
                "FLASK_SECRET_KEY": "flask-test-secret",
                "JWT_SECRET": "jwt-test-secret",
                "OPENROUTER_API_KEY": "openrouter-live-key",
                "AUTH_DB_PATH": os.path.join(self.tempdir.name, "auth.sqlite3"),
            },
            clear=False,
        )
        self.env_patch.start()

        for module_name in ("app", "services.auth_service", "routes.core"):
            sys.modules.pop(module_name, None)

        self.app_module = importlib.import_module("app")
        self.flask_app = self.app_module.create_app()
        self.flask_app.config["WTF_CSRF_ENABLED"] = False
        self.client = self.flask_app.test_client()
        with self.client.session_transaction() as session:
            session["authenticated"] = True
            session["user"] = {"username": "admin", "is_admin": True}

    def tearDown(self):
        self.env_patch.stop()
        self.tempdir.cleanup()

    def test_dashboard_chat_completions_uses_server_side_openrouter_key(self):
        fake_response = FakeOpenRouterResponse(content=b'{"choices":[]}')

        with patch("routes.core.requests.post", return_value=fake_response) as post:
            response = self.client.post(
                "/dashboard/openrouter/chat-completions",
                json={
                    "model": "openai/gpt-4o",
                    "messages": [{"role": "user", "content": "hello"}],
                    "stream": False,
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_data(), b'{"choices":[]}')
        post.assert_called_once()
        headers = post.call_args.kwargs["headers"]
        self.assertEqual(headers["Authorization"], "Bearer openrouter-live-key")

    def test_dashboard_chat_completions_requires_admin_session(self):
        with self.client.session_transaction() as session:
            session["user"] = {"username": "regular", "is_admin": False}

        response = self.client.post(
            "/dashboard/openrouter/chat-completions",
            json={
                "model": "openai/gpt-4o",
                "messages": [{"role": "user", "content": "hello"}],
            },
        )

        self.assertEqual(response.status_code, 403)

    def test_openrouter_static_js_does_not_embed_browser_keys_or_authorization(self):
        script = Path("static/js/openrouter.js").read_text(encoding="utf-8")

        self.assertNotIn("MjM0NTY3ODkwMTI", script)
        self.assertNotRegex(script, r"\bapiKey\s*=")
        self.assertNotIn("Authorization", script)
        self.assertNotIn("EventSource", script)
        self.assertNotIn("responseArea.innerHTML = formatResponse", script)

    def test_openrouter_model_output_is_rendered_as_text(self):
        script = Path("static/js/openrouter.js").read_text(encoding="utf-8")
        malicious_output = "<img src=x onerror=alert(1)>"
        set_plain_text = script[
            script.index("function setPlainText"):
            script.index("function setResponseText")
        ]
        set_response_text = script[
            script.index("function setResponseText"):
            script.index("function setLoading")
        ]

        self.assertIn("wrapper.textContent = text", set_plain_text)
        self.assertIn("setPlainText(responseArea, text, className);", set_response_text)
        self.assertNotIn(
            "innerHTML",
            set_plain_text + set_response_text,
            msg=f"malicious model output must not be rendered as HTML: {malicious_output}",
        )
        self.assertNotIn("formatResponse", script)

    def test_openrouter_template_does_not_render_provider_key(self):
        template = Path("templates/openrouter.html").read_text(encoding="utf-8")

        self.assertNotIn("{{ api_key", template)
        self.assertNotIn("openrouter.ai/api/v1/auth/key", template)
        self.assertNotIn("'Authorization':", template)
        self.assertNotIn('"Authorization":', template)


if __name__ == "__main__":
    unittest.main()
