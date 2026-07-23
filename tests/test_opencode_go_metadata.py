import unittest
from pathlib import Path

from proxy import PROVIDER_DETAILS
from services.model_registry import DEFAULT_MODEL_IDS


class OpenCodeGoMetadataTest(unittest.TestCase):
    repo_root = Path(__file__).resolve().parents[1]

    def test_provider_metadata_exposes_both_protocols_and_catalog(self):
        details = PROVIDER_DETAILS["opencode"]
        endpoint_urls = {endpoint["url"] for endpoint in details["endpoints"]}

        self.assertIn("OpenCode Go", details["description"])
        self.assertTrue(details["supported_features"]["streaming"])
        self.assertTrue(details["supported_features"]["function_calling"])
        self.assertTrue(details["supported_features"]["anthropic_messages"])
        self.assertTrue(details["supported_features"]["model_discovery"])
        self.assertEqual(details["default_model"], "kimi-k3")
        self.assertTrue(
            {
                "/v1/chat/completions",
                "/v1/messages",
                "/v1/models",
                "/chat/completions",
            }.issubset(endpoint_urls)
        )

    def test_current_go_models_are_available_to_unified_routes(self):
        model_ids = set(DEFAULT_MODEL_IDS["opencode"])

        for model_id in (
            "grok-4.5",
            "glm-5.2",
            "kimi-k3",
            "kimi-k2.7-code",
            "mimo-v2.5",
            "minimax-m3",
            "qwen3.7-max",
            "deepseek-v4-pro",
            "deepseek-v4-flash",
            "hy3",
        ):
            with self.subTest(model_id=model_id):
                self.assertIn(model_id, model_ids)

    def test_docs_configuration_and_dashboard_cover_native_routes(self):
        docs = (self.repo_root / "docs/opencode-go.md").read_text(encoding="utf-8")
        env_example = (self.repo_root / ".env.example").read_text(encoding="utf-8")
        dashboard_sources = "\n".join(
            (
                (self.repo_root / "static/js/api-endpoints.js").read_text(
                    encoding="utf-8"
                ),
                (self.repo_root / "static/js/endpoints.js").read_text(
                    encoding="utf-8"
                ),
            )
        )

        for value in (
            "OPENCODE_GO_API_KEY",
            "OPENCODE_API_KEY",
            "OPENCODE_GO_BASE_URL",
            "/opencode/v1/chat/completions",
            "/opencode/v1/messages",
            "/opencode/v1/models",
            "opencode-go/<model-id>",
            "opencode:kimi-k3",
            "X-MultiLLM-Api-Key",
        ):
            with self.subTest(value=value):
                self.assertIn(value, f"{docs}\n{env_example}\n{dashboard_sources}")

    def test_navyai_metadata_and_docs_cover_new_client_index(self):
        details = PROVIDER_DETAILS["navyai"]
        endpoint_urls = {endpoint["url"] for endpoint in details["endpoints"]}
        docs = (self.repo_root / "docs/navyai.md").read_text(encoding="utf-8")

        for endpoint in (
            "/v1/models/status",
            "/v1/audio/transcriptions/jobs/{id}/status",
            "/v1/audio/transcriptions/jobs/{id}/download",
            "/v1/oauth/token",
            "/v1/oauth/me",
            "/v1/oauth/revoke",
        ):
            with self.subTest(endpoint=endpoint):
                self.assertIn(endpoint, endpoint_urls)

        for client in (
            "Codex CLI",
            "Claude Code",
            "Roo Code",
            "SillyTavern",
            "Janitor AI",
            "RisuAI",
            "Agnai",
        ):
            with self.subTest(client=client):
                self.assertIn(client, docs)


if __name__ == "__main__":
    unittest.main()
