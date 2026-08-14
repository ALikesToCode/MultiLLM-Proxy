import unittest
from pathlib import Path


class ControlPlaneUiTest(unittest.TestCase):
    repo_root = Path(__file__).resolve().parents[1]

    def read(self, relative_path: str) -> str:
        return (self.repo_root / relative_path).read_text(encoding="utf-8")

    def test_base_shell_uses_local_assets_without_runtime_cdns(self):
        base = self.read("templates/base.html")

        self.assertIn("css/style.css", base)
        self.assertIn("css/shell.css", base)
        self.assertNotIn("cdn.tailwindcss.com", base)
        self.assertNotIn("cdnjs.cloudflare.com", base)
        self.assertNotIn("unpkg.com", base)
        self.assertIn('class="skip-link"', base)

    def test_interactive_surfaces_keep_scripts_external_and_plain_text(self):
        users = self.read("templates/users.html")
        openrouter = self.read("templates/openrouter.html")
        openrouter_script = self.read("static/js/openrouter.js")

        self.assertNotIn("onclick=", users)
        self.assertNotIn("<script>", users)
        self.assertNotIn("onclick=", openrouter)
        self.assertNotIn("<script>", openrouter)
        self.assertIn("wrapper.textContent = text", openrouter_script)
        self.assertNotIn("innerHTML", openrouter_script)

    def test_design_artifacts_and_page_styles_are_present(self):
        for relative_path in (
            "docs/design.md",
            "docs/design-preview.html",
            "static/design-tokens.json",
            "static/css/shell.css",
            "static/css/auto-routes.css",
            "static/css/documentation.css",
            "static/css/operations.css",
            "static/css/surfaces.css",
        ):
            self.assertTrue((self.repo_root / relative_path).is_file(), relative_path)

    def test_changed_handwritten_ui_files_stay_below_source_limit(self):
        relative_paths = (
            "static/css/shell.css",
            "static/css/operations.css",
            "static/css/surfaces.css",
            "static/js/auto-route-catalog.js",
            "static/js/auto-routes.js",
            "static/js/dashboard.js",
            "static/js/documentation.js",
            "static/js/openrouter.js",
            "static/js/users.js",
            "templates/base.html",
            "templates/documentation.html",
            "templates/login.html",
            "templates/openrouter.html",
            "templates/operations.html",
            "templates/users.html",
        )
        for relative_path in relative_paths:
            line_count = len(self.read(relative_path).splitlines())
            self.assertLess(
                line_count,
                1_000,
                f"{relative_path} is too large at {line_count} lines",
            )

    def test_service_worker_precaches_current_control_plane_assets(self):
        worker = self.read("static/service-worker.js")

        self.assertIn("multillm-proxy-v9", worker)
        for asset in (
            "/static/css/shell.css",
            "/static/css/auto-routes.css?v=7",
            "/static/css/documentation.css?v=8",
            "/static/css/operations.css",
            "/static/css/surfaces.css",
            "/static/js/auto-route-catalog.js?v=8",
            "/static/js/auto-routes.js?v=7",
            "/static/js/dashboard.js",
            "/static/js/documentation.js?v=9",
            "/static/js/openrouter.js",
            "/static/js/users.js",
        ):
            self.assertIn(asset, worker)
        self.assertNotIn("/static/css/openrouter.css", worker)

    def test_live_documentation_is_linked_and_uses_safe_external_rendering(self):
        base = self.read("templates/base.html")
        documentation = self.read("templates/documentation.html")
        script = self.read("static/js/documentation.js")

        self.assertIn("url_for('proxy_documentation')", base)
        self.assertIn('id="proxy-documentation-state"', documentation)
        self.assertIn("/v1/chat/completions", documentation)
        self.assertIn("/v1/images/generations", documentation)
        self.assertIn("provider:image-model", documentation)
        self.assertIn("NANOGPT_PREFERRED_KEY_INDEX=1", documentation)
        self.assertIn("wrangler secret put NANOGPT_API_KEY_1", documentation)
        self.assertIn("js/documentation.js", documentation)
        self.assertNotIn("onclick=", documentation)
        self.assertNotIn("innerHTML", script)
        self.assertIn("replaceChildren", script)
        self.assertIn("context_window", script)
        self.assertIn("max_output_tokens", script)

    def test_provider_matrix_distinguishes_passthrough_from_managed_circuits(self):
        dashboard = self.read("static/js/dashboard.js")

        self.assertIn("circuit.mode === 'bypassed'", dashboard)
        self.assertIn("'passthrough'", dashboard)

    def test_auto_route_editor_uses_authenticated_external_script(self):
        operations = self.read("templates/operations.html")
        editor = self.read("static/js/auto-routes.js")
        catalog = self.read("static/js/auto-route-catalog.js")

        self.assertIn('id="auto-route-panel"', operations)
        self.assertIn(
            "data-auto-routes=\"{{ url_for('admin_auto_routes') }}\"", operations
        )
        self.assertIn(
            "data-model-catalog=\"{{ url_for('admin_auto_route_catalog') }}\"",
            operations,
        )
        self.assertIn('id="auto-route-setup-title"', operations)
        self.assertIn('id="auto-route-model-catalog"', operations)
        self.assertIn("NANOGPT_API_KEY_1=your-second-key", operations)
        self.assertIn("NANOGPT_PREFERRED_KEY_INDEX=1", operations)
        self.assertIn("js/auto-route-catalog.js", operations)
        self.assertIn("js/auto-routes.js", operations)
        self.assertIn("filename='js/auto-route-catalog.js', v='8'", operations)
        self.assertIn("filename='js/auto-routes.js', v='7'", operations)
        self.assertIn("X-CSRFToken", editor)
        self.assertIn("refreshCatalog", editor)
        self.assertIn("window.MultiLLMAutoRoutes?.createAutoRouteCatalog", editor)
        self.assertIn("createAutoRouteCatalog", catalog)
        self.assertIn("onAddModel", catalog)
        self.assertIn("context_window", catalog)
        self.assertIn("max_output_tokens", catalog)
        self.assertIn(
            "window.MultiLLMAutoRoutes = Object.freeze({ createAutoRouteCatalog })",
            catalog,
        )
        self.assertNotIn("window.MultiLLM.createAutoRouteCatalog", catalog)
        self.assertNotIn("innerHTML", editor)
        self.assertNotIn("innerHTML", catalog)


if __name__ == "__main__":
    unittest.main()
