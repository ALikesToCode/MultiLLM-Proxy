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
            "static/css/operations.css",
            "static/css/surfaces.css",
        ):
            self.assertTrue((self.repo_root / relative_path).is_file(), relative_path)

    def test_changed_handwritten_ui_files_stay_below_source_limit(self):
        relative_paths = (
            "static/css/shell.css",
            "static/css/operations.css",
            "static/css/surfaces.css",
            "static/js/auto-routes.js",
            "static/js/dashboard.js",
            "static/js/openrouter.js",
            "static/js/users.js",
            "templates/base.html",
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

        self.assertIn("multillm-proxy-v5", worker)
        for asset in (
            "/static/css/shell.css",
            "/static/css/auto-routes.css",
            "/static/css/operations.css",
            "/static/css/surfaces.css",
            "/static/js/auto-routes.js",
            "/static/js/dashboard.js",
            "/static/js/openrouter.js",
            "/static/js/users.js",
        ):
            self.assertIn(asset, worker)
        self.assertNotIn("/static/css/openrouter.css", worker)

    def test_provider_matrix_distinguishes_passthrough_from_managed_circuits(self):
        dashboard = self.read("static/js/dashboard.js")

        self.assertIn("circuit.mode === 'bypassed'", dashboard)
        self.assertIn("'passthrough'", dashboard)

    def test_auto_route_editor_uses_authenticated_external_script(self):
        operations = self.read("templates/operations.html")
        editor = self.read("static/js/auto-routes.js")

        self.assertIn('id="auto-route-panel"', operations)
        self.assertIn('data-auto-routes="{{ url_for(\'admin_auto_routes\') }}"', operations)
        self.assertIn("js/auto-routes.js", operations)
        self.assertIn("X-CSRFToken", editor)
        self.assertNotIn("innerHTML", editor)


if __name__ == "__main__":
    unittest.main()
