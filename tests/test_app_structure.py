from pathlib import Path
import unittest


class AppStructureTest(unittest.TestCase):
    def test_app_factory_file_is_below_500_lines(self):
        app_py = Path(__file__).resolve().parents[1] / "app.py"
        with app_py.open("r", encoding="utf-8") as handle:
            line_count = sum(1 for _ in handle)
        self.assertLessEqual(
            line_count,
            500,
            f"app.py is still too large at {line_count} lines; expected <= 500 lines after route extraction",
        )

    def test_ci_uses_current_worker_test_path(self):
        workflow = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml"
        workflow_text = workflow.read_text(encoding="utf-8")

        self.assertIn("node --test tests/test_cloudflare_worker.mjs", workflow_text)
        self.assertNotIn("node --test test_cloudflare_worker.mjs", workflow_text)


if __name__ == "__main__":
    unittest.main()
