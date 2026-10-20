import json
import re
import shlex
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
        repository = Path(__file__).resolve().parents[1]
        workflow = repository / ".github" / "workflows" / "ci.yml"
        workflow_text = workflow.read_text(encoding="utf-8")
        package = json.loads((repository / "package.json").read_text(encoding="utf-8"))
        worker_test = package["scripts"]["test:worker"]

        self.assertIn("npm run test:worker", workflow_text)
        self.assertIn("node --import ./tests/helpers/network_guard.mjs --test tests/test_cloudflare_worker.mjs", worker_test)
        self.assertIn("tests/test_roleplay_worker.mjs", worker_test)
        self.assertIn("tests/test_roleplay_memory_worker.mjs", worker_test)
        self.assertNotIn("node --test test_cloudflare_worker.mjs", workflow_text)

        # Standalone Node CI steps must also run in the ordinary Worker suite.
        node_job = workflow_text.split("\n  node:\n", 1)[1].split("\n  integration:\n", 1)[0]
        worker_patterns = shlex.split(worker_test)[shlex.split(worker_test).index("--test") + 1:]
        covered = {str(path.relative_to(repository)) for pattern in worker_patterns for path in repository.glob(pattern)}
        for command in re.findall(r"^\s+run: (.+)$", node_job, re.MULTILINE):
            if command.startswith("npm run "):
                command = package["scripts"][command.removeprefix("npm run ")]
            tokens = shlex.split(command)
            if tokens[0] != "node" or "--test" not in tokens:
                continue
            for pattern in tokens[tokens.index("--test") + 1:]:
                files = list(repository.glob(pattern))
                self.assertTrue(files, f"CI test pattern matches no files: {pattern}")
                for path in files:
                    self.assertIn(str(path.relative_to(repository)), covered,
                                  f"Node CI test is missing from test:worker: {path.name}")


if __name__ == "__main__":
    unittest.main()
