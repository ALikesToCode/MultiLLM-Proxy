from pathlib import Path
import unittest


class AppStructureTest(unittest.TestCase):
    def test_app_factory_file_is_below_500_lines(self):
        app_py = Path(__file__).resolve().parent / "app.py"
        with app_py.open("r", encoding="utf-8") as handle:
            line_count = sum(1 for _ in handle)
        self.assertLessEqual(
            line_count,
            500,
            f"app.py is still too large at {line_count} lines; expected <= 500 lines after route extraction",
        )


if __name__ == "__main__":
    unittest.main()
