import os
from pathlib import Path
import unittest

from scripts.check_static_secrets import main as check_static_secrets


class StaticSecretScannerTest(unittest.TestCase):
    def setUp(self):
        self.original_cwd = Path.cwd()
        self.repo_root = Path(__file__).resolve().parents[1]
        os.chdir(self.repo_root)

    def tearDown(self):
        os.chdir(self.original_cwd)

    def test_static_assets_do_not_contain_secret_like_values(self):
        self.assertEqual(check_static_secrets(), 0)


if __name__ == "__main__":
    unittest.main()
