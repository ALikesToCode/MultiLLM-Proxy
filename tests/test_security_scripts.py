import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


class SecurityScriptTest(unittest.TestCase):
    def test_gemini_key_setup_rewrites_env_without_exposing_or_mangling_key(self):
        key = "AIza" + "a-b_C" * 6
        with tempfile.TemporaryDirectory() as tempdir:
            env_path = Path(tempdir) / ".env"
            env_path.write_text(
                "OTHER=value\nGEMINI_API_KEY=old\nGEMMA_API_KEY=old-too\n",
                encoding="utf-8",
            )

            result = subprocess.run(
                ["bash", str(REPOSITORY_ROOT / "get_gemini_key.sh")],
                cwd=tempdir,
                input=f"y\n{key}\n",
                capture_output=True,
                check=False,
                text=True,
                timeout=10,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                env_path.read_text(encoding="utf-8"),
                f"OTHER=value\nGEMINI_API_KEY={key}\nGEMMA_API_KEY={key}\n",
            )
            self.assertEqual(stat.S_IMODE(env_path.stat().st_mode), 0o600)
            self.assertNotIn(key, result.stdout)
            self.assertNotIn(key, result.stderr)

    def test_cloudflare_entrypoint_uses_private_random_credential_directory(self):
        source = (REPOSITORY_ROOT / "scripts" / "cloudflare-entrypoint.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("umask 077", source)
        self.assertIn("mktemp -d /tmp/multillm-runtime.XXXXXX", source)
        self.assertNotIn("/tmp/google-credentials.json", source)
        self.assertNotIn("export HOME=/tmp", source)

    def test_deployment_shell_scripts_have_valid_syntax(self):
        for shell, script in (
            ("bash", "get_gemini_key.sh"),
            ("sh", "scripts/cloudflare-entrypoint.sh"),
            ("bash", "vercel-build.sh"),
        ):
            result = subprocess.run(
                [shell, "-n", str(REPOSITORY_ROOT / script)],
                capture_output=True,
                check=False,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_vercel_build_installs_the_locked_dependency_set(self):
        source = (REPOSITORY_ROOT / "vercel-build.sh").read_text(encoding="utf-8")

        self.assertIn("pip install -r requirements.lock", source)
        self.assertNotIn("pip install -r requirements.txt", source)


if __name__ == "__main__":
    unittest.main()
