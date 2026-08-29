import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from error_handlers import APIError
from services.auth_service import AuthService
from services.proxy_service import ProxyService


class GoogleCliSecurityTest(unittest.TestCase):
    def setUp(self):
        AuthService._google_token = None
        AuthService._google_token_expiry = None
        ProxyService._google_token = None
        ProxyService._google_token_expiry = None

    def test_auth_service_executes_resolved_gcloud_binary(self):
        completed = SimpleNamespace(stdout="access-token\n")

        with (
            patch.object(
                AuthService,
                "_build_google_service_account_credentials",
                return_value=None,
            ),
            patch("services.auth_service.shutil.which", return_value="/trusted/gcloud"),
            patch("services.auth_service.subprocess.run", return_value=completed) as run,
        ):
            self.assertEqual(AuthService.get_google_token(), "access-token")

        self.assertEqual(run.call_args.args[0][0], "/trusted/gcloud")
        self.assertEqual(run.call_args.kwargs["timeout"], 30)

    def test_proxy_service_uses_resolved_binary_and_local_environment(self):
        completed = SimpleNamespace(stdout="access-token\n")

        with tempfile.TemporaryDirectory() as tempdir:
            credentials_path = Path(tempdir) / "credentials.json"
            credentials_path.write_text("{}", encoding="utf-8")
            with (
                patch.dict(
                    os.environ,
                    {"GOOGLE_APPLICATION_CREDENTIALS": str(credentials_path)},
                    clear=False,
                ),
                patch("shutil.which", return_value="/trusted/gcloud"),
                patch("subprocess.run", return_value=completed) as run,
            ):
                self.assertEqual(ProxyService.get_google_access_token(), "access-token")

        self.assertEqual(run.call_args.args[0][0], "/trusted/gcloud")
        self.assertEqual(run.call_args.kwargs["timeout"], 30)
        self.assertEqual(
            run.call_args.kwargs["env"]["GOOGLE_APPLICATION_CREDENTIALS"],
            str(credentials_path),
        )

    def test_proxy_service_does_not_disclose_missing_credentials_path(self):
        credentials_path = "/private/tenant/credential-secret.json"

        with (
            patch.dict(
                os.environ,
                {"GOOGLE_APPLICATION_CREDENTIALS": credentials_path},
                clear=False,
            ),
            patch("services.proxy_service.os.path.exists", return_value=False),
            self.assertLogs("services.proxy_service", level="ERROR") as captured,
            self.assertRaisesRegex(
                APIError,
                "Unable to obtain a Google Cloud token",
            ) as raised,
        ):
            ProxyService.get_google_access_token()

        self.assertNotIn(credentials_path, str(raised.exception))
        self.assertNotIn(credentials_path, "\n".join(captured.output))


if __name__ == "__main__":
    unittest.main()
