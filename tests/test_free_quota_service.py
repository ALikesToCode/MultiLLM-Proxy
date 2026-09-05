import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from services.free_quota_service import FreeQuotaService, reset_seconds, retry_seconds


class FreeQuotaTest(unittest.TestCase):
    def test_retry_after_seconds_date_and_bad_values(self):
        for value, expected in [
            ("2", 2),
            ("0.25", 1),
            ("nan", 60),
            ("inf", 60),
            ("bad", 60),
            ("-1", 60),
            ("999999999", 604800),
            ("Thu, 01 Jan 1970 00:02:00 GMT", 20),
        ]:
            with self.subTest(value=value):
                self.assertEqual(retry_seconds({"Retry-After": value}, 100), expected)

    def test_exhausted_dimensions_use_longest_reset(self):
        headers = {
            "Retry-After": "2",
            "x-ratelimit-remaining-requests": "0",
            "x-ratelimit-reset-requests": "1h2m3.4s",
            "x-ratelimit-remaining-tokens": "0",
            "x-ratelimit-reset-tokens": "7.66s",
        }
        self.assertEqual(retry_seconds(headers, 100), 3724)
        self.assertEqual(reset_seconds("2m59.56s"), 179.56)
        self.assertIsNone(reset_seconds(""))
        self.assertIsNone(reset_seconds("bad"))

    def test_storage_shared_between_instances_and_never_shortens_cooldown(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(
                os.environ,
                {
                    "MODEL_REGISTRY_DB_PATH": str(Path(directory) / "quota.sqlite3"),
                    "CONTROL_PLANE_DATABASE_URL": "",
                },
            ),
        ):
            FreeQuotaService.block("provider:groq", 120, now=100)
            FreeQuotaService.block("provider:groq", 5, now=110)
            self.assertEqual(
                FreeQuotaService().remaining("provider:groq", now=110), 110
            )
            self.assertEqual(FreeQuotaService.remaining("provider:groq", now=221), 0)
            self.assertEqual(
                FreeQuotaService.remaining("provider:openrouter", now=110), 0
            )
