from tests.unified_api_test_case import UnifiedApiTestCase


class UnifiedRequestValidationTest(UnifiedApiTestCase):
    def test_json_api_routes_reject_array_bodies(self):
        for path in (
            "/v1/chat/completions",
            "/v1/images/generations",
            "/v1/responses",
        ):
            with self.subTest(path=path):
                response = self.client.post(
                    path,
                    headers={"Authorization": "Bearer admin-test-key"},
                    json=[],
                )

                self.assertEqual(response.status_code, 400)
                self.assertEqual(
                    response.get_json()["message"],
                    "Request body must be a JSON object",
                )

    def test_unified_chat_rejects_invalid_json(self):
        response = self.client.post(
            "/v1/chat/completions",
            headers={
                "Authorization": "Bearer admin-test-key",
                "Content-Type": "application/json",
            },
            data=b"{invalid",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json()["message"],
            "Request body must be a JSON object",
        )
