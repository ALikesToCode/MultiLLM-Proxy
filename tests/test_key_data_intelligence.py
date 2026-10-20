"""Key controls survive managed routing and its background transport handoff."""

import json
from unittest.mock import patch

from services.intelligence_store import IntelligenceStore
from tests.intelligence_fixtures import IntelligenceApiTestCase, completion, upstream
from tests.test_intelligence_policy import candidate, policy


class KeyDataIntelligenceTest(IntelligenceApiTestCase):
    def controlled_key(self, **controls):
        auth = self.app_module.AuthService
        with patch.object(auth, "get_current_user", return_value={"username": "admin", "is_admin": True}):
            created = auth.create_user("guarded", scopes=["chat", "models"])
            auth.set_key_controls("guarded", controls)
        self.headers["Authorization"] = f"Bearer {created['api_key']}"

    def test_intelligence_skips_nonofficial_and_refuses_an_empty_policy(self):
        self.controlled_key(official_only=True)
        IntelligenceStore.seed(policy(candidates=[candidate("navyai:small"), candidate("openai:large")]))
        with self.requests(return_value=upstream(completion())) as send:
            response = self.post()
        assert response.status_code == 200, response.json
        assert send.call_count == 1
        assert send.call_args.kwargs["api_provider"] == "openai"
        with patch("routes.intelligence.load_policy", return_value=policy(candidates=[candidate("navyai:small")])):
            with self.requests() as send:
                response = self.post()
        assert response.status_code == 403, response.json
        assert response.json["error"]["code"] == "provider_class_not_allowed"
        send.assert_not_called()

    def test_forced_preferences_are_captured_before_background_submission(self):
        self.controlled_key(forced_provider_preferences={"data_collection": "deny"})
        IntelligenceStore.seed(policy(candidates=[candidate("openrouter:example/model")]))
        with self.requests(return_value=upstream(completion())) as send:
            response = self.post()
        assert response.status_code == 200, response.json
        assert json.loads(send.call_args.kwargs["data"])["provider"] == {"data_collection": "deny"}
