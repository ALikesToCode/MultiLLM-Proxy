import json
import os
from unittest.mock import patch

import requests

from services.intelligence_store import IntelligenceStore
from tests.test_intelligence_policy import candidate, policy
from tests.unified_api_test_case import UnifiedApiTestCase


def upstream(body=None, status=200, headers=None, chunks=None):
    response = requests.Response()
    response.status_code = status
    response.headers.update(headers or {"Content-Type": "application/json"})
    if chunks is None:
        response._content = (
            body if isinstance(body, bytes) else json.dumps(body or {}).encode()
        )
        response._content_consumed = True
    else:
        response.iter_content = lambda **kwargs: iter(chunks)
    response.close = lambda: None
    return response


def completion(content="ok", *, usage=True, calls=None):
    message = {
        "role": "assistant",
        "content": content,
        "reasoning_content": "private thoughts",
    }
    if calls:
        message["tool_calls"] = calls
    result = {
        "choices": [
            {
                "index": 0,
                "message": message,
                "finish_reason": "tool_calls" if calls else "stop",
            }
        ]
    }
    if usage:
        result["usage"] = {
            "prompt_tokens": 4,
            "completion_tokens": 2,
            "total_tokens": 6,
        }
    return result


def frames(*values):
    return [
        b"data: "
        + (value.encode() if isinstance(value, str) else json.dumps(value).encode())
        + b"\n\n"
        for value in values
    ]


class IntelligenceApiTestCase(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        os.environ["CONTROL_PLANE_DATABASE_URL"] = ""
        os.environ["INTELLIGENCE_REQUIRE_DURABLE_STORAGE"] = "false"
        os.environ.pop("INTELLIGENCE_POLICY_JSON", None)
        self.headers = {
            "Authorization": "Bearer admin-test-key",
            "X-Request-ID": "omni-request-1",
        }
        self.keys = patch.object(
            self.app_module.AuthService,
            "get_api_key",
            return_value="synthetic-provider-key",
        )
        self.keys.start()
        self.addCleanup(self.keys.stop)
        self.pool = patch.object(
            self.app_module.AuthService,
            "get_api_keys",
            return_value=["synthetic-provider-key"],
        )
        self.pool.start()
        self.addCleanup(self.pool.stop)

    def seed(self, **kwargs):
        IntelligenceStore.seed(
            policy(
                candidates=[
                    candidate("openai:small"),
                    candidate("navyai:large", quality_tier=2),
                ],
                **kwargs,
            )
        )

    def post(self, **kwargs):
        return self.client.post(
            "/v1/chat/completions",
            headers=self.headers,
            json={
                "model": "auto:intelligence",
                "messages": [{"role": "user", "content": "test"}],
                **kwargs,
            },
        )

    def requests(self, **kwargs):
        return patch.object(self.app_module.ProxyService, "make_request", **kwargs)
