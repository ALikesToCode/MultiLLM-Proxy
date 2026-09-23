import json

from services.intelligence_store import IntelligenceStore
from services.nanogpt_key_pool import NanoGPTUnifiedKeyPool
from tests.intelligence_fixtures import IntelligenceApiTestCase, completion, upstream
from tests.test_intelligence_policy import candidate, policy


class IntelligenceReasoningTests(IntelligenceApiTestCase):
    def setUp(self):
        super().setUp()
        NanoGPTUnifiedKeyPool.reset()
        self.addCleanup(NanoGPTUnifiedKeyPool.reset)

    def seed_glm(self, *models):
        IntelligenceStore.seed(
            policy(
                candidates=[
                    candidate(f"nanogpt:{model}", billing="subscription")
                    for model in models
                ]
            )
        )

    def test_omni_xhigh_uses_the_native_glm_maximum_on_each_fallback_attempt(self):
        self.seed_glm("z-ai/glm-5.3-flash", "z-ai/glm-5.3")
        with self.requests(
            side_effect=[upstream({}, 404), upstream(completion())]
        ) as send:
            response = self.post(reasoning_effort="xhigh")
        assert response.status_code == 200
        bodies = [json.loads(call.kwargs["data"]) for call in send.call_args_list]
        assert [body["model"] for body in bodies] == [
            "z-ai/glm-5.3-flash",
            "z-ai/glm-5.3",
        ]
        assert all(body["reasoning_effort"] == "max" for body in bodies)

    def test_explicit_native_efforts_are_preserved(self):
        self.seed_glm("z-ai/glm-5.3-flash")
        for effort in ("low", "high", "max"):
            with self.subTest(effort=effort), self.requests(
                return_value=upstream(completion())
            ) as send:
                response = self.post(reasoning_effort=effort)
                assert response.status_code == 200
                body = json.loads(send.call_args.kwargs["data"])
                assert body["reasoning_effort"] == effort
                assert "thinking" not in body

    def test_omitted_effort_retains_nanogpt_native_thinking_default(self):
        self.seed_glm("z-ai/glm-5.3-flash")
        with self.requests(return_value=upstream(completion())) as send:
            response = self.post()
        assert response.status_code == 200
        body = json.loads(send.call_args.kwargs["data"])
        assert not {"reasoning_effort", "reasoning", "thinking"} & body.keys()

    def test_provider_specific_reasoning_fields_remain_outside_the_contract(self):
        self.seed_glm("z-ai/glm-5.3")
        for fields in (
            {"reasoning": {"effort": "xhigh"}},
            {"thinking": {"type": "enabled"}},
        ):
            with self.subTest(fields=fields), self.requests() as send:
                response = self.post(**fields)
                assert response.status_code == 400
                send.assert_not_called()

    def test_non_glm_explicit_reasoning_is_unchanged(self):
        self.seed()
        with self.requests(return_value=upstream(completion())) as send:
            response = self.post(reasoning_effort="xhigh")
        assert response.status_code == 200
        body = json.loads(send.call_args.kwargs["data"])
        assert body["model"] == "small"
        assert body["reasoning_effort"] == "xhigh"
