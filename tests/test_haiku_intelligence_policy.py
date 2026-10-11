from types import SimpleNamespace

import pytest

from services import intelligence_policy as policy_service
from services import latency_slo
from services.intelligence_anthropic import HAIKU_INTELLIGENCE_MODEL
from services.intelligence_contract import ChatRequest
from tests.test_intelligence_policy import candidate, policy


@pytest.fixture
def selection():
    fallback = candidate("openai:fallback", quality_tier=5, task_scores={"coding": 99})
    haiku = candidate(HAIKU_INTELLIGENCE_MODEL, billing="payg")
    configured = policy(allow_paid_overage=True, candidates=[fallback, haiku])
    request = ChatRequest.parse(
        {
            "model": "auto:intelligence",
            "messages": [{"role": "user", "content": "synthetic"}],
            "max_tokens": 100,
            "routing": {"profile": "quality", "task": "coding", "allow_paid_overage": True},
        },
        configured,
    )
    config = {"API_BASE_URLS": {"anthropic": "https://api.anthropic.com", "openai": "https://api.openai.com/v1"}}
    return configured, request, config, fallback, haiku


def test_latency_admission_evaluates_haiku_and_preserves_its_reroute(monkeypatch, selection):
    configured, request, config, fallback, haiku = selection
    observed = []

    def latency_filter(choices, **kwargs):
        observed.append(choices)
        assert kwargs["auto"] is True
        return [fallback]

    monkeypatch.setattr(latency_slo, "selection_candidates", latency_filter)
    result = policy_service.select_candidates(
        configured, request, config, model_status=lambda _: "enabled"
    )
    assert observed == [[haiku, fallback]]
    assert result == [fallback]


def test_approved_session_lane_can_exclude_haiku(monkeypatch, selection):
    configured, request, config, fallback, _ = selection
    lane = SimpleNamespace(select=lambda choices: [item for item in choices if item == fallback])
    observed = []

    def latency_filter(choices, **kwargs):
        observed.append(choices)
        assert kwargs["lane_selected"] is True
        return choices

    monkeypatch.setattr(latency_slo, "selection_candidates", latency_filter)
    assert policy_service.select_candidates(
        configured, request, config, session_tier=lane, model_status=lambda _: "enabled"
    ) == [fallback]
    assert observed == [[fallback]]


def test_lane_acquisition_still_sees_haiku_first_without_latency_admission(selection):
    configured, request, config, fallback, haiku = selection
    assert policy_service.select_candidates(
        configured, request, config, model_status=lambda _: "enabled", apply_latency=False
    ) == [haiku, fallback]
