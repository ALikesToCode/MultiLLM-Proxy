import pytest
from flask import Flask

from services.judge_routing import excluding_gemini, judge_candidate_allowed


def test_routed_aliases_exclude_gemini_and_restore_on_exit():
    app = Flask(__name__)
    with app.test_request_context():
        assert judge_candidate_allowed("gemini:gemini-3.1-flash-lite")
        with excluding_gemini("free:vision"):
            assert not judge_candidate_allowed("gemini:gemini-3.1-flash-lite")
            assert not judge_candidate_allowed("openrouter:google/gemini-3-flash:free")
            assert not judge_candidate_allowed("openrouter:openrouter/free")
            assert judge_candidate_allowed("groq:qwen/qwen3.8-27b")
            with excluding_gemini("gemini:gemini-3-pro"):
                assert judge_candidate_allowed("gemini:gemini-3-pro")
            assert not judge_candidate_allowed("gemini:gemini-3.1-flash-lite")
        with pytest.raises(RuntimeError), excluding_gemini("auto:vision"):
            raise RuntimeError("judge failed")
        assert judge_candidate_allowed("gemini:gemini-3.1-flash-lite")


def test_outside_a_request_nothing_is_excluded():
    assert judge_candidate_allowed("gemini:gemini-3.1-flash-lite")
