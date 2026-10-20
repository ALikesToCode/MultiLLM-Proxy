"""Expansion preserves legacy rows and fences every future controlled dispatch."""
import subprocess
import sys
import types
from unittest.mock import MagicMock, Mock

import pytest
from flask import Flask, g

from error_handlers import APIError
from services.dispatch_policy import envelope
from services.provider_dispatch import capture_dispatch, dispatch_as, provider_http
from services.user_store import USER_FIELDS, _row


def account(policy):
    return {"username": "synthetic", "data_policy": envelope(policy)}


@pytest.mark.parametrize("controls", [
    {"official_only": None, "forced_provider_preferences": None},
    {"official_only": 1, "forced_provider_preferences": None},
    {"official_only": 0, "forced_provider_preferences": None},
    {"official_only": False, "forced_provider_preferences": None},
    {"official_only": None, "forced_provider_preferences": '{}'},
    {"official_only": None, "forced_provider_preferences": '{"data_collection":"deny"}'},
])
@pytest.mark.parametrize("provider", ["openai", "gemini", "openrouter", "linkapi", "knowledge", "cloudflare"])
def test_future_policies_refuse_before_every_transport_but_nulls_keep_working(controls, provider, monkeypatch):
    current = account(controls)
    monkeypatch.setattr("services.auth_service.AuthService._load_user_by_username", lambda _: current)
    send = Mock()
    with dispatch_as({"username": "synthetic"}):
        if controls["official_only"] is not None or controls["forced_provider_preferences"] is not None:
            with pytest.raises(APIError) as error:
                provider_http(provider, "POST", "https://provider.example/generate", transport=send)
            assert error.value.status_code == 503
            send.assert_not_called()
        else:
            provider_http(provider, "POST", "https://provider.example/generate", transport=send)
            send.assert_called_once()


def test_background_callback_rereads_policy_after_rollback(monkeypatch):
    current = account({"official_only": None, "forced_provider_preferences": None})
    monkeypatch.setattr("services.auth_service.AuthService._load_user_by_username", lambda _: current)
    send = Mock()
    with Flask(__name__).test_request_context():
        g.authenticated_user = current
        callback = capture_dispatch(lambda: provider_http("openai", "POST", "https://provider.example/", transport=send))
    current = account({"official_only": 1, "forced_provider_preferences": None})
    with pytest.raises(APIError) as error:
        callback()
    assert error.value.status_code == 503
    send.assert_not_called()


def test_both_row_shapes_remain_readable_without_a_global_account_list_fence():
    row = dict.fromkeys(USER_FIELDS)
    row.update(username="synthetic", api_key_hash="synthetic", api_key_prefix="synthetic", scopes="chat",
               is_admin=0, created_at="2026-10-01T00:00:00Z")
    assert _row(row) == row
    controlled = {"official_only": 1, "forced_provider_preferences": None}
    assert _row({**row, **controlled, "data_policy": envelope(controlled), "future_metadata": 1})["data_policy"]["official_only"] == 1


@pytest.mark.parametrize("policy", [{}, {"version": 1, "official_only": 1},
                                      {"version": 1, "official_only": "invalid", "forced_provider_preferences": None}])
def test_malformed_current_policy_never_dispatches(policy, monkeypatch):
    monkeypatch.setattr("services.auth_service.AuthService._load_user_by_username", lambda _: {"data_policy": policy})
    send = Mock()
    with dispatch_as({"username": "synthetic"}), pytest.raises(APIError) as error:
        provider_http("openai", "POST", "https://provider.example/", transport=send)
    assert error.value.status_code == 503
    send.assert_not_called()


@pytest.mark.parametrize("controls", [{"official_only": 1, "forced_provider_preferences": None},
                                     {"official_only": 0, "forced_provider_preferences": None},
                                     {"official_only": False, "forced_provider_preferences": None},
                                     {"official_only": None, "forced_provider_preferences": '{}'},
                                     {"official_only": None, "forced_provider_preferences": '{"data_collection":"deny"}'}])
def test_media_and_both_shadow_dispatches_refuse_future_controls(controls, monkeypatch):
    from services.media_storage import fetch_public
    from services.shadow_eval_data_policy import guarded_dispatch
    monkeypatch.setattr("services.auth_service.AuthService._load_user_by_username", lambda _: account(controls))
    send = Mock()
    session = Mock()
    session.__enter__ = Mock(return_value=session)
    session.__exit__ = Mock(return_value=False)
    monkeypatch.setattr("services.media_storage._session", lambda: session)
    with dispatch_as({"username": "synthetic"}), pytest.raises(APIError) as error:
        fetch_public("https://images.example.com/asset.png")
    assert error.value.status_code == 503
    session.request.assert_not_called()
    for role in ("candidate", "judge"):
        with pytest.raises(APIError) as error:
            guarded_dispatch({"key_id": "synthetic"}, send)({"role": role})
        assert error.value.status_code == 503
    send.assert_not_called()


OLD = "544bf49ba3b3d03d185ec5b5a71b2b1877dda786"


def pinned_module(name, monkeypatch):
    module = types.ModuleType("pinned_" + name)
    monkeypatch.setitem(sys.modules, module.__name__, module)
    source = subprocess.check_output(["git", "show", f"{OLD}:services/{name}.py"], text=True)
    exec(compile(source, f"{OLD}:{name}", "exec"), module.__dict__)
    return module


@pytest.fixture
def null_principal(monkeypatch):
    monkeypatch.setattr("services.auth_service.AuthService._load_user_by_username", lambda _: {
        "username": "synthetic", "data_policy": envelope({"official_only": None, "forced_provider_preferences": None})})
    with dispatch_as({"username": "synthetic"}):
        yield


def test_old_and_expansion_video_api_operations_do_not_follow_redirects(monkeypatch, null_principal):
    from services import video_generation
    for module in (pinned_module("video_generation", monkeypatch), video_generation):
        send = Mock()
        monkeypatch.setattr(module.requests, "request", send)
        options = {"provider": "xai"} if module is video_generation else {}
        module._send("POST", "https://api.x.ai/v1/videos/generations", timeout=10, **options)
        assert send.call_args.kwargs["allow_redirects"] is False


def test_old_and_expansion_private_ai_posts_do_not_follow_redirects(monkeypatch, null_principal):
    from services import cloudflare_ai
    for module in (pinned_module("cloudflare_ai", monkeypatch), cloudflare_ai):
        session = MagicMock()
        session.__enter__.return_value = session
        response = MagicMock(status_code=302, headers={})
        response.iter_content.return_value = iter([b"redirect"])
        session.request.return_value = response
        session.post.return_value = response
        monkeypatch.setattr(module.requests, "Session", lambda: session)
        result = module.post("/v1/images/generations", {"model": "synthetic"}, 10)
        assert result.status_code == 302
        send = session.request if module is cloudflare_ai else session.post
        assert send.call_args.kwargs["allow_redirects"] is False


@pytest.mark.parametrize("redirects", [False, True])
def test_expansion_boundary_keeps_explicit_python_redirect_mode(redirects, null_principal):
    send = Mock()
    provider_http("xai", "GET", "https://api.x.ai/v1/videos/synthetic", transport=send, allow_redirects=redirects)
    assert send.call_args.kwargs["allow_redirects"] is redirects


@pytest.mark.parametrize("controls", [
    {"official_only": 0, "forced_provider_preferences": None},
    {"official_only": False, "forced_provider_preferences": None},
    {"official_only": None, "forced_provider_preferences": {}},
    {"official_only": None, "forced_provider_preferences": '{}'},
])
def test_non_null_policies_never_enter_shadow_sampling(controls):
    from services.shadow_eval_contract import eligible, make_sample
    user = {"username": "synthetic", "shadow_eval_rate": 0.2, **controls}
    payload = {"model": "auto:synthetic", "messages": [{"role": "user", "content": "synthetic"}]}
    assert not eligible(payload, user, "/v1/chat/completions")
    assert make_sample(payload, user, "auto:synthetic", {"content": "synthetic"}, "openai:synthetic", 1, {}) is None
