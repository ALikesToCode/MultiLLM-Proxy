"""Assets retain admission without inheriting API credentials or redirect bodies."""
import io
from unittest.mock import Mock, patch

import pytest
import requests

from error_handlers import APIError
from services import media_storage, video_generation
from services.dispatch_policy import envelope
from services.provider_assets import asset_http
from services.provider_dispatch import dispatch_as, provider_http
from tests.unified_api_test_case import UnifiedApiTestCase


def response(status=200, location=None):
    result = requests.Response()
    result.status_code = status
    result.raw = io.BytesIO(b"synthetic-video")
    result.headers.update({"Content-Type": "video/mp4", "Content-Length": "15"})
    if location is not None:
        result.headers["Location"] = location
    return result


@pytest.fixture
def authority(monkeypatch):
    user = {"username": "synthetic-assets", "data_policy": envelope({"official_only": 1, "forced_provider_preferences": None})}
    monkeypatch.setattr("services.auth_service.AuthService._load_user_by_username", lambda _: user)
    monkeypatch.setenv("XAI_API_KEY", "synthetic-operator-secret")
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-operator-secret")
    with dispatch_as({"username": user["username"]}):
        yield user


@pytest.mark.parametrize("consumer", ["relay", "storage"])
@pytest.mark.parametrize("restricted", [False, True])
def test_public_video_retrieval_never_receives_credentials(consumer, restricted, authority, monkeypatch):
    authority["data_policy"]["official_only"] = 1 if restricted else None
    send = Mock(return_value=response())
    monkeypatch.setattr("services.provider_dispatch.requests.request", send)
    monkeypatch.setattr(media_storage, "put_stream", lambda *args, **kwargs: {"size": args[2]})
    url = "https://unrelated-cdn.example/asset.mp4"
    headers = {"Authorization": "Bearer synthetic-cached", "x-goog-api-key": "synthetic-cached", "Cookie": "synthetic"}
    if consumer == "relay":
        assert video_generation.stream_content(url, headers, provider="xai").get_data() == b"synthetic-video"
    else:
        assert media_storage.store_video("mv_synthetic", url, headers, owner=authority["username"], model="xai:synthetic")
    assert send.call_args.kwargs["headers"] == {}


@pytest.mark.parametrize("consumer", ["relay", "storage"])
@pytest.mark.parametrize("restricted", [False, True])
def test_video_redirects_follow_location_and_strip_secrets(consumer, restricted, authority, monkeypatch):
    authority["data_policy"]["official_only"] = 1 if restricted else None
    send = Mock(side_effect=[response(302, "https://cdn.example/one"), response(307, "/two"), response()])
    monkeypatch.setattr("services.provider_dispatch.requests.request", send)
    monkeypatch.setattr(media_storage, "put_stream", lambda *args, **kwargs: {"size": args[2]})
    url = "https://api.openai.com/v1/videos/synthetic/content"
    headers = {"Authorization": "Bearer synthetic-cached"}
    if consumer == "relay":
        assert video_generation.stream_content(url, headers, provider="openai").get_data() == b"synthetic-video"
    else:
        assert media_storage.store_video("mv_synthetic", url, headers, owner=authority["username"], model="openai:synthetic")
    calls = [call.kwargs for call in send.call_args_list]
    assert calls[0]["headers"]["Authorization"] == "Bearer " + ("synthetic-operator-secret" if restricted else "synthetic-cached")
    assert [call["url"] for call in calls[1:]] == ["https://cdn.example/one", "https://cdn.example/two"]
    assert all(call["headers"] == {} and call["allow_redirects"] is False for call in calls[1:])


@pytest.mark.parametrize("consumer", ["relay", "storage"])
@pytest.mark.parametrize("location", [None, "http://cdn.example/asset", "https://cdn.example/loop"])
def test_unresolved_or_unsafe_redirects_are_errors(consumer, location, authority, monkeypatch):
    send = Mock(side_effect=lambda **kwargs: response(302, location))
    monkeypatch.setattr("services.provider_dispatch.requests.request", send)
    put = Mock()
    monkeypatch.setattr(media_storage, "put_stream", put)
    with pytest.raises(APIError) as error:
        if consumer == "relay":
            video_generation.stream_content("https://cdn.example/one", {}, provider="xai")
        else:
            media_storage.store_video("mv_synthetic", "https://cdn.example/one", {}, owner=authority["username"], model="xai:synthetic")
    assert error.value.status_code == 502
    assert send.call_count <= 6
    put.assert_not_called()


def test_each_redirect_rechecks_policy_and_never_reintroduces_credentials(authority, monkeypatch):
    send = Mock(side_effect=[response(302, "https://cdn.example/one"),
        response(302, "https://api.openai.com/v1/videos/synthetic/content"), response()])
    monkeypatch.setattr("services.provider_dispatch.requests.request", send)
    asset_http("openai", "https://api.openai.com/v1/videos/synthetic/content").close()
    assert [c.kwargs["headers"] for c in send.call_args_list][1:] == [{}, {}]
    def changed(**kwargs):
        authority["data_policy"] = None
        return response(302, "https://cdn.example/two")
    send.side_effect = changed
    with pytest.raises(APIError) as error:
        asset_http("xai", "https://cdn.example/one")
    assert error.value.status_code == 503
    assert send.call_count == 4


def test_unapproved_api_origin_cannot_receive_attested_secret(authority, monkeypatch):
    send = Mock()
    with pytest.raises(APIError):
        provider_http("xai", "GET", "https://api.x.ai.unrelated.example/v1/videos/synthetic", transport=send)
    send.assert_not_called()


class RegisteredVideoAssetTest(UnifiedApiTestCase):
    def test_restricted_registered_content_route_keeps_status_credential_off_cdn(self):
        from tests.test_media_generation import upstream
        auth = self.app_module.AuthService
        with patch.object(auth, "get_current_user", return_value={"username": "admin", "is_admin": True}):
            created = auth.create_user("synthetic-assets", is_admin=True)
            auth.set_key_controls("synthetic-assets", {"official_only": True})
        with self.app.app_context():
            job = video_generation.issue_job_id("synthetic-assets", "xai", "synthetic", "synthetic-video")
        with patch.dict("os.environ", {"XAI_API_KEY": "synthetic-operator-secret"}), \
                patch.object(auth, "get_api_key", return_value="synthetic-cached"), \
                patch("services.provider_dispatch.requests.request", side_effect=[upstream(200,
                    {"video": {"url": "https://unrelated-cdn.example/asset.mp4"}}), response()]) as send:
            result = self.client.get(f"/v1/videos/{job}/content", headers={"Authorization": "Bearer " + created["api_key"]})
            assert result.status_code == 200, result.json
            assert result.data == b"synthetic-video"
        assert send.call_args_list[0].kwargs["headers"]["Authorization"] == "Bearer synthetic-operator-secret"
        assert send.call_args_list[1].kwargs["headers"] == {}
