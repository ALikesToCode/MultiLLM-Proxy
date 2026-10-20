"""Controlled Container reads require the current main's enforcement capability."""
import pytest

from error_handlers import APIError
from services import user_store
from services.dispatch_policy import envelope


@pytest.mark.parametrize("controls", [
    {"official_only": None, "forced_provider_preferences": None},
    {"official_only": 1, "forced_provider_preferences": None},
    {"official_only": None, "forced_provider_preferences": '{"data_collection":"deny"}'},
])
@pytest.mark.parametrize("capability", [None, {}, {"protocol": 1, "enforcement": False},
                                       {"protocol": 2, "enforcement": True}])
def test_current_main_capability_is_required_only_for_controlled_rows(controls, capability, monkeypatch):
    calls = []
    row = dict.fromkeys(user_store.USER_FIELDS)
    row.update(username="synthetic", api_key_hash="synthetic", api_key_prefix="synthetic", scopes="chat",
               is_admin=0, created_at="2026-10-01T00:00:00Z", **controls, data_policy=envelope(controls))

    def rpc(payload, **_):
        calls.append(payload["operation"])
        return ({"version": 1, "key_controls": capability} if payload["operation"] == "capabilities"
                else {"version": 1, "user": row})

    monkeypatch.setattr(user_store, "request_private_intelligence", rpc)
    monkeypatch.setattr(user_store, "READ_RETRY_DELAY_SECONDS", 0)
    controlled = controls["official_only"] or controls["forced_provider_preferences"] is not None
    if controlled and capability != {"protocol": 2, "enforcement": True}:
        with pytest.raises(APIError) as error:
            user_store.get_user("synthetic")
        assert error.value.status_code == 503
    else:
        assert user_store.get_user("synthetic")["username"] == "synthetic"
    if not controlled:
        assert calls == ["get"]
