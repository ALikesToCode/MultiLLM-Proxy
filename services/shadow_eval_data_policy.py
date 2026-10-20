"""Recheck source-key authority before retained content leaves the evaluation runner."""

from error_handlers import APIError
from services.key_data_guards import has_data_controls


def source_allows_replay(sample):
    from services.auth_service import AuthService
    from services.key_controls import expired

    try:
        user = AuthService._load_user_by_username(sample["key_id"])
        from services.dispatch_policy import verify
        policy = verify(user.get("data_policy") if user else None)
        return bool(user and not user.get("revoked_at") and not expired(user)
                    and not has_data_controls(policy))
    except Exception:
        # Missing, malformed or unavailable authority cannot authorize content replay.
        return False


def guarded_dispatch(sample, dispatch):
    def guarded(payload):
        if not source_allows_replay(sample):
            raise APIError("Source key does not permit shadow replay", 403,
                           {"error": "shadow_source_not_allowed"})
        from services.provider_dispatch import dispatch_as
        with dispatch_as({"username": sample["key_id"]}):
            return dispatch(payload)
    return guarded
