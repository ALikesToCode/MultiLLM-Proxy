"""The code version advertises rollout support; configuration cannot turn it on."""
CAPABILITY = {"protocol": 1, "enforcement": False}


def expansion_fence(policy):
    if not CAPABILITY["enforcement"] and (policy.get("official_only") or policy.get("forced_provider_preferences") is not None):
        from error_handlers import APIError
        raise APIError("This runtime cannot enforce the account policy", 503, {"error": "key_controls_require_upgrade"})
    return policy
