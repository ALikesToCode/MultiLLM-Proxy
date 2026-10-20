"""The code version advertises rollout support; configuration cannot turn it on."""
CAPABILITY = {"protocol": 2, "enforcement": True}


def policy_present(policy):
    return policy.get("official_only") is not None or policy.get("forced_provider_preferences") is not None


def expansion_fence(policy):
    if not CAPABILITY["enforcement"] and policy_present(policy):
        from error_handlers import APIError
        raise APIError("This runtime cannot enforce the account policy", 503, {"error": "key_controls_require_upgrade"})
    return policy
