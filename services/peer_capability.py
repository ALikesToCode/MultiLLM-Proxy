"""Current peer code capability is required before controlled delegation."""
from services.dispatch_policy import unavailable


def require_enforcement(capability):
    if (not isinstance(capability, dict) or type(capability.get("protocol")) is not int
            or capability["protocol"] < 2 or capability.get("enforcement") is not True):
        raise unavailable()
