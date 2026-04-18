import os
from typing import Dict


RUNTIME_SECRET_PLACEHOLDERS = {
    "ADMIN_API_KEY": {"your-universal-api-key", "default-key"},
    "FLASK_SECRET_KEY": {"your-flask-secret-key", "your-secret-key"},
    "JWT_SECRET": {"your-jwt-secret-key", "your-secret-key"},
}


def require_runtime_secret(name: str) -> str:
    value = (os.environ.get(name) or "").strip()
    if not value:
        raise RuntimeError(f"{name} must be configured before starting MultiLLM-Proxy")

    if value in RUNTIME_SECRET_PLACEHOLDERS.get(name, set()):
        raise RuntimeError(f"{name} must be replaced with a real secret before starting MultiLLM-Proxy")

    return value


def validate_runtime_secrets() -> Dict[str, str]:
    return {
        name: require_runtime_secret(name)
        for name in ("ADMIN_API_KEY", "FLASK_SECRET_KEY", "JWT_SECRET")
    }
