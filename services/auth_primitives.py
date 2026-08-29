"""Validation and serialization primitives for authentication records."""

from datetime import datetime, timezone
from typing import List, Optional

from werkzeug.security import generate_password_hash

from error_handlers import APIError
from providers.image_relays import image_relay_credential_env_names

DEFAULT_USER_SCOPES = ("chat", "models")
DEFAULT_ADMIN_SCOPES = ("admin", "chat", "metrics", "models", "users")
MAX_USERNAME_LENGTH = 128
MAX_API_KEY_LENGTH = 1024
PROVIDER_API_KEY_ENV_NAMES = {
    "opencode": ("OPENCODE_GO_API_KEY", "OPENCODE_API_KEY"),
    "linkapi": ("LINKAPI_KEY", "LINKAPI_API_KEY"),
    "codex-easy": ("CODEX_EASY_API_KEY", "CODEX_API_KEY"),
    "kimi-code": ("KIMI_CODE_API_KEY",),
    "nanogpt": ("NANOGPT_API_KEY", "NANO_GPT_KEY"),
}


def provider_api_key_env_names(provider: str) -> tuple[str, ...]:
    relay_names = image_relay_credential_env_names(provider)
    if relay_names:
        return relay_names
    return PROVIDER_API_KEY_ENV_NAMES.get(
        provider,
        (f"{provider.upper()}_API_KEY",),
    )


def provider_credential_env_names(provider: str) -> tuple[str, ...]:
    """Return safe environment-variable names for setup guidance."""
    if provider in {"gemini", "gemma"}:
        return ("GEMINI_API_KEY",)
    if provider == "chutes":
        return ("CHUTES_API_TOKEN",)
    if provider == "googleai":
        return (
            "GOOGLE_APPLICATION_CREDENTIALS_JSON",
            "GOOGLE_APPLICATION_CREDENTIALS",
        )
    if provider == "groq":
        return ("GROQ_API_KEY", "GROQ_API_KEY_1", "GROQ_API_KEY_2")
    if provider == "nanogpt":
        return (
            "NANOGPT_API_KEY",
            "NANOGPT_API_KEY_1",
            "NANOGPT_API_KEY_2",
            "NANO_GPT_KEY",
        )
    return provider_api_key_env_names(provider)


def serialize_datetime(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def deserialize_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    return datetime.fromisoformat(value)


def default_scopes(is_admin: bool) -> tuple[str, ...]:
    return DEFAULT_ADMIN_SCOPES if is_admin else DEFAULT_USER_SCOPES


def serialize_scopes(scopes: Optional[List[str] | tuple[str, ...]]) -> str:
    if not scopes:
        return ",".join(DEFAULT_USER_SCOPES)
    return ",".join(
        sorted({scope.strip() for scope in scopes if scope and scope.strip()})
    )


def deserialize_scopes(value: Optional[str]) -> List[str]:
    if not value:
        return list(DEFAULT_USER_SCOPES)
    return [scope.strip() for scope in value.split(",") if scope.strip()]


def build_api_key_prefix(api_key: Optional[str]) -> str:
    if not api_key:
        return "mllm_unknown"
    return f"mllm_{api_key[:8]}"


def hash_api_key(api_key: str) -> str:
    return generate_password_hash(api_key)


def normalized_username(username: object) -> Optional[str]:
    if not isinstance(username, str):
        return None
    normalized = username.strip()
    if not normalized or len(normalized) > MAX_USERNAME_LENGTH:
        return None
    if any(
        ord(character) < 32 or ord(character) == 127
        for character in normalized
    ):
        return None
    return normalized


def require_valid_username(username: object) -> str:
    normalized = normalized_username(username)
    if normalized is None:
        raise APIError(
            f"Username must be 1 to {MAX_USERNAME_LENGTH} characters "
            "and contain no control characters",
            status_code=400,
        )
    return normalized
