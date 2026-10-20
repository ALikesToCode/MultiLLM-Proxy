"""Origin-bound operator credentials; public assets never receive API secrets."""
import json
import os
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

from flask import current_app, has_app_context

from error_handlers import APIError
from services.auth_primitives import provider_api_key_env_names, usable_credential

SECRET_HEADERS = {"authorization", "proxy-authorization", "x-api-key", "x-goog-api-key", "api-key", "cookie"}


def origin(url):
    try:
        parsed = urlsplit(url)
        if parsed.username or parsed.password or not parsed.hostname:
            return None
        return parsed.scheme.lower(), parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return None


def api_origin(provider, url):
    from config import Config
    bases = current_app.config.get("API_BASE_URLS", Config.API_BASE_URLS) if has_app_context() else Config.API_BASE_URLS
    allowed = {origin(bases.get(provider, ""))}
    # Native Gemini and Vertex protocols use the same operator API binding.
    if provider in {"gemini", "gemma", "palm"}:
        allowed.add(origin("https://generativelanguage.googleapis.com"))
    allowed.discard(None)
    target = origin(url)
    return target is not None and target[0] == "https" and target in allowed


def strip_credentials(headers):
    return {name: value for name, value in headers.items() if name.lower() not in SECRET_HEADERS}


def unavailable_credential():
    return APIError("Attested provider credential is unavailable", 503, {"error": "attested_credential_unavailable"})


def _google_binding():
    raw = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS_JSON", "").strip()
    path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "").strip()
    if raw:
        return "json", raw
    if path:
        return "file", Path(path).read_text()
    return None


def google_operator_token():
    """Refresh the current binding, never the legacy process-wide token cache."""
    try:
        binding = _google_binding()
        if binding:
            from google.oauth2 import service_account
            from google.auth.transport.requests import Request
            info = json.loads(binding[1])
            if origin(info.get("token_uri", "")) != origin("https://oauth2.googleapis.com"):
                raise ValueError()
            credentials = service_account.Credentials.from_service_account_info(info,
                scopes=["https://www.googleapis.com/auth/cloud-platform"])
            credentials.refresh(Request())
            token = credentials.token
            if binding != _google_binding():
                raise ValueError()
        else:
            binary = shutil.which("gcloud")
            if not binary:
                raise ValueError()
            def run(*args):
                return subprocess.run([binary, *args, "--quiet"], capture_output=True, text=True,
                                      check=True, timeout=30).stdout.strip()
            account = run("config", "get-value", "account")
            if not account or account == "(unset)":
                raise ValueError()
            token = run("auth", "print-access-token", account)
            if _google_binding() is not None or account != run("config", "get-value", "account"):
                raise ValueError()
        if not isinstance(token, str) or not token.strip():
            raise ValueError()
        return token.strip()
    except Exception:
        raise unavailable_credential() from None


def operator_credential(provider):
    if provider == "googleai":
        return google_operator_token()
    names = ("GEMINI_API_KEY",) if provider == "gemini" else provider_api_key_env_names(provider)
    key = next((usable_credential(os.environ.get(name), name) for name in names if usable_credential(os.environ.get(name))), None)
    if not key:
        raise unavailable_credential()
    return key
