import os
import tempfile
from pathlib import Path

from env_loader import load_runtime_env

EPHEMERAL_SQLITE_FILENAMES = {
    "AUTH_DB_PATH": "auth.sqlite3",
    "RATE_LIMIT_DB_PATH": "rate-limits.sqlite3",
    "MODEL_REGISTRY_DB_PATH": "model-registry.sqlite3",
}


def _ephemeral_sqlite_defaults() -> dict[str, str]:
    runtime_directory = Path(tempfile.mkdtemp(prefix="multillm-"))
    return {
        name: str(runtime_directory / filename)
        for name, filename in EPHEMERAL_SQLITE_FILENAMES.items()
    }


def init_vercel():
    """Initialize Vercel-specific configuration"""
    load_runtime_env()

    # Set default environment variables if not set
    if not os.environ.get('FLASK_ENV'):
        os.environ['FLASK_ENV'] = 'production'
    
    # Copy the Vercel secret into the runtime env when it is explicitly configured.
    if not os.environ.get('ADMIN_API_KEY') and os.environ.get('VERCEL_ADMIN_API_KEY'):
        os.environ['ADMIN_API_KEY'] = os.environ['VERCEL_ADMIN_API_KEY']

    if os.environ.get("VERCEL"):
        missing_names = [
            name
            for name in EPHEMERAL_SQLITE_FILENAMES
            if not os.environ.get(name)
        ]
        defaults = _ephemeral_sqlite_defaults() if missing_names else {}
        for name in missing_names:
            if not os.environ.get(name):
                os.environ[name] = defaults[name]
