import os

from env_loader import load_runtime_env

EPHEMERAL_SQLITE_DEFAULTS = {
    "AUTH_DB_PATH": "/tmp/multillm-auth.sqlite3",
    "RATE_LIMIT_DB_PATH": "/tmp/multillm-rate-limits.sqlite3",
    "MODEL_REGISTRY_DB_PATH": "/tmp/multillm-model-registry.sqlite3",
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
        for name, path in EPHEMERAL_SQLITE_DEFAULTS.items():
            if not os.environ.get(name):
                os.environ[name] = path
