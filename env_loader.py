import os
from pathlib import Path
from typing import Iterable, Optional

from dotenv import dotenv_values, load_dotenv


def load_runtime_env(root: Optional[Path] = None, filenames: Iterable[str] = (".env", ".env.local")) -> None:
    """
    Load local environment files without clobbering externally supplied secrets.

    Precedence is: real environment > .env.local > .env.
    """
    root_path = root or Path(__file__).resolve().parent
    protected_keys = set(os.environ)

    env_path = root_path / ".env"
    if env_path.is_file():
        load_dotenv(env_path, override=False)

    for filename in filenames:
        if filename == ".env":
            continue

        values = dotenv_values(root_path / filename)
        for key, value in values.items():
            if value is None or key in protected_keys:
                continue
            os.environ[key] = value
