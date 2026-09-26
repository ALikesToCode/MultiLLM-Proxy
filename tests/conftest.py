import os

# NanoGPT speed routing is a deployment choice that a developer may enable in a
# local .env, but it switches the text endpoint off subscription and rewrites
# model ids. Pin it off before `config` is first imported so the suite asserts
# the repository default; tests that need it override app.config directly.
os.environ["NANOGPT_SPEED_ROUTING"] = ""

import pytest


@pytest.fixture(autouse=True)
def _fresh_public_capability_cache():
    # The models.dev index is cached per process; each test sees its own fixtures.
    from services.provider_capability_discovery import reset_public_capability_cache

    reset_public_capability_cache()
    yield
    reset_public_capability_cache()
