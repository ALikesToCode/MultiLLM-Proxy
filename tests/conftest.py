import os

# NanoGPT speed routing is a deployment choice that a developer may enable in a
# local .env, but it switches the text endpoint off subscription and rewrites
# model ids. Pin it off before `config` is first imported so the suite asserts
# the repository default; tests that need it override app.config directly.
os.environ["NANOGPT_SPEED_ROUTING"] = ""
