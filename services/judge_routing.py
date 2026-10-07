"""Request-local candidate restrictions for routed judges."""

from contextlib import contextmanager

from flask import g, has_request_context

_FLAG = "judge_exclude_gemini"


def routed_alias(model) -> bool:
    return isinstance(model, str) and model.startswith(("free:", "auto:"))


@contextmanager
def excluding_gemini(model):
    """Keep a routed judge alias off Gemini; a concrete model is a deliberate choice."""
    previous = getattr(g, _FLAG, False)
    setattr(g, _FLAG, routed_alias(model))
    try:
        yield
    finally:
        setattr(g, _FLAG, previous)


def judge_candidate_allowed(model: str) -> bool:
    if not has_request_context() or not getattr(g, _FLAG, False):
        return True
    provider, _, name = model.lower().partition(":")
    # Opaque routers cannot guarantee which model receives the request.
    return (provider != "gemini" and "gemini" not in name
            and name not in {"openrouter/free", "openrouter/auto", "orcarouter/free"})
