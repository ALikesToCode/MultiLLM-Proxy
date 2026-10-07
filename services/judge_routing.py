"""Request-local candidate restrictions for routed image judges."""

from flask import g, has_request_context


def judge_candidate_allowed(model: str) -> bool:
    if not has_request_context() or not getattr(g, "image_qa_exclude_gemini", False):
        return True
    provider, _, name = model.lower().partition(":")
    # Opaque routers cannot guarantee which model receives the image.
    return (provider != "gemini" and "gemini" not in name
            and name not in {"openrouter/free", "openrouter/auto", "orcarouter/free"})
