"""Public product overview. It explains the gateway without exposing deployment state."""

from flask import Response, render_template, request

from proxy import PROVIDER_DETAILS
from routes.knowledge_onboarding import KNOWLEDGE_PROVIDERS, tool_catalogue
from services.proxy_documentation_service import PROVIDER_DISPLAY_NAMES

PUBLIC_ENDPOINTS = frozenset({"product_overview"})


def _integration_names():
    return sorted(
        {PROVIDER_DISPLAY_NAMES.get(provider, provider.title()) for provider in PROVIDER_DETAILS},
        key=str.casefold,
    )


def register_public_routes(app):
    @app.get("/about")
    def product_overview():
        tools = tool_catalogue()
        response = Response(render_template(
            "product.html",
            origin=request.url_root.rstrip("/"),
            integrations=_integration_names(),
            knowledge_providers=KNOWLEDGE_PROVIDERS,
            tool_count=len(tools),
            read_tool_count=sum(tool["scope"] == "knowledge:read" for tool in tools),
        ))
        # Pages carry a per-session CSRF token and a signed-in header variant.
        response.headers["Cache-Control"] = "no-store"
        return response
