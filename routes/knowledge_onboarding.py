"""Public, credential-free discovery and setup material for Knowledge clients."""

import json
import shlex
from pathlib import Path

from flask import Response, jsonify, render_template, request, url_for

from routes import knowledge_alexandria, knowledge_management

PUBLIC_ENDPOINTS = frozenset({
    "knowledge_agent_setup", "knowledge_llms", "knowledge_llms_full",
    "knowledge_agent_skill", "knowledge_agent_prompt", "knowledge_agent_config",
})
_SKILL_PATH = Path(__file__).resolve().parents[1] / "skills" / "multillm-knowledge" / "SKILL.md"
_RESOURCES = [
    ("/llms.txt", "Discovery index for agents: setup links, access model and providers."),
    ("/llm.txt", "Alias of llms.txt for clients that request the singular name."),
    ("/llms-full.txt", "Complete operating instructions; the same text as the skill."),
    ("/agent-onboarding/SKILL.md", "Installable skill for Codex and Claude Code."),
    ("/agent-onboarding/prompt.txt", "The setup prompt as plain text."),
    ("/agent-onboarding/config.json", "Endpoint, protocol versions, scopes and tool catalogue."),
]
KNOWLEDGE_PROVIDERS = [
    ("Context7", "Version-aware library documentation discovery"),
    ("Exa", "Source discovery and original source acquisition"),
    ("Firecrawl", "Acquire and refresh registered public documentation"),
    ("Mintlify Index", "Documentation discovery"),
    ("DeepWiki", "Public repository documentation discovery"),
    ("Cloudflare AI Search", "Search the verified, retained documentation corpus"),
    ("Firecrawl Alexandria", "Discover structured data capabilities, inspect prices, retrieve with receipts"),
]


def _origin():
    # Production's trusted-origin middleware takes this from the outer Worker.
    return request.url_root.rstrip("/")


def tool_catalogue():
    return [
        {"name": name, "scope": "knowledge:read"}
        for name in ("knowledge_context", "knowledge_search")
    ] + [
        {"name": tool["name"], "scope": "knowledge:read"}
        for tool in knowledge_alexandria.TOOLS
    ] + [
        {"name": tool["name"], "scope": knowledge_management.required_scope(tool["name"])}
        for tool in knowledge_management.TOOLS
    ]


def _setup_prompt():
    origin = _origin()
    return f"""Set up MultiLLM Knowledge as my default knowledge service for this project.
Read {origin}/llms.txt and {origin}/agent-onboarding/SKILL.md.
Install the multillm-knowledge skill for my client, preserving existing configuration.
Connect the remote HTTP MCP server at {origin}/mcp as multillm-knowledge.
Use MULTILLM_KNOWLEDGE_API_KEY from my private environment for the Bearer credential;
never ask me to paste a secret into chat or save it in this repository.
Use knowledge:read for evidence and Alexandria; add knowledge:manage only for authorized administration.
Initialize the connection, list the tools available to my key, and verify a small request.
Route library docs, repository knowledge, web evidence, source indexing, and Alexandria
through MultiLLM. Do not silently fall back to direct provider tools when the gateway fails.
Preserve existing integrations and use direct providers only when I explicitly ask.
Read the actual dependency version, cite original evidence, and state coverage gaps.
Discover and inspect Alexandria capabilities before authorized retrieval. Report each
call's actual credits and cost state; after uncertainty, check the same request's receipt.
Do not enable spending or assert retention/billing acknowledgements without my confirmation.
Report connection, scope, indexing or provider limitations instead of claiming readiness.
"""


def _client_setup(origin):
    """Configuration and one-line commands that reference the key without containing it."""
    endpoint = origin + "/mcp"
    claude_server = {"type": "http", "url": endpoint,
                     "headers": {"Authorization": "Bearer ${MULTILLM_KNOWLEDGE_API_KEY}"}}
    return {
        "codex_config": ("[mcp_servers.multillm-knowledge]\n"
                         f"url = {json.dumps(endpoint)}\n"
                         'bearer_token_env_var = "MULTILLM_KNOWLEDGE_API_KEY"'),
        "codex_command": (f"codex mcp add multillm-knowledge --url {shlex.quote(endpoint)} "
                          "--bearer-token-env-var MULTILLM_KNOWLEDGE_API_KEY"),
        "claude_config": json.dumps({"mcpServers": {"multillm-knowledge": claude_server}}, indent=2),
        # Single quotes keep ${...} unexpanded so Claude Code resolves it from the environment.
        "claude_command": ("claude mcp add-json multillm-knowledge "
                           f"{shlex.quote(json.dumps(claude_server, separators=(',', ':')))} --scope project"),
    }


def _skill():
    content = _SKILL_PATH.read_text(encoding="utf-8")
    connection = f"\nGateway origin: `{_origin()}`. MCP endpoint: `{_origin()}/mcp`.\n"
    return content.replace("# MultiLLM Knowledge\n", "# MultiLLM Knowledge\n" + connection, 1)


def _text(content, *, markdown=False):
    response = Response(content, mimetype="text/markdown" if markdown else "text/plain")
    response.headers["Cache-Control"] = "public, max-age=300"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


def register_knowledge_onboarding_routes(app):
    @app.get("/agent-onboarding")
    def knowledge_agent_setup():
        origin = _origin()
        response = Response(render_template("knowledge_agents.html", origin=origin,
            setup_prompt=_setup_prompt(), providers=KNOWLEDGE_PROVIDERS, tools=tool_catalogue(),
            resources=_RESOURCES, **_client_setup(origin)))
        response.headers["Cache-Control"] = "no-store"
        return response

    # Decorators register bottom-up; /llms.txt first makes it the canonical url_for target.
    @app.get("/llm.txt")
    @app.get("/llms.txt")
    def knowledge_llms():
        origin = _origin()
        return _text(f"""# MultiLLM Knowledge Gateway

> One scoped knowledge service for technical evidence, public documentation indexing,
> and credit-priced structured data. Clients use a proxy key; provider keys stay private.

## Setup
- [Agent setup]({origin}/agent-onboarding): Copyable setup prompt and client configuration.
- [Installable skill]({origin}/agent-onboarding/SKILL.md): Complete operating instructions.
- [Setup prompt]({origin}/agent-onboarding/prompt.txt): Configure this service as the default knowledge entry point.
- [Machine configuration]({origin}/agent-onboarding/config.json): Endpoint, scopes and tool catalogue.
- [Full instructions]({origin}/llms-full.txt): Evidence, management, cost and retry contracts.

## Access
- [MCP]({origin}/mcp): Streamable HTTP POST with a scoped Bearer proxy key.
- [Administrator dashboard]({origin}/knowledge): Sources, jobs, connections and allowances; login required.

Use knowledge:read for retrieval and retained artifacts; knowledge:manage for status,
sources, jobs and policy. Tools are filtered to the authenticated key's scopes.
Providers: Context7, Firecrawl, Exa, Mintlify Index, DeepWiki, Cloudflare AI Search,
and Firecrawl Alexandria. Availability depends on configured credentials and policy.
Public setup material contains no credentials, source inventory, or account status.
Alexandria discovery and inspection are free. Execution spends the discovered price;
report actual receipt costs and keep the same request ID after uncertain outcomes.
""", markdown=True)

    @app.get("/llms-full.txt")
    def knowledge_llms_full():
        return _text(_skill(), markdown=True)

    @app.get("/agent-onboarding/SKILL.md")
    def knowledge_agent_skill():
        response = _text(_skill(), markdown=True)
        if request.args.get("download") == "1":
            response.headers["Content-Disposition"] = 'attachment; filename="SKILL.md"'
        return response

    @app.get("/agent-onboarding/prompt.txt")
    def knowledge_agent_prompt():
        return _text(_setup_prompt())

    @app.get("/agent-onboarding/config.json")
    def knowledge_agent_config():
        return jsonify({"name": "multillm-knowledge", "transport": "streamable-http",
            "url": _origin() + "/mcp", "protocol_versions": ["2025-06-18", "2025-03-26"],
            "accept": "application/json, text/event-stream",
            "authentication": {"type": "bearer", "env": "MULTILLM_KNOWLEDGE_API_KEY"},
            "skill_url": url_for("knowledge_agent_skill", _external=True),
            "prompt_url": url_for("knowledge_agent_prompt", _external=True),
            "tools": tool_catalogue(), "providers": [name for name, _ in KNOWLEDGE_PROVIDERS]})
