"""Public, credential-free discovery and setup material for Knowledge clients."""

import json
import shlex
from pathlib import Path

from flask import Response, jsonify, render_template, request, url_for

from routes import gateway_mcp, knowledge_mcp

PUBLIC_ENDPOINTS = frozenset({
    "knowledge_agent_setup", "knowledge_llms", "knowledge_llms_full",
    "knowledge_agent_skill", "knowledge_agent_prompt", "knowledge_agent_config", "media_agent_skill",
    "chat_agent_skill", "mcp_agent_skill", "mcp_agent_config",
})
_SKILL_PATH = Path(__file__).resolve().parents[1] / "skills" / "multillm-knowledge" / "SKILL.md"
_SKILLS_DIR = Path(__file__).resolve().parents[1] / "skills"
_RESOURCES = [
    ("/llms.txt", "Discovery index for agents: setup links, access model and providers."),
    ("/llm.txt", "Alias of llms.txt for clients that request the singular name."),
    ("/llms-full.txt", "Complete operating instructions; the same text as the skill."),
    ("/agent-onboarding/SKILL.md", "Installable skill for Codex and Claude Code."),
    ("/agent-onboarding/chat/SKILL.md", "Installable skill for chat models from code: SDK setup, routes and retries."),
    ("/agent-onboarding/media/SKILL.md", "Installable skill for image, image batch and video generation."),
    ("/agent-onboarding/mcp/SKILL.md", "Installable skill for the MultiLLM MCP server: model, chat and media tools."),
    ("/agent-onboarding/mcp/config.json", "MultiLLM MCP endpoint, protocol versions, scopes and tools."),
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
    return [{"name": entry["definition"]["name"], "scope": entry["scope"]}
            for entry in knowledge_mcp.catalogue()["tools"]]


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


def _gateway_skill(name, title):
    """A chat or media skill with this gateway's origin, as agents install it."""
    content = (_SKILLS_DIR / name / "SKILL.md").read_text(encoding="utf-8")
    connection = f"\nGateway origin: `{_origin()}`. Set `MULTILLM_BASE_URL={_origin()}` for the examples below.\n"
    return content.replace(f"# {title}\n", f"# {title}\n" + connection, 1)


def _download(content):
    response = _text(content, markdown=True)
    if request.args.get("download") == "1":
        response.headers["Content-Disposition"] = 'attachment; filename="SKILL.md"'
    return response


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
        return _text(f"""# MultiLLM Proxy

> One OpenAI-compatible gateway for chat models, image and video generation, and cited
> technical knowledge. Clients use a scoped proxy key; provider keys stay private.

## Skills for LLMs and coding agents
Install these in Claude Code, Codex or another agent, or read them before writing code.
- [Chat skill]({origin}/agent-onboarding/chat/SKILL.md): Call chat models from code: SDK setup, model discovery, automatic routes, free pools, the Messages API, caching, headers and retries.
- [Media skill]({origin}/agent-onboarding/media/SKILL.md): Generate and edit images, run background batches, make videos, and create embeddings, speech and transcriptions from code.
- [MCP skill]({origin}/agent-onboarding/mcp/SKILL.md): Connect the MultiLLM MCP server for model, chat and media tools.
- [Knowledge skill]({origin}/agent-onboarding/SKILL.md): Cited evidence, documentation indexing and Firecrawl Alexandria.

## Chat
- OpenAI SDK base URL `{origin}/v1` with `Authorization: Bearer $MULTILLM_API_KEY`
  (scope `chat`, plus `models` for discovery). Keep the key on a server.
- `GET {origin}/v1/models`: exact model IDs (`provider:model`, `auto:<name>`, `free:text`,
  `free:vision`) and their chat, image and video capabilities.
- `POST {origin}/v1/chat/completions`: Chat Completions with optional `stream: true`.
  `auto:` routes fall back between providers; `free:` pools use only free models and
  accept function `tools`, sending them only to models with confirmed tool support.
- `POST {origin}/v1/responses`: the Responses API for any chat model, including `auto:`
  routes and `free:` pools.
- `POST {origin}/v1/messages`: the Anthropic Messages API for any chat model (`x-api-key`
  or Bearer). Messages-compatible SDKs use base URL `{origin}` with a MultiLLM model ID.
- `POST {origin}/optimize/v1/chat/completions`: compacts long histories before sending.
- `GET {origin}/v1/usage`: the key's own spend, remaining budget and recent history.
- `GET {origin}/status.json`: public health of each automatic route and provider.

Set SDK retries to 0: a retried generation can be billed twice. `auto:` routes move on
after a definite refusal or a `500`, `502` or `503` before any output, never after a
timeout. Send `X-MultiLLM-Cache: on` to reuse answers to identical deterministic requests.
A key may carry a dollar budget or model allowlist: `429 budget_exceeded` and
`403 model_not_allowed` mean stop and tell the user.

## Media generation
- `POST {origin}/v1/images/generations` with `model: "auto:image"`: the best current model
  (GPT Image 2.5 Sunburst) at `max` quality, falling back across GGUU, Cloudflare AI,
  OpenAI, xAI, Together, AIHubMix and Workers AI.
- `POST {origin}/v1/images/edits` (default `auto:image-edit`): edit or combine images from
  a multipart upload, image URLs or `{{"file_id": ...}}` of an image stored with
  `POST {origin}/v1/media/uploads` (reuse one large source image across requests).
- `POST {origin}/v1/images/batch`: different prompts, sizes and models in one call (16 items).
- `POST {origin}/v1/images/batches`: up to 500 items in the background, with
  `Idempotency-Key`, polling or a signed webhook, and stored results.
- `POST {origin}/v1/videos`, then `GET /v1/videos/{{id}}` and `/content`: asynchronous video
  (Veo 3.1, Grok Imagine Video, Sora 2), with an optional `webhook_url`.
- `POST {origin}/v1/embeddings`, `/v1/audio/speech` and `/v1/audio/transcriptions`:
  `auto:embed`, `auto:tts` and `auto:stt` by default (scopes `embeddings` and `audio`).
- `GET {origin}/v1/media/providers`: which providers can run now, without cost.

Image and video requests use a proxy key with the `chat` scope. Stored media come back as
signed `/v1/media/files/...` links. Videos and large batches cost money; confirm with the
user first.

## MCP for coding agents
- [MultiLLM MCP]({origin}/v1/mcp): Streamable HTTP POST with `Authorization: Bearer $MULTILLM_API_KEY`.
  Tools: `list_models` (scope `models`), `chat`, `generate_image`, `generate_images_batch`,
  `create_video`, `get_video` and `media_providers` (scope `chat`).
- [MCP configuration]({origin}/agent-onboarding/mcp/config.json): Endpoint, protocol versions, scopes and tools.

`chat` defaults to `free:text`; other models and every image and video tool may cost money.
Each call makes one gateway request and is never retried. The Knowledge MCP is `/mcp`.

## Knowledge
- [Agent setup]({origin}/agent-onboarding): Copyable setup prompt and client configuration.
- [Setup prompt]({origin}/agent-onboarding/prompt.txt): Configure this service as the default knowledge entry point.
- [Machine configuration]({origin}/agent-onboarding/config.json): Endpoint, scopes and tool catalogue.
- [Full instructions]({origin}/llms-full.txt): Evidence, management, cost and retry contracts.
- [Knowledge MCP]({origin}/mcp): Streamable HTTP POST with a scoped Bearer proxy key.
- [Administrator dashboard]({origin}/knowledge): Sources, jobs, connections and allowances; login required.

Use knowledge:read for retrieval and retained artifacts; knowledge:manage for status,
sources, jobs and policy. Tools are filtered to the authenticated key's scopes.
Providers: Context7, Firecrawl, Exa, Mintlify Index, DeepWiki, Cloudflare AI Search,
and Firecrawl Alexandria. Availability depends on configured credentials and policy.
Alexandria discovery and inspection are free. Execution spends the discovered price;
report actual receipt costs and keep the same request ID after uncertain outcomes.

Public setup material contains no credentials, source inventory, or account status.
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

    @app.get("/agent-onboarding/media/SKILL.md")
    def media_agent_skill():
        return _download(_gateway_skill("multillm-media", "MultiLLM Media"))

    @app.get("/agent-onboarding/chat/SKILL.md")
    def chat_agent_skill():
        return _download(_gateway_skill("multillm-chat", "MultiLLM Chat"))

    @app.get("/agent-onboarding/mcp/SKILL.md")
    def mcp_agent_skill():
        # Configuration examples name this gateway instead of a placeholder origin.
        return _download(_gateway_skill("multillm-mcp", "MultiLLM MCP").replace("https://<gateway-origin>", _origin()))

    @app.get("/agent-onboarding/mcp/config.json")
    def mcp_agent_config():
        return jsonify({"name": "multillm", "transport": "streamable-http",
            "url": _origin() + gateway_mcp.ENDPOINT, "protocol_versions": list(gateway_mcp.PROTOCOL_VERSIONS),
            "accept": "application/json, text/event-stream",
            "authentication": {"type": "bearer", "env": "MULTILLM_API_KEY"},
            "skill_url": url_for("mcp_agent_skill", _external=True),
            "tools": gateway_mcp.tool_catalogue()})

    @app.get("/agent-onboarding/prompt.txt")
    def knowledge_agent_prompt():
        return _text(_setup_prompt())

    @app.get("/agent-onboarding/config.json")
    def knowledge_agent_config():
        return jsonify({"name": "multillm-knowledge", "transport": "streamable-http",
            "url": _origin() + "/mcp", "protocol_versions": list(knowledge_mcp.PROTOCOL_VERSIONS),
            "accept": "application/json, text/event-stream",
            "authentication": {"type": "bearer", "env": "MULTILLM_KNOWLEDGE_API_KEY"},
            "skill_url": url_for("knowledge_agent_skill", _external=True),
            "prompt_url": url_for("knowledge_agent_prompt", _external=True),
            "tools": tool_catalogue(), "providers": [name for name, _ in KNOWLEDGE_PROVIDERS]})
