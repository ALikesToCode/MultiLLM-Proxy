"""Credential-free integration instructions for the deployed gateway."""


def build_agent_setup_prompt(base_url: str) -> str:
    return f"""Integrate my application with MultiLLM Proxy.

Gateway origin: {base_url}
OpenAI-compatible SDK base URL: {base_url}/v1
Credential environment variable: MULTILLM_API_KEY
Agent skills: {base_url}/agent-onboarding/chat/SKILL.md (chat from code),
{base_url}/agent-onboarding/media/SKILL.md (images, image batches, video),
{base_url}/agent-onboarding/mcp/SKILL.md (models, chat and media as MCP tools at
{base_url}/v1/mcp) and {base_url}/agent-onboarding/SKILL.md (Knowledge).
Discovery index: {base_url}/llms.txt

1. Inspect the application's existing client and configuration before editing.
   Reuse its conventions and preserve unrelated work.
2. Read MULTILLM_API_KEY from the application's secret environment. It must be
   a MultiLLM client key, not an upstream provider key. If missing, ask me to
   configure it securely. Never print it, commit it, or put it in browser code.
3. Discover exact available model IDs with GET {base_url}/v1/models using
   Authorization: Bearer $MULTILLM_API_KEY. Choose a model appropriate for my
   task from the returned catalog; do not invent IDs or assume availability.
4. For chat, POST {base_url}/v1/chat/completions with the discovered model,
   messages, and optional stream=true. Preserve the complete provider:model ID
   on unified routes. Use an auto:name route only when it exists in the catalog
   and I want automatic routing. An SDK base URL ends in /v1; a raw HTTP request
   uses the complete endpoint. Do not append /v1 twice.
5. Select other contracts only when my task needs them: /v1/responses for
   Responses-compatible clients; /v1/images/generations with model auto:image
   (the best image model, quality max, falling back across providers) or an
   explicit image model; /v1/images/batch for several prompts or sizes; and
   /v1/videos for asynchronous video jobs (poll /v1/videos/{{id}}, then download
   /content). Check model capabilities and the setup guide at {base_url}/docs.
   The guide and /docs.json require dashboard login, not just an API bearer key.
   Provider-native routes have their own model IDs, protocols, and permissions;
   do not switch to them automatically or assume a user key grants admin access.
6. Keep credentials on the server. Handle HTTP errors and SSE completion or
   interruption explicitly. Disable automatic retries of generation POSTs:
   a timeout or 5xx can follow billable work, and the proxy provides no
   idempotency guarantee. Automatic routes already fall back between providers.
7. Verify configuration and model discovery first. Run a minimal generation
   only within my task's authorized scope. Report the selected endpoint and
   model, checks performed, and any failures without exposing credentials.

For explicit technical evidence retrieval, use POST {base_url}/v1/knowledge/context
or POST {base_url}/v1/knowledge/search with a key granted knowledge:read in Access.
Send query, optional product/version/repository, mode (economy, smart or deep),
token_budget, and freshness (normal or fresh). Inspect citations, observed version
evidence and coverage gaps; requested versions are not proof of compatibility.
Remote MCP uses stateless Streamable HTTP at {base_url}/mcp with the same scoped
Bearer key. Its tools are knowledge_context and knowledge_search. Never put the
key in a URL. A Knowledge-only key does not grant chat or model-discovery access.
Operators configure sources, providers and allowances at {base_url}/knowledge.
Retrieval remains disabled until the private service, required Cloudflare resources,
provider credentials and finite allowances are configured. A setup_needed or
upstream failure is not an empty successful search. Disable automatic retries
of potentially billed retrieval and indexing operations.
"""
