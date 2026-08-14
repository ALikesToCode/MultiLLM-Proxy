# Automatic model priorities

MultiLLM exposes explicit virtual Chat Completions models in the
`auto:<name>` namespace. Each virtual model stores an ordered list of normal
`provider:model` candidates. This keeps fallback policy visible and editable
without changing any direct provider route.

The first startup seeds this route:

1. `nanogpt:glm-5.2`
2. `opencode:glm-5.2`
3. `navyai:glm-5.2`

Use `auto:glm-5.2` with the normal unified endpoint:

```bash
curl "$PROXY_BASE_URL/v1/chat/completions" \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "auto:glm-5.2",
    "messages": [{"role": "user", "content": "Hello"}],
    "stream": true
  }'
```

`GET /v1/models` includes every saved virtual model with
`owned_by: multillm-auto`, built-in provider models, and IDs retained from the
last successful live provider-catalog refresh. Automatic models also work through
`POST /optimize/v1/chat/completions`. Images and the Responses API still
require an explicit `provider:model` because their request and stream
contracts differ across providers.

The authenticated `/docs` route presents the same combined catalog alongside
copyable chat and image requests, runtime credential status, native provider
paths, and the currently saved automatic priorities. `/docs.json` exposes the
credential-safe guide data to an authenticated dashboard session.

## Edit priorities in the dashboard

Sign in as an administrator and open **Operations**. The **Automatic model
priorities** panel can:

- reorder candidates with Up and Down controls;
- add any provider/model ID supported by the unified Chat route;
- remove a candidate from the pending order;
- create additional virtual models such as `auto:kimi-k3`; and
- show whether each provider currently has a configured server credential.

Saving writes the complete order to the SQLite database selected by
`MODEL_REGISTRY_DB_PATH`. There is no separate routing configuration file.
Container or serverless deployments that place this database in `/tmp` lose
dashboard changes when that ephemeral filesystem is replaced; use durable
storage before relying on saved priorities in production.

The authenticated dashboard API is `GET` and `PUT /admin/auto-routes`. A PUT
body has this shape:

```json
{
  "route_id": "auto:glm-5.2",
  "candidates": [
    "nanogpt:glm-5.2",
    "opencode:glm-5.2",
    "navyai:glm-5.2"
  ]
}
```

The browser sends the normal session cookie and CSRF token. The API returns
configuration state only and never returns provider keys.

The dashboard includes the exact environment-variable names for every provider.
For the default priority route, a local setup can use:

```dotenv
OPENCODE_GO_API_KEY=your-key
NANOGPT_API_KEY=your-first-key
NANOGPT_API_KEY_1=your-second-key
NAVYAI_API_KEY=your-key
```

Restart the proxy after changing its environment. Hosted deployments require
the same values in their runtime secret store; changing a repository `.env`
file does not update an already deployed Worker or container.

**Refresh live models** calls `POST /admin/auto-routes/catalog`. It performs
read-only model-list requests only for configured providers, caches successful
model IDs in `MODEL_REGISTRY_DB_PATH`, and preserves the last good catalog when
a provider is unavailable. The searchable dashboard catalog combines those live
IDs with built-in IDs and models already referenced by saved routes. Provider
keys and upstream error bodies are never returned to the browser.

## Failover boundary

MultiLLM advances to the next locally available candidate only when the
current attempt returns a definite pre-generation availability rejection:

- `401` or `403`: provider credential rejected;
- `402`: provider balance or payment requirement prevents generation;
- `404`: provider/model unavailable;
- `429`: provider rate limit reached; or
- a local `503` marked with `X-MultiLLM-Circuit-State: open` or `half_open`,
  which means no upstream request was sent.

Disabled models and providers without a configured credential are skipped
before transport. The first response outside this list is returned unchanged,
including `400`, `408`, generic `5xx`, network failures, and successful stream
starts. Those outcomes may be ambiguous after a paid generation began, so the
proxy does not replay them through another provider. It never fabricates a
successful fallback body.

Every selected response includes:

- `X-MultiLLM-Auto-Route`
- `X-MultiLLM-Auto-Selected-Model`
- `X-MultiLLM-Auto-Attempts`
- `X-MultiLLM-Auto-Selected-Priority`

The standard `X-MultiLLM-Provider`, `X-MultiLLM-Model`, and
`X-MultiLLM-Route-Decision` headers report the actual selected candidate and
whether it was the primary route or a failover.

## NanoGPT key pools

Unified NanoGPT Chat, Responses, and image requests use the same configured
key pool as direct `/nanogpt/*` routes. The process checks the read-only model
catalog when more than one key is configured and retains the first working key
for the configured TTL. A `401`, `403`, or `429` invalidates that key for a
later request.

An automatic request does not replay the same paid generation against another
NanoGPT key. After a NanoGPT rejection it advances to the next provider in the
virtual model. A `402` insufficient-balance response also advances without
replaying NanoGPT. A later request can select another working NanoGPT key.

Provider catalogs change over time. Query `/nanogpt/v1/models`,
`/opencode/v1/models`, and `/navyai/v1/models`, then enter the exact returned
IDs in the dashboard rather than assuming that similarly named models use the
same ID everywhere.
