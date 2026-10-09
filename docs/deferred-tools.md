# Deferred tool discovery

`DEFERRED_TOOLS_ENABLED=false` is the default. Empty values also disable it. Invalid values disable it and emit one warning containing only the setting name. While disabled, tool lists, calls, schemas, responses, headers and storage access follow the existing MCP behavior; `multillm.tools.discover` returns the existing method-not-found error.

Enable the feature only after applying `0018_tool_grants.sql`. Flask reads grants through the fixed private `tool_grants` read operation on the existing model-state endpoint or an injected `app.extensions["deferred_tools"]` service. Worker uses `INTELLIGENCE_DB`. There is no fallback to local grants, public scopes alone or stale cached permissions. Missing storage or a missing table returns JSON HTTP 503 before execution. The private read also returns HTTP 503 when deferred tools are disabled in the Worker.

## Explicit discovery

Send a JSON-RPC request to the gateway MCP endpoint `/v1/mcp` or the Knowledge MCP endpoint `/mcp`:

```json
{"jsonrpc":"2.0","id":1,"method":"multillm.tools.discover","params":{"query":"model search","limit":4}}
```

The result contains `tools`, each with its complete `inputSchema`, and `_meta.contract_digest` from the existing MCP contract digest implementation. `nextCursor`, when present, can be used with the same query and limit:

```json
{"jsonrpc":"2.0","id":2,"method":"multillm.tools.discover","params":{"query":"model search","limit":4,"cursor":"<nextCursor>"}}
```

Queries must be nonempty, at most 500 characters, and contain no control characters. Limits are integers from 1 to 16; the default is 16. Unknown options are rejected. Ranking matches words in names, titles and descriptions locally, with deterministic ties by tool name. Permissions are filtered before ranking. A query without matches returns an empty tool list. No embedding, remote classification or provider call is made.

A discovery response, including its JSON-RPC envelope, is bounded to 64 KiB. Pagination includes whole schemas only. A schema that cannot fit returns `tool_schema_too_large` (HTTP 413); it is never shortened or replaced. The existing canonical contract implementation also imposes its catalogue byte, node and depth limits. `tools/list` continues to return the entire authorized set, subject to the existing Knowledge toolset selector. Existing contract digest metadata and contract pins remain supported.

## Grants and calls

`tool_grants` stores principal ID, exact tool name, explicit scopes, allow/deny and row revision. The additive migration creates explicit compatibility rows for the current public tools and their existing required scopes. The `*` principal applies those rows to existing scope holders; it does not grant arbitrary tools or new scopes. An exact principal/tool row overrides its compatibility row, including a denial. New tools without a row are denied by default. Administrators must still have a grant; administrator scope does not bypass an explicit denial. Existing rows survive repeated migration execution.

`tools/call` rereads grants and validates the full runtime schema, including when the tool was never advertised to the caller. Discovery does not grant permission or execute anything. Flask uses its existing JSON Schema validator. Worker preflight validates the static catalogue's `type`, `required`, `properties`, `additionalProperties`, string length and pattern, `enum`, numeric bounds, `items`, array length and uniqueness, `anyOf` and `oneOf` constraints. `default` and `description` are annotations and never change arguments. Unsupported or malformed schemas return `tool_validation_unavailable` (HTTP 503), including unsupported keywords in unused branches. Validation is bounded to depth 32, 8,192 schema and argument nodes, 262,144 string code units and 65,536 work steps; exceeding a bound also returns HTTP 503. Patterns are limited to 512 code units and come from the static catalogue. Existing operation-specific permission checks still apply, including provider options requiring management scope. Grant changes should increment the row revision and the existing `model_grants` control revision in the same transaction.

With revision-aware configuration sync enabled, Flask binds cursors to its confirmed, fresh `model_grants` revision; unavailable or stale revision metadata returns HTTP 503. Worker reads the same control revision with the grant snapshot. With configuration sync disabled, each process or Worker isolate uses a stable random revision for its lifetime. Cursors also bind the observed grant rows, so revocations invalidate them even without configuration sync.

Cursors are HMAC-signed and bind the authenticated principal and scopes, authorized tool contract digest, grant revision, observed grant rows, query, limit and page offset. Their maximum lifetime is 120 seconds from the first page; pagination does not renew it. A changed principal, scope, tool contract, toolset, grant or revision invalidates the cursor. Process restarts and movement to another isolate also invalidate it because signing keys stay only in memory. Start discovery again on `invalid_cursor` (HTTP 400). A concurrent grant change while preparing a page returns `tool_grants_changed` (HTTP 409).

## Errors, cost and retention

Denied calls return `tool_not_granted` (HTTP 403); invalid arguments return HTTP 400. Disabled discovery returns JSON-RPC `-32601`. Missing grant storage and missing validation collaborators return JSON HTTP 503. Errors do not expose rejected arguments, schema contents or storage exception text. Discovery never retries a tool call and does not change billing or provider retry rules. Explicit tool execution retains its existing cost and scope requirements.

Only content-free grants and revisions are persisted. Queries and cursors are not stored by this feature and no prompt, response or query content is logged. Signing keys are generated internally and are never stored or returned. Storage reads are bounded to 4,096 applicable grant rows; malformed or oversized grant snapshots fail closed.
