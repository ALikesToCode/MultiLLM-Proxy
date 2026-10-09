# Reversible context paging

Context paging replaces complete older conversation exchanges with retrieval handles.
It preserves the exact JSON body of each stored exchange, including whitespace and
Unicode in message content, tool-call IDs, arguments, and tool results. It does not
summarize history or invent a tool call. System and developer messages, incomplete
exchanges, explicitly protected indices, and the latest user exchange remain in full.

Paging is off by default. Leave `CONTEXT_PAGING_ENABLED` unset, empty, or `false` to
keep existing traffic and storage unchanged. Invalid flag values disable paging and
produce one warning containing only the setting name. Raw forwarding is unchanged.

## Enable for a managed client

Apply the context-pages migration before setting `CONTEXT_PAGING_ENABLED=true`.
The deployment must expose the authenticated context retrieval route and private
storage operation, and supply verified principal, session, current policy revision,
current chat/tool grants, and retention decisions to the managed dispatch path.
The same existing `multillm_media` R2 bucket holds bodies under `context-pages/`;
`INTELLIGENCE_DB.context_pages` holds metadata. There are no additional bindings.
The existing media signing secret (or Flask signing secret) signs page handles.

A managed client explicitly declares retrieval capability:

```json
{
  "model": "provider:explicit-model",
  "capabilities": ["multillm_context_retrieve"],
  "messages": [
    {"role": "user", "content": "Older complete exchange"},
    {"role": "assistant", "content": "Older answer"},
    {"role": "user", "content": "Current request"}
  ]
}
```

Only exchanges that need paging to fit the candidate's input window are stored.
The upstream messages contain a handle marker instead of the old group, plus the
`multillm_context_retrieve` function schema. Page metadata returned to the client is
`{page_id, sha256, expires_at, tool_schema}`; expiry is a Unix timestamp. The managed
response exposes this as `context_pages`. No body or base64 blob is attached to the
upstream generation request. The explicit model and output reservation are preserved.

Retrieve only when needed by calling `multillm_context_retrieve({"page_id":"cp_..."})`
or making an authenticated `GET /v1/context/pages/cp_...`. The caller's current grants
and policy revision must still authorize access; a handle alone does not grant access.
The route returns `page_id`, `sha256`, `expires_at`, `messages`, and `body_base64`.
`body_base64` decodes to the exact UTF-8 bytes that were hashed and stored. Responses
use `Cache-Control: private, no-store`. Retrieving does not dispatch a provider call;
the client chooses whether to include restored content in a later generation.

With the flag off, the same request keeps its original history and does not write
pages. A client without the capability also keeps its existing behavior. Zero-content
retention disables paging before any storage call and denies retrieval of existing
pages for that request. Changing policy does not delete earlier retained objects.

## Bounds and errors

- Each page holds at most 64 KiB; active pages hold at most 1 MiB per principal/session.
  The D1 limit check and all metadata inserts run in one statement, so competing
  writers cannot exceed the session allowance. Candidate plans reuse identical pages
  within one request.
- Pages expire after 3,600 seconds. Every retrieval checks expiry, ownership, session,
  current revision, the HMAC, byte length, and SHA-256 before exposing content.
- HTTP 413 `context_window_exceeded` means protected content and handles cannot fit
  the candidate window after reserving output and safety tokens. Nothing is silently
  truncated. Oversized pages/session content also return 413.
- HTTP 404 covers disabled retrieval, absent, expired, foreign, or stale-revision
  handles. HTTP 403 covers missing current grants or zero retention.
- HTTP 503 JSON reports unavailable D1 tables, R2 bindings, signing configuration,
  authority, or storage, and corrupted bodies. Generation must stop before dispatch.
  Failed storage is never permission to truncate, summarize, or replay a generation.

Token estimates use serialized UTF-8 byte counts, not a provider tokenizer. Retrieval
can increase a later request's input cost; paging does not authorize a model or budget
change. Configure an R2 lifecycle rule for `context-pages/` according to retention
policy: expiry denies access immediately, but physical storage cleanup follows that
rule. D1 metadata may be retained for operations; expired metadata does not count
against the active session allowance. No prompt or retrieved body is logged.
