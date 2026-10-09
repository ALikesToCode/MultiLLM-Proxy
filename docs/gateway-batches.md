# Gateway batches

The Batch API stores owned JSONL files and executes each item through the gateway's managed Chat Completions or Responses route. Both `GATEWAY_BATCHES_ENABLED` and `BATCH_SPILLOVER_ENABLED` default to `false`. Empty settings are off; malformed settings are off with one warning that omits the value. Disabled batch routes return 404 and normal generations continue unchanged.

Apply the gateway batch D1 migration before enabling `GATEWAY_BATCHES_ENABLED` in the Worker and Container. Storage uses `INTELLIGENCE_DB` and the existing `multillm_media` R2 binding. No extra binding or cron schedule is required. An enabled endpoint with missing tables or storage returns JSON 503 `gateway_batches_unavailable` before provider submission.

## Upload and create

Each UTF-8 JSONL line contains a unique `custom_id`, `method: "POST"`, a supported `url`, and a nonstreaming request `body` with a model. A file can contain at most 1,000 items and 10 MiB. Invalid input returns 400 `invalid_file` with the first bad line number. Other file purposes return 400. Requests must use a concrete priced model or a route whose every candidate has a known price; custom routing definitions are rejected.

```json
{"custom_id":"question-1","method":"POST","url":"/v1/chat/completions","body":{"model":"mimo:mimo-v2.5","messages":[{"role":"user","content":"Explain tides briefly."}],"max_tokens":128}}
```

Upload with an existing gateway credential in your client environment:

```sh
curl "$GATEWAY_URL/v1/files" -H "Authorization: Bearer $GATEWAY_KEY" \
  -F purpose=batch -F file=@input.jsonl
```

Create a batch using the returned file ID:

```json
{"input_file_id":"file_RETURNED_ID","endpoint":"/v1/chat/completions","completion_window":"24h","metadata":{"multillm_budget_usd":"0.50"}}
```

Send this JSON to `POST /v1/batches`. All items must match `endpoint`, which accepts `/v1/chat/completions` or `/v1/responses`. The budget is required: a positive decimal string of at most 100000 USD with at most ten fractional digits. Metadata accepts at most 16 string values, with keys up to 64 and values up to 512 characters. Unknown prices fail creation with 400 `unknown_price`. Model permissions apply at creation and execution.

Explicit output limits must be integers from 1 to 262144 tokens; completion count `n`, when present, is from 1 to 16. Admission uses input JSON byte count and the largest output bound, multiplied by `n`, rounded upwards in units of 0.0000000001 USD. Without an output limit, admission conservatively reserves 262144 output tokens. Set an explicit output limit to keep the reservation useful. This is a gateway spend bound, not a provider batch discount or a guarantee of provider billing accuracy.

## Read, cancel and delete

`GET /v1/files` and `GET /v1/batches` return list objects with `data`, `first_id`, `last_id`, and `has_more`. They accept `limit` from 1 to 100 and an `after` ID. File metadata is available at `GET /v1/files/<id>`; bytes at `GET /v1/files/<id>/content`; deletion at `DELETE /v1/files/<id>`. Every operation is restricted to the authenticated owner, including administrators. Another owner's ID returns 404. An input file used by an active batch cannot be deleted (409 `file_in_use`). Existing media routes remain unchanged.

`GET /v1/batches/<id>` returns the batch object, timestamps, request counts, and output/error file IDs. `POST /v1/batches/<id>/cancel` stops new work; already dispatched items finish and remain recorded. Cancellation moves through `cancelling` to `cancelled`. Normal execution moves through `validating`, `in_progress`, `finalizing`, and `completed`. Expiry stops unfinished work 24 hours after creation and ends as `expired`. Individual failures appear in the error file; a completed batch can contain failed items.

Output and error files contain JSONL records keyed by `custom_id`, with `response` and `error` fields. They use the same owned file APIs. Individual results are limited to 1 MiB; aggregate output and error content are bounded at 16 MiB each. Oversized results become errors and are never retried. API files remain stored until their owner deletes them; the 24-hour completion window is not file retention expiry. Intermediate result objects and assembly checkpoints persist independently under `batches/`; there is no automatic TTL or batch deletion endpoint.

## Execution and recovery

The existing Worker scheduler claims at most two items per invocation using an atomic D1 lease and spend hold. Each item has a 30-second deadline; the invocation has a 65-second work budget. Remaining items continue on the next invocation. Completion time depends on the configured cron frequency and the two-items-per-run limit. A single shard processing 1,000 items needs at least 500 invocations.

The scheduler sends the Container an expiring, signed owner capability and an item lease. It does not store or replay the owner's API credential. The Container consumes the durable lease once, loads canonical content from batch storage, reloads the owner's current account, and checks key rotation, expiry, original client-IP restrictions, scopes, model permissions, rate limits, budget, and retention. It invokes the real managed route with its dispatch, conversion, validation, cache, accounting and cancellation machinery. A missing or revoked account cannot execute. The private item route rejects unsigned calls.

Measured spend replaces each known hold. Missing usage, an uncertain provider result, lost transport, or an expired dispatched lease produces `outcome_unknown` and preserves the hold. That item is never dispatched again. Result-storage failures also retain the hold conservatively. Once measured plus held spend reaches the batch budget, further items fail `budget_exhausted`; an item that would exceed the remaining budget is also refused before dispatch. A pricing increase beyond its reserved estimate fails before dispatch. Finalization uses durable checkpoints so output assembly can continue after a scheduler interruption.

Batch items cannot request context paging: with paging on, an item that sends the `multillm_context_retrieve` capability fails with 400 `context_paging_unsupported` before dispatch, because page handles belong to the caller's API key and stored work never holds that key.

Zero-content retention rejects upload, batch creation and spillover with 400 `retention_conflict`. Current retention is checked again before executing stored work. Content lives only under the R2 `batches/` prefix; D1 stores ownership, opaque signing capability, control identifiers, status, spend, leases and content pointers. Scheduler warnings omit prompts, completions, credentials and transport details.

## Explicit asynchronous submission

With both flags enabled, a managed `POST /v1/chat/completions` containing both `X-MultiLLM-Priority: batch` and `Prefer: respond-async`, plus `metadata.multillm_budget_usd`, creates a real one-item batch and returns HTTP 202. Its `Location` header points to `/v1/batches/<id>`. Without both headers, or with spillover disabled, the request follows the existing synchronous path. Submission is explicit; overload does not queue a request automatically.
