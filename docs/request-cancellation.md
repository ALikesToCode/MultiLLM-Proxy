# Disconnect-aware upstream cancellation

Cleanup is always enabled. There is no environment flag or disabled mode.
Successful bytes, status codes and headers are preserved. No response content,
credentials or request bodies are added to cancellation outcomes or logs.

For example, closing a streaming client before its first event, after a partial
event, or while waiting for the next event closes the upstream owner once.
Reading the whole response keeps its original bytes. Aborting after a completed
response does not change that completed outcome.

## Python transport

`bind_cancellation(response, on_outcome=callback)` attaches a
`CancellationContext` to `response.multillm_cancellation` and shares its
idempotent close operation with existing owners. `iter_stream_content` and
`iter_stream_lines` return closable iterators immediately, before generator
execution. `GeneratorExit`, read exceptions, normal exhaustion and redundant
close calls release the upstream once. A socket error propagates; it does not
restart reads through a different iterator.

Unified dispatch binds each returned response without changing request bodies
or existing origin-fallback policy. Flask body ownership closes the underlying
iterable even when no body iteration occurred. The stream preflight (`preflight_chat_stream`)
closes that same owner on rejection; validated prefix replay keeps the same
owner.

WSGI detects disconnects during writes or iteration. It cannot reliably detect
a disconnect while a synchronous provider setup or socket read is blocked.
Existing bounded connect/read timeouts remain in force. No per-request watcher
thread is created, and cancellation cannot promise the provider stopped billing.

## Worker transport

`UpstreamCancellation` owns an AbortController, a bounded header timer, the
parent abort listener and an upstream reader. Parent abort propagates to fetch
through its signal. The listener remains active after headers until the body
finishes or closes. Cancelling a downstream body also aborts fetch and cancels
the upstream reader once. Cleanup does not wait for a provider's cancellation
acknowledgement. `readBoundedUpstreamBytes` owns cancellation and reader release
for bounded nonstream reads, including abort and size rejection.

Roleplay uses this owner for generation and compaction. A client abort, including
one racing an HTTP rejection, stops candidate and origin fallback. Existing
non-cancellation fallback decisions remain unchanged. Terminal HTTP error bodies
retain their owner until consumption or cancellation instead of detaching at
headers. Header timers end at headers; compaction retains its total timer.

## Outcomes and settlement

Python callbacks receive `CancellationOutcome`; Worker callbacks receive an
object with `reason`, `ambiguous`, `usageState`, `usage` and `replayPermission`.
Python also reports an [`UpstreamOutcome`](upstream-outcomes.md). After upstream handoff,
cancellation or interruption is ambiguous, usage is unknown (`None`/`null`),
and replay permission is false. Nothing here asserts zero tokens or zero cost.
Callbacks run once and contain no generated content. Cleanup errors are logged
by type only and do not mask the original result.

These are transient transport outcomes, not durable accounting records. Flask request
accounting records a managed request whose stream was cancelled after handoff with
status 499 and unknown usage instead of its original status; the in-flight budget
estimate is then released as for any other request without measured usage.

## Coverage

Unified dispatch, the stream preflight and the roleplay transport use these
owners. Other native Worker provider fetches and the provider-specific streaming
paths in `services/proxy_service.py` keep their existing connect and read
timeouts. Whether a provider stops billing after a disconnect depends on that
provider.
