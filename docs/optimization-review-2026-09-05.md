# Runtime optimization and experience review

Date: September 5, 2026. Source baseline: `02d99606d8438918c910c14e3036401a5d948f79`.

## Conclusion

Prioritize bounded stream recovery, accurate completion telemetry, and linear-time
reasoning normalization before changing models or increasing infrastructure.
The largest experience risks are requests that appear alive without progressing,
requests waiting behind them, and metrics that cannot distinguish those states.

This is an architecture-wide source review with deeper inspection of request hot
paths, local synthetic probes, and the existing test suites. It is not a production
load test, a visual accessibility audit, or proof of the cause of a particular
Janitor/network failure. No runtime, provider configuration, or deployment changes
are part of this report.

## Coverage and baseline

The source inventory contains 214 tracked Python/JavaScript files and 65,479 lines,
including tests. Configuration, templates, deployment scripts, and relevant design
and provider documentation were also inspected.

| Area | Main responsibilities reviewed |
| --- | --- |
| Worker | Edge dispatch, CORS/preflight, direct routes, container forwarding |
| Roleplay | Session queue/storage, history, compaction, routing, reasoning, output budgets, streaming, recovery, metrics |
| Python data plane | Provider adapters, unified/raw routes, pooled transport, response conversion, stream handling |
| Control plane | Authentication, rate limits, SQLite access, model catalogs, auto routes, usage and request metrics |
| Interface | Operations updates, endpoint/configuration discovery, OpenRouter lab, shared copy behavior, offline asset caching |
| Delivery | Container startup, Worker configuration, CI, dependency manifests, tests, secret exclusions |

Two paths need separate measurements:

```text
Client -> Worker -> roleplay session -> provider
                                   -> container -> selected OpenCode provider

Client -> Worker -> Python container -> unified/raw provider transport
                                    -> dashboard and SQLite control plane
```

Native roleplay does not normally traverse Flask. Improving Python authentication
will not improve a direct NanoGPT roleplay request. OpenCode roleplay uses container
egress when the corresponding binding and credential are present.

Verification:

- All 22 Worker test files passed.
- Python suite: 596 tests and 314 subtests passed; two additional tests initially
  failed because socket creation was sandbox-blocked. Both passed on a targeted
  loopback-enabled rerun with synthetic data. This was not a single all-green run.
- Ruff fatal checks passed. The configured mypy checks passed for 52 source files;
  their disabled checks and untyped bodies limit that assurance.
- Tailwind build passed in an isolated source snapshot. Static secret scan passed.
- Local runtimes were Node 26.8.1 and Python 3.12.13, whereas CI specifies Node 22
  and Python 3.11. Version-matched CI remains necessary before implementation ships.
- Python tests used an exported source snapshot with an empty inherited environment,
  not the working checkout's private environment files. Stream probes used mocked
  providers. No production inference benchmark was performed.

## Prioritized findings

### 1. High: give each turn a progress deadline and a cancellation-aware queue

Evidence: [transport](../worker/roleplay/transport.mjs#L515),
[stream loop](../worker/roleplay/streaming.mjs#L232),
[session queue](../worker/roleplay/endpoint.mjs#L356).

The header timeout is cleared once upstream headers arrive. After that, the
observed stream races reads against heartbeat timers, but has no upstream idle
deadline or total turn deadline. Heartbeats keep the downstream connection active
without proving model progress. The session queue waits for the entire completion
promise before releasing the next turn; it has no admission limit or queue deadline.
An aborted queued request is not handled until its predecessor completes.

A synthetic upstream returned headers and one comment, then stopped producing
bytes without closing. Approximately nine seconds later, three generated keepalives
had been delivered, only one upstream call existed, and two turns remained pending.
The canceled second request was still unresolved. Canceling the first released it;
the second then returned 502 rather than a distinct cancellation result.

Recommendation:

- Separate header, upstream-progress, queue, and overall turn budgets. Count
  provider reasoning/content progress separately from transport comments.
- Preserve a generous configurable reasoning budget; do not equate hidden reasoning
  with inactivity or silently lower reasoning effort to meet a deadline.
- Bound pending turns and race queued waits against cancellation. Preserve ordering
  when removing a queued turn; releasing it must not let later writes overtake the
  active turn.
- Return a stable cancellation/busy/incomplete classification. After visible output,
  preserve the partial response and require explicit recovery instead of silently
  replaying a paid request.
- Apply a shared elapsed-time budget across candidate attempts and continuations.
  The configured 90-second header limit currently applies per attempt, not per turn.

Acceptance: stalled/comment-only providers terminate predictably; canceled queued
turns release promptly; subsequent turns work; partial-output failures never look
like successful completion; recovery does not duplicate upstream calls.

### 2. High: measure readable output and completed streams, not just successful headers

Evidence: [Worker measurement](../worker/roleplay/streaming.mjs#L170),
[first-byte capture](../worker/roleplay/streaming.mjs#L544),
[Python recording](../routes/proxy.py#L431),
[metrics store](../services/metrics_service.py#L19),
[session metrics](../worker/roleplay/session-metrics.mjs#L36).

Worker TTFB is genuinely first upstream byte, including comments. It is not
time-to-first-token or time-to-readable-story. A local probe recorded approximately
0 ms TTFB while first content arrived at 80 ms. Generation duration also starts at
the first raw byte, and usage combines whatever completion-token count the provider
reports. This cannot be compared directly with a provider's advertised decoding TPS.

Several Python paths record the upstream HTTP status and elapsed time before
consuming the stream. A later body failure can therefore leave a successful, short
request in dashboard metrics. `ttft_ms` and `actual_cost` exist in the metrics API
but no production caller supplies those keyword arguments. Process-local metrics
retain only the latest 10,000 requests. Worker roleplay metrics live separately in
each session; the dashboard is not a unified view of native Worker traffic.

Recommendation: use one sanitized completion-event contract across both paths:
request/attempt identifiers, route/provider/model, billing mode, effective reasoning
effort, queue/preparation/header timings, first reasoning, first visible content,
completion duration, reported token categories, continuation count, and terminal
outcome. Finalize stream success on a valid terminal result, not HTTP 200 alone.
Keep prompts, response bodies, and credentials out of telemetry.

Show p50/p95 visible TTFT, completed-turn latency, failure rate, sample count, and
the observation window. Label process-local and session-local coverage explicitly.

### 3. High: remove quadratic reasoning-normalization work

Evidence: [reasoning accumulation](../worker/roleplay/reasoning-output.mjs#L241).

Each reasoning delta appends text and then recomputes the comparable form of the
entire accumulated reasoning string. Long histories of small deltas repeatedly
scan an expanding prefix. Replay detection also scans accumulated text.

Synthetic benchmark of the actual normalizer, median of three runs per size:

| Reasoning frames | Local CPU time |
| ---: | ---: |
| 2,000 | 73 ms |
| 4,000 | 294 ms |
| 8,000 | 1,146 ms |

Each frame contained a unique `reasoning_content` fragment of the form ` wordN`.
Four times the frames took roughly sixteen times the CPU time. These are local
microbenchmark results, not production wall-clock savings or upstream token rates.

Recommendation: normalize new deltas incrementally, retain whitespace/tag parsing
state, and bound the overlap/replay search window. Treat explicit token deltas and
cumulative replay payloads as different inputs. Preserve legitimate repeated words,
split tags, cumulative reasoning, Unicode, and exactly one balanced visible think
block. Add a scaling benchmark alongside the existing correctness cases.

Acceptance: near-linear scaling at 2k/4k/8k/16k frames with byte-for-byte equivalent
output for the existing supported cases. Do not achieve speed by discarding reasoning.

### 4. Medium: make speed-routing policy match its name and expose its constraints

Evidence: [ranking](../worker/roleplay/config.mjs#L636),
[quality guard](../worker/roleplay/quality-routing.mjs#L41),
[forwarded options](../worker/roleplay/memory.mjs#L264).

Candidates are grouped by provider priority before score ordering. In a synthetic
`glm-speed` example, the preferred provider stayed first with score 112,400 while
another provider scored 5,220; lower scores are preferred. This preserves explicit
provider order but is not global fastest-route selection. Plain `speed` also retains
model routing rank ahead of its throughput score. Statistics are session-local, so
new sessions cannot use another session's established latency evidence.

Recommendation: distinguish `provider-priority`, `fastest-eligible`, `quality`, and
`pinned` policies. Preserve the current priority policy for existing configurations.
Let fastest-eligible compare only explicitly allowed providers/models/billing modes,
using predicted completed-turn time plus failure risk rather than raw TPS alone.
Include sample freshness and comparable context/output/reasoning buckets.

The roleplay payload allowlist does not forward arbitrary sub-provider selection
options. NanoGPT subscription protection also deliberately removes options that can
select PAYG routing. Do not add unrestricted sub-provider pinning merely to reproduce
a marketplace TPS figure; preserve the billing boundary and verify the provider's
current contract before offering such an option.

### 5. Medium: keep dashboard connections from consuming chat capacity

Evidence: [startup settings](../scripts/cloudflare-entrypoint.sh#L16),
[status stream](../routes/core.py#L770),
[dashboard polling](../static/js/dashboard.js#L538).

The supplied startup defaults are one Gunicorn worker and eight threads. Every
`/status/updates` connection runs an indefinite synchronous generator with a sleep
loop. Dashboard streams and container-backed chat streams share that finite request
capacity. Multiple open dashboards can exhaust the default thread budget before
provider throughput is the bottleneck. Native Worker/NanoGPT roleplay is a separate
path, but OpenCode roleplay and container routes can contend here.

Recommendation: serve a cached, bounded dashboard snapshot with visibility-aware
polling, or move live fan-out to a transport that does not reserve Flask request
threads. Compute shared aggregates once per interval. Pause hidden-tab updates and
prevent overlapping polls. The current `Polling only` state does not implement
fallback polling for the full dashboard, only the separate request log.

Acceptance: test several dashboards plus concurrent chats against the real startup
configuration; health and chat admission remain responsive. This contention risk
was established from the code/configuration, not a production concurrency test.

### 6. Medium: reduce Python authentication and SQLite hot-path work safely

Evidence: [key verification](../services/auth_service.py#L802),
[usage update](../services/auth_service.py#L774),
[auto-route reads](../services/auto_route_service.py#L217),
[rate-limit transactions](../services/rate_limit_service.py#L386).

Every API-key verification loads a database record, verifies a password-style hash,
and synchronously persists usage metadata. Twelve sequential synthetic admin-key
checks measured 45.4 ms median and 46.4 ms maximum locally, without a provider call.
Auto-route reads run schema/default initialization, including writes, before reading
the requested route. Rate-limit admission also performs retention cleanup inside
its write transaction.

Recommendation: profile these stages under realistic concurrency, then separate
schema/default migrations from steady-state reads; schedule bounded retention work;
and coalesce nonessential last-used metadata updates. For authentication, consider
a bounded keyed-digest verification cache only with tested rotation/revocation
invalidation, or a reviewed verifier design appropriate for high-entropy API keys.
Do not weaken password hashing, store plaintext keys, or cache authorization without
a revocation strategy. Quota admission must remain atomic.

### 7. Medium: make frontend updates and interrupted requests trustworthy

Evidence: [asset cache](../static/service-worker.js#L80),
[OpenRouter stream reader](../static/js/openrouter.js#L98),
[stream rendering](../static/js/openrouter.js#L144),
[copy handling](../static/js/app.js).

- Unversioned application assets are cache-first. Changed JS/CSS can remain stale
  until the service-worker cache version is changed. Cache misses store responses
  without checking success, so an error response can also be cached.
- Service-worker activation deletes every other cache name on the origin, not just
  caches owned by this application.
- OpenRouter lab treats EOF without a terminal marker as normal completion, does
  not surface SSE error objects through its content callback, and has no abort
  control. A thrown stream error replaces the displayed partial response.
- OpenRouter replaces the full response DOM on every content delta. Shared copy
  handling announces success even when its legacy clipboard fallback returns false.

Recommendation: use build-versioned assets and application-scoped cache cleanup;
cache only valid responses. Add Stop, distinguish interrupted/error/complete states,
retain partial text, and provide explicit Retry. Append or batch text updates to a
frame cadence. Report clipboard failure honestly. Add browser behavior tests for
stale assets, missing terminal frames, error events, cancellation, and partial text.

### 8. Architectural prerequisite: durable control-plane state before scaling out

Evidence: [container database defaults](../cloudflare-worker.mjs#L284),
[documented persistence boundary](deployment-cloudflare.md#important-state-limitation).

The supplied container configuration puts auth, rate-limit, and model-registry
databases under `/tmp`. The deployment documentation explicitly identifies the disk
as ephemeral and warns that users, rotated keys, model overrides, and usage history
can disappear on restart. Roleplay Durable Object state has a different persistence
boundary. This is a known architecture limitation, not a newly observed data-loss
incident.

Choose durable control-plane storage and an explicit migration/recovery strategy
before relying on dashboard changes as persistent configuration or adding replicas.
Simply increasing workers/instances also fragments process-local metrics and caches.
Keep this as a separately approved migration, not a quick performance patch.

## Maintainability and delivery

Two production files exceed the 1,000-line ceiling:

- `services/proxy_service.py`: 3,462 lines. Extract provider-native codecs first
  (especially Gemini and OpenRouter), then shared transport and reasoning/stream
  normalization behind existing interfaces.
- `cloudflare-worker.mjs`: 2,219 lines. Extract direct-provider handlers, edge
  auth/CORS policy, and container dispatch into separate cohesive modules.

Near the limit are `routes/unified.py` (1,000), roleplay `endpoint.mjs` (998),
`auth_service.py` (987), `rate_limit_service.py` (975), roleplay `memory.mjs` (967),
and `transport.mjs` (919). Split by responsibility before extending these paths.
The 4,046-line Worker and 1,344-line roleplay test files also need domain-oriented
splits when touched. None was modified during this review.

Keep raw passthrough and managed roleplay deliberately distinct. Consolidation
should use shared contracts and cross-runtime fixtures, not silently change raw
provider behavior. Protect existing cookie isolation, secret-safe errors, scoped
session storage, billing guards, and replay restrictions.

CI currently checks mostly fatal lint errors and permissive types. Strengthen typed
transport/result boundaries incrementally, and add failure-injection and performance
gates. Existing green suites did not establish stalled-stream deadlines, honest
visible-TTFT telemetry, or linear normalization cost.

## Suggested implementation sequence

1. **Recovery and measurements:** queue/stream deadlines, cancellation classification,
   partial-output handling, and unified completion events. Add failure-injection
   tests before changing routing policy.
2. **Measured hot-path optimization:** incremental reasoning normalization, then
   dashboard capacity isolation. Benchmark with identical input and output fixtures.
3. **Predictable controls:** clearly separate roleplay, raw provider, and explicit
   auto routes in the UI; display effective model, billing mode, reasoning effort,
   fallback policy, limits, and a copyable endpoint without embedding a key.
4. **Routing experiments:** compare allowed models/providers using visible TTFT,
   completion time, failure rate, and a task-specific quality rubric. Keep the
   existing reasoning preference fixed during speed comparisons.
5. **Durability and modularity:** migrate control-plane state and extract the large
   transport modules in independent, reversible changes.

Do not begin with blanket model downgrades, shortened prompts, response caching of
private chats, aggressive retry fan-out, or more container replicas. Those changes
can alter behavior or cost without addressing the confirmed failure modes.
