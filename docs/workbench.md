# Operator workbench

Open `/workbench` after signing in as an administrator. The workbench requires
the Flask dashboard and the Cloudflare roleplay Worker from the same release.
Set `WORKBENCH_WORKER_URL` to the trusted HTTPS Worker origin, without a path.
The server uses its configured administrator credential; the browser never
receives provider keys. Do not put credentials in profiles or exported files.

Local installations use `CONNECTION_PROFILES_DB_PATH` (default
`instance/workbench.sqlite3`) or external PostgreSQL. On Cloudflare, profiles and
comparison results are stored in D1 whenever the Worker provides it, so they survive
Container restarts; see [control-plane persistence and encrypted
backups](control-plane-storage.md#control-plane-state-in-d1). Provisioning a database
is a separate operator action; enabling the dashboard does not provision or migrate
storage.

## Connection profiles

Save creates a new profile without replacing older settings. Validate & preview
checks configured routes and local parameter mapping without generating text.
Exports contain an endpoint, request settings, and the validation receipt. Supply
the proxy key and conversation messages separately in your client. Saving a
profile does not change another client's active connection automatically.

Roleplay profiles use `/roleplay/v1/chat/completions`. Direct profiles support the
configured NanoGPT, OpenCode, OpenRouter, LinkAPI, and NavyAI routes. OpenRouter
exports `/openrouter/chat/completions`; NanoGPT subscription-only exports
`/nanogpt/subscription/v1/chat/completions`. Direct connections must be pinned,
with memory and recovery off and no roleplay fallback. Providers/models absent
from the configured roleplay catalog cannot be selected through this workbench.

| Routing mode | Selection behavior |
| --- | --- |
| Provider priority | Preserve configured provider tiers; adapt within a tier. |
| Fastest eligible | Rank across eligible providers using recent successful observations in the current session. |
| Quality | Apply configured family order and model preference across providers; GLM Flash precedes Uncensored Flash and GLM 5.2. This is not a measured intelligence score. |
| Pinned | Restrict selection to the exact configured provider and model. |

Fastest-eligible requires at least two successes and observations within 24 hours
before using a route's speed score. Unknown or stale routes keep configured
order behind measured routes. Cooldowns and billing restrictions remain hard
constraints. Its reference completion size is configurable through
`ROLEPLAY_SPEED_REFERENCE_OUTPUT_TOKENS`. Comparison-lab sessions are isolated:
their reports inform manual selection, not a global automatic speed ranking.

`subscription-only` cannot escape to a standard/pay-as-you-go route. Configured
mode uses each route's existing billing policy; it does not guarantee 1x token
weight. An explicit model pin can select a configured higher-weight model.
Fallback `none` disables alternative generation candidates, refusal fallback,
automatic continuation, and output-contract repairs. Automatic memory compaction
is separate and may still require a call; choose memory off for an isolated
single-generation comparison.

The parameter receipt distinguishes requested reasoning effort from locally
mapped wire effort. `providerAcknowledged: false` means there is no independent
proof the upstream honored the setting. Longer visible reasoning is not a quality
measurement. Existing global defaults remain unchanged.

## Blind comparison lab

Choose 2–4 configured routes, a fixed synthetic conversation, effort, and 1–3 runs
per route. Confirmation permits at most 12 sequential generation attempts, each
capped at 2,048 output tokens. There are no automatic retries. Stop cancels the
active browser request and prevents queued trials from starting; upstream work
already accepted may still be billed.

Answers are randomly labeled and provider identity stays hidden in the interface
until every answer is rated. This is presentation-level blinding, not concealment
from an administrator inspecting network traffic. Judge continuity, character
agency, spatial plausibility, and instruction following before revealing routes.
Saved reports contain ratings, route identifiers, outcome and numeric measurements,
not prompts, answers, or reasoning. Up to 100 reports and 50 profiles are retained
per administrator; reaching a limit rejects new saves rather than deleting old ones.

First-visible latency is browser-observed, including the dashboard relay. Output
TPS uses provider-reported completion tokens, which may include reasoning, over
the observed output interval. Missing usage produces unknown TPS, not an estimate.
These measurements are not equivalent to a catalog's advertised TPS. Small samples
are exploratory; compare repeated runs under similar context sizes and load.

Lab answers remain in the tab, but a failed synthetic turn opts into the bounded
Worker recovery snapshot described below. Successful answers are not saved by
the lab. Closing the tab loses unsaved results. Profile/report exports never
include authentication headers. If the browser blocks downloads, the profile
preview remains readable and copyable.

## Session diagnostics and continuity

Enter `X-Roleplay-Session-ID` and select the credential scope used for the original
request. Public session IDs are scoped to the key; the same ID under another key
does not refer to the same session. Comparison sessions use administrator scope.

Monitoring polls metadata every three seconds and stops when the tab is hidden.
Reconnect never retries generation. The timeline retains up to 30 turns for 24
hours and exposes phase timings, route, trace ID, completion state and parameter
receipts, without chat text or credentials. Active progress is runtime-local;
completed traces survive Durable Object eviction. Missing events do not prove
zero latency. Failed persistence is not reported as successful completion.

Memory inspection is explicit. The optional context checkbox additionally loads
private retained messages and protected directives. Edit the summary and up to
24 pinned facts; stale revisions and edits during an active turn are rejected.
Pins supplement continuity but do not override current instructions. They are
used only when memory is enabled. Compaction preserves pins.

Creating a branch copies the retained context into a new independent session.
It does not generate text, modify the source, or recover older compacted history.
Use the returned branch ID in the client to continue that branch. Save any desired
corrections before branching; unsaved editor text is not copied.

## Interrupted response recovery

Ordinary roleplay requests retain no recovery snapshot unless
`recovery_enabled: true` is supplied. A failed opted-in turn may save its request
context and up to 16,000 visible partial characters. Reasoning is not included in
the partial. Requests above the 60 KB recovery-template limit and snapshots above
100 KB are ineligible. Access expires after 24 hours; expired data is removed on
inspection or session cleanup, not under a guaranteed 24-hour physical-deletion
schedule. Existing Durable Object session retention still applies.

Inspecting is read-only apart from expired-snapshot cleanup. Continue and
regenerate require confirmation and the latest one-use recovery token. Both
consume the snapshot before dispatch and create a separate session. Continue
provides the retained partial as context; it is a new generation, not network
resumption. Truncated or empty partials cannot be continued. Regeneration remains
available. A network failure never automatically repeats the billed action.
Failed partials are not inserted into the original conversation memory.

## Release checks

The custom Worker build and Docker image build independently fingerprint the
application sources. The dashboard compares both fingerprints and compatibility
versions. Missing evidence is unverified; unequal evidence is pending or mixed.
Worker version metadata is supplementary and never substitutes for Container
build evidence. Readiness and both JanitorAI preflight paths can be probed without
generation. These are server-to-Worker checks, not proof of a user's browser
network path, a successful provider request, or a completed rollout.

Authenticated Worker operations are under `/v1/roleplay/control/`: `timeline`
and `status` use GET; `receipt`, `memory`, `branch`, and `recovery` use POST.
Session operations require `session_id` and `scope` query parameters. Only the
administrator key can access them. The dashboard bridge is session-authenticated,
CSRF-protected for writes, fixed-origin, non-redirecting, and `no-store`.

## Verification

Worker routing, metadata privacy, memory revisions, branching and one-use recovery
have focused tests in `tests/test_roleplay_*worker.mjs`. Browser stream framing,
reasoning suppression, interruption and cancellation are covered by
`tests/test_workbench_stream.mjs`. Persistence, backups, profile/report boundaries,
admin access and the gateway are covered by `tests/test_control_plane_storage.py`
and `tests/test_workbench_services.py`. The optional PostgreSQL test requires an
isolated database through `TEST_CONTROL_PLANE_DATABASE_URL`.

`tests/helpers/workbench_preview.py` serves a loopback-only synthetic browser
fixture. Run it only from a secret-free source snapshot with the fixture's explicit
synthetic environment. It never measures real providers or validates production
deployment. It is excluded from the Container image.

## Model league and shadow evaluation

The Model league panel samples successful routed chat requests only for keys with
an explicit `shadow_eval_rate` between 0 and 0.2 in Users → key controls. Blank,
null and zero disable sampling. `auto:*`, `cascade:*` and intelligence requests
are eligible, including the normalized `/v1/responses` chat path. Media, roleplay,
Knowledge and direct concrete models are excluded. Retained requests are scanned
with the existing secret scanner; high-confidence findings or incomplete scans
skip the sample. Heuristic findings remain unchanged. Answers are also scanned.
Request data is limited to 64 KiB and answer data to 32 KiB. Successful streaming
answers require a terminal finish and `[DONE]`; partial/error streams are skipped.

Load league & settings to configure candidate IDs by coding, extraction, writing,
reasoning and chat. Evaluation starts disabled. The judge defaults to `free:json`
(or `SHADOW_EVAL_JUDGE_MODEL` when first seeded), with three replays per run and a
50-replay UTC daily cap. A replay can include one candidate and two judge calls;
all three are separately accounted to `internal:shadow-evaluation`. Optional
`SHADOW_EVAL_DAILY_BUDGET_USD` and `SHADOW_EVAL_MONTHLY_BUDGET_USD` constrain that
principal. Free/subscription candidates in the reviewed policy run first. Routed
free/auto judges exclude Gemini; a concrete Gemini judge is an explicit choice.

The five-minute scheduled trigger uses `fetchIfRunning` and never wakes or renews
an idle Container. Claims and a five-minute lease prevent concurrent duplicate
runs and enforce the daily cap. Failed attempts consume their claim and are not
retried. A run starts no more than the configured count within four minutes; calls
use existing dispatch timeouts. Replays cap output at 2,048 tokens. Judging uses
random A/B order followed by swapped order. Only agreeing valid judgments record
a win/loss; disagreement is a tie and malformed output is excluded from ratings.

The league shows per-task wins/losses/ties, Elo (1500 initial, K=32), comparison
count, median latency and known cost. Export league contains numeric results and
model identifiers, never retained text. Propose update changes only task scores
for models with at least 20 judged comparisons in that task; auto-route order
suggestions are displayed separately. Applying requires a checked confirmation
and the current proposal revision. Policy validation, an atomic revision guard
and a retained policy backup run before replacing the policy. Auto routes never
change automatically.

Inspect sample metadata before selecting Load sample text. Only administrators
can request individual retained text. Samples expire from access after seven days
and the oldest are evicted above 2,000. D1 retention cleanup runs on every cron,
even while the Container is asleep, and on storage access. Physical deletion
depends on successful cron/storage execution; this is not a D1 native TTL.
Content-free results retain at most 10,000 records for 90 days; policy backups
retain at most 20. Purge requires confirmation and removes samples and results,
without resetting the daily allowance or removing policy backups. This data is
excluded from the general control-plane export so prompt text cannot enter it.

Apply `0014_shadow_eval.sql` before releasing the Worker/Container. It adds the
nullable key override and four tables (including guarded policy backups). Reuse
`INTELLIGENCE_DB`, the private intelligence outbound service and existing cron;
no new binding or Durable Object migration is needed. Configure the judge and
optional evaluation budgets through the existing Container environment path,
then enable evaluation and opt in individual keys. Provider credentials remain
in the existing server configuration. Local-only installations clean retention
on access/run; they need periodic invocation if idle physical deletion is required.
