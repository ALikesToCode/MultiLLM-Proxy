# Shadow evaluation on opted-in gateway traffic

## Contract and integration

The existing outbound firewall, tool-call repair, image quality judge, answer
memos, product sites, comparison lab, accounted dispatch, judge routing, D1 RPC
and five-minute health schedule are preserved. The existing policy store supports
seed-only writes and has no guarded replacement path. This feature adds that
path with fixed shared SQL, validation, compare-and-swap and atomic backups.

`shadow_eval_rate` mirrors nullable `secret_scan_mode` across AuthService local
schema, key controls, backup restore compatibility and Worker control users.
Null/omitted/zero means no sampling; the range is 0–0.2. Migration 0013 adds the
column plus samples, results, config and policy backup tables. It does not depend
on the parallel cascade migration (0012). Cascade eligibility is prefix-only.

Sampling occurs after successful unified chat dispatch on /v1/chat/completions,
/v1/responses, /v1/messages and /optimize/v1/chat/completions (after normalization),
or the dedicated /intelligence/v1/chat/completions response. Only opted-in routed
requests are eligible. accounted_dispatch sets a request-local gateway_subrequest
flag and restores its previous value in finally, including nested calls/failures.
Sampling returns immediately under that flag without consuming the outer request's
decision. Only an eligible outer request sets shadow_eval_sampled and draws once.
The request callback wraps SSE only for an opted-in eligible request, forwards identical chunks and submits only a successful
terminal stream. A 32-entry daemon queue stores without blocking the user; queue
full, validation or storage failures drop the sample and never fail the request.

Each sample stores UUID, creation time, key identity, route, deterministic task,
messages/tools/tool_choice/response_format and explicit max_tokens or
max_completion_tokens ≤65,536 UTF-8 bytes, production model, content/tool_calls
≤32,768 bytes, optional production_finish_reason, latency and numeric token usage.
Agent requests whose retained replay fields exceed 64 KiB are never sampled.
Task precedence is declared tools/fences → coding, JSON format → extraction, writing cues →
writing, math/step-by-step → reasoning, otherwise chat. Scan the full original
request and answer, skipping high-confidence or truncated scans; heuristic values
are retained exactly. Both Flask and private D1 ingress enforce the contract.
Samples are inaccessible after seven days and at most 2,000 survive an atomic
insert/eviction transaction. Metadata lists show the newest 20 without text.
Individual sample text requires an explicit admin request. Purge deletes samples
and results after explicit confirmation, retaining allowance counters/backups.

Seven locked, saturating process counters expose eligible, sampled, skipped_rate,
skipped_secret, skipped_oversize, skipped_queue_full and skipped_error. They store
no request/model/key labels, reset on process restart and saturate at 2**53−1.
Eligible counts opted-in eligible decisions; sampled counts successful queue
admissions. Incomplete secret scans, partial/error streams, validation and storage
failures count as errors. A later persistence error can follow a queue admission,
so counters are diagnostics, not a strict partition of eligible traffic. Purge
retains these counters. The league API, numeric dashboard fields and content-free
export include sampling_counts and result_counts (judged/failed/same_model/
candidate_truncated); counters are local to the serving process, not D1 totals.

Config has enabled=false, five task candidate lists, judge env override or
free:json, max_replays_per_run=3 and daily_cap=50. Candidate lists allow at most
eight unique provider:model/auto:/cascade: IDs each; per-run count is 1–20 and
daily cap 1–500. Config saves require the previous normalized config. Optional
evaluation daily/monthly USD budgets are separate from the sampled key's budget.

Cron cleans expired D1 records directly, then uses Container.fetchIfRunning for
POST /admin/shadow-eval/run. It never calls waking fetch or renews idle time.
The admin API endpoint uses existing API authentication, not dashboard sessions.
A fresh background request context installs internal:shadow-evaluation. A process
lock plus D1 lease serializes work; transactional claims deduplicate sample/route
and reserve the UTC daily count before calls. Changing config cancels new claims;
purging does not replenish the cap. Crashed/failed claims are not retried.

Candidates reviewed as free/subscription run first, stably within billing classes.
Each replay calls normal unified dispatch through accounted_dispatch, then two
judge calls through the same accounting path. Per-call admission, budgets, route
health, firewall and tool repair remain active. No call is charged to the sampled
key. Background requests cannot sample themselves. The runner starts at most
20 replays, checking a four-minute deadline between calls, with existing dispatch
timeouts and a five-minute lease. Replay output uses
max(1024, min(8192, 2 * production completion_tokens)), or 8192 when usage is
unknown, lowered to either explicit original request limit. Send only
max_completion_tokens through normal gateway translation. Replay uses all stored
messages and tool schemas, independently of judge context compaction. A candidate
resolving to the production model records same_model, excluded from failures and
ratings. A candidate finishing with length when production did not records
candidate_truncated=true and outcome=candidate_truncated, also excluded and counted
separately. Neither excluded comparison incurs judge calls.

Judges receive task rubric and untrusted request/answers labeled A/B, without
model/key/route metadata. Random ordering is reversed for the second judgment.
Judges get a 1024-token output budget. Their compact request view has system
messages capped at 8 KiB total and the last eight non-system messages within
24 KiB, selecting newest first and restoring conversation order. The oldest kept
message can be truncated to fit (UTF-8 and JSON escaping are counted). Tools keep
names/descriptions only, with full schemas retained for tools called by either
answer. response_format and both answers remain as stored. The complete serialized
judge payload is at most 64 KiB: drop older non-system messages first, then system
context. If the intact answers/format/tool metadata alone cannot fit, fail that
comparison without making a judge call rather than truncate evidence.

JSON requires winner A/B/tie and finite confidence 0–1 (numeric strings accepted).
One surrounding markdown fence is accepted and unknown keys are ignored. Drop
non-string reasons, keep the first three strings truncated to 160 characters;
missing/non-list reasons become empty. Missing/invalid winners, invalid confidences,
duplicate JSON keys, nested fences and output above 4 KiB remain invalid.
Consistent judgments produce candidate win/loss/tie; disagreement is
a tie. Malformed responses/call failures yield failed, excluded from ratings.
Reasons and judge text are discarded. Routed free/auto judges use excluding_gemini;
explicit concrete Gemini is permitted. Coding/tool samples count validity through
repair_tool_calls without extracting calls from answer text.

Results contain sample/task, actual candidate/production model, requested candidate
route, outcome, judge identifier, numeric latencies/usage/costs and optional tool
validity counts. Failed attempts retain status, never prompt/answer/judge text.
Results are capped at 10,000/90 days and read in pages of 50. Elo is task-specific,
initial 1500, K=32, chronological with ID tie-breaks. Exported league rows have
wins/losses/ties, comparison count, rounded Elo, median latency, median known USD
cost and tool validity counts. Unknown cost is null.

Proposals validate the current policy, deep-copy it and change only task_scores
for registered candidates with ≥20 valid comparisons in that task. Per task:

* anchor = mean current task_scores of rated models with a score; default 70.
* mean_rating = mean Elo of all models with ≥20 comparisons for that task.
* proposed score = clamp(round(anchor + (rating − mean_rating) * SCORE_PER_ELO), 0, 100).
* SCORE_PER_ELO = 0.1: 100 Elo means 10 absolute score points. MAX_STEP = 15 caps
  each change from a previous score; models without a previous score use the
  anchored score directly. Unevaluated models remain untouched.

Example: rated models with current scores 80 and 90 anchor at 85. Ratings 1550
and 1450 average 1500, producing scores 90 and 80. Both changes stay within 15
and the mean remains 85. Ratings 2000/1000 on an 80/80 baseline would propose
100/30 after clamping, then the step limit yields 95/65. Rounding, clamping and
step limits can prevent exact mean preservation or rating ordering at extremes.
Chat/extraction are added to the existing policy task vocabulary. Auto-route
suggestions require 20 comparisons for every route candidate and remain suggestions. Apply requires explicit true confirmation
and the SHA-256 proposal revision, then full policy validation and an atomic
expected-policy update with a pre-update backup; at most 20 backups are retained.
No automatic policy/route write exists. General control-plane exports exclude all
shadow tables, so retained traffic cannot enter exports.

## Reviewed dispatch inventory

/admin/workbench/shadow/{config,league,samples,samples/<identifier>,purge,propose,apply}
are administrator-only storage/aggregation/validation paths, with CSRF on writes,
no-store responses and existing dashboard audit hooks on settings/apply/purge.
/admin/shadow-eval/run is API-admin-only and starts normal accounted unified
candidate/judge dispatch. The private http://intelligence.internal/v1/shadow-eval
handler executes only bounded fixed SQL and does not call providers. The new
scheduled module performs D1 cleanup and fetchIfRunning only. The frozen firewall
inventory includes all new modules/routes and now recognizes Flask get/post/put/
patch/delete decorators as well as route/add_url_rule.

## Explicit adaptations and limitations

* The base had no policy replacement/backup path; migration 0013 includes one
  additional backup table and implements a guarded path instead of reusing a
  nonexistent one.
* Default per-key state is nullable rather than literal 0 to mirror the lead's
  secret_scan_mode decision; both mean disabled.
* High-confidence answer findings and truncated scans also skip capture to avoid
  persisting credentials or incomplete privacy checks.
* Native Responses/Messages normalization is sampled at the chat dispatch seam
  without storing protocol-specific fields. Explicit token limits and optional
  production finish reasons extend the stored document compatibly; older samples
  without finish metadata treat production as not known to have hit length.
* Runs use a four-minute between-call deadline and five-minute lease; an
  already-running call is governed by the dispatch timeout, not force-killed.
* Intact answers/required tool context can exceed the 64 KiB total judge cap;
  those comparisons fail safely after replay. Truncated/same-model comparisons
  skip judging entirely, preserving rating fairness and avoiding unnecessary cost.
* Result retention, candidate/config bounds, newest-20 metadata lists and capped
  policy backups bound new stores and loops where the original design omitted
  limits. Failed attempts consume the cap and cannot be blindly retried.
* Auto-route orders are suggested only. Explicit Apply changes policy scores;
  a separate normal auto-route edit is required for an order change.
* D1 has no native TTL in this design. Access expiry is strict; physical cleanup
  runs every five-minute cron plus writes/reads/runs, subject to runtime availability.
  Local SQLite cleanup runs on accesses/runs and needs an external timer while idle.
* The task vocabulary gains chat/extraction so those scored tasks pass existing
  policy validation. Quality tiers and other routing policy fields are unchanged.

## Release steps and verification

Apply 0013 before release; reuse existing INTELLIGENCE_DB/private outbound binding,
cron and Container. No new binding or Durable Object migration is required.
Set SHADOW_EVAL_JUDGE_MODEL before first config seed if changing the default;
afterward use dashboard config. Optional SHADOW_EVAL_DAILY_BUDGET_USD and
SHADOW_EVAL_MONTHLY_BUDGET_USD constrain the evaluation principal. Review provider
entitlements and configure candidates, then explicitly enable and opt in keys.
No live provider, remote migration or deployment is part of local verification.

Synthetic Python/Worker acceptance tests cover sampling/probability, normalized
and streaming responses, task/secret/size contracts, TTL/caps/purge, no-wake cron,
leases/daily limits, independent accounting with exactly one ledger row per call,
Gemini exclusions, swapped judging/malformed output, tool validity, known Elo math,
20-comparison thresholds, policy validation/CAS/backups, admin revalidation/CSRF,
explicit apply/purge confirmation and text-free league/metadata exports. Round-2
regressions add anchored scores/step limits, usage-based replay caps, finish reason
capture, tolerant bounded judgment parsing, compact context/schema selection,
subrequest isolation/restoration, both added surfaces and numeric coverage.

## Source boundaries

Round-2 changed source files remain below 1,000 lines; the sampling module is
below 300 lines and the compact judge context has its own cohesive module. The
round-1 integration files below remain unchanged in round 2. Two existing
integration files remain over 1,000 lines: cloudflare-worker.mjs (2,128) adds only the schedule import and
waitUntil call; services/auth_service.py (1,208) adds the nullable field to the
existing schema/read/write paths. A whole-file extraction is unsafe within this
feature's scope. The next cohesive boundaries are Worker request/provider
transport orchestration and AuthService account schema/persistence adapters.
