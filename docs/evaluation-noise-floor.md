# Three-arm evaluation and offline cost replay

`SHADOW_EVAL_NOISE_FLOOR_ENABLED` defaults to `false`. Paired runs keep their existing
sampling, two judges, result JSON, one-unit daily claims, league and review behavior.
The flag does not change production traffic, sample probability, retained request
fields, provider authorization or route policy. The scheduler continues to start
paired runs. Three-arm results are excluded from the league when the flag is off.

## Run a comparison

With the flag enabled on both the Worker and Container, an administrator can submit
this body to the existing `POST /admin/shadow-eval/run` endpoint:

```json
{"three_arm":true,"seed":17,"bootstrap_draws":1000}
```

Authentication and the existing evaluation config's `enabled` setting still apply.
An empty body starts the existing paired run. An explicit three-arm option while
the feature flag is off returns HTTP 400. Invalid options, boolean/negative seeds,
unknown options, or draws outside 1–5000 also return HTTP 400. The seed defaults to
0; draws default to 1000. The seed is a uint32 analysis seed recorded with every
comparison: it fixes judge order and bootstrap resampling, not provider randomness.

A and B independently replay the same retained request against its recorded
production model. C replays that request against the configured candidate route.
The request limits and full retained request are preserved by the existing replay
payload builder. Each of A/B, A/C and B/C is judged blind twice with mirrored order.
Judge prompts stay blind to producing models and principals; judge reasons are
discarded. Results contain model identifiers and numeric metadata. New arm answers
are kept only in memory. No new prompt retention, table or migration is required.

There are nine upstream calls per complete comparison: three arms and six judges.
Three-arm runs interpret `max_replays_per_run` as a call budget, while paired runs
keep its existing comparison-count meaning. A value below nine returns HTTP 400
for an explicit three-arm start; the maximum of 20 permits two comparisons per run.
The existing daily cap atomically reserves all nine units before the first call,
including free/subscription calls. If fewer than nine units remain, no units or
result row are reserved and the comparison is skipped. Concurrent claims share the
same daily counter and lease. Failed or incomplete comparisons keep their reserved
units; purging results does not refill the budget. Normal admission, accounting
and dollar-budget checks still run for every individual call, and can stop a run.
Reservations do not guarantee that a provider succeeds or that its price is known.

The existing 240-second run deadline is checked before each arm and judge. Existing
per-request timeouts still bound a call already in progress. There is no new retry
after failure or partial output. Changed baseline models, truncated/filtered arms,
malformed judges, failed calls and incomplete comparisons do not qualify for review.

## Review the statistics

The league and proposal responses add optional `noise_floor` metadata only for
three-arm evidence while the flag is enabled. Statistics group by task, requested
candidate route, selected candidate model, baseline model, seed and draw count.
Runs accumulate into a cohort; duplicate sample IDs never add statistical weight.
Different baselines/seeds do not pool. At least 30 distinct complete paired samples
are required, so multiple bounded runs are necessary. Fewer than 1000 draws may be
used for exploratory statistics, but cannot qualify a proposal.

Concordant pairwise wins/losses/ties score +1/−1/0. Per sample, candidate effect is
the mean of C-versus-A and C-versus-B scores; noise is the absolute B-versus-A score.
The seeded paired bootstrap resamples their difference. A cohort qualifies only
when the lower endpoint of its percentile 95% interval is strictly above zero.
All applicable cohorts must qualify. Invalid tool calls also exclude evidence.
This conservative ordinal noise floor is not a calibrated quality measurement;
provider drift, correlated samples and judge disagreement can limit inference.

Existing Elo anchoring, minimum review counts, score bounds, confirmation, policy
validation and compare-and-swap remain in place. Baseline rows provide an anchor;
three-arm evidence proposes changes to candidates only. There is no automatic
policy application or automatic route reordering. Proposal revisions include the
cohort statistics and an evidence digest; changed evidence requires another review.
Samples retain their existing seven-day/2000-row bounds and results retain their
90-day/10000-row bounds. Aggregation cannot recover expired evidence.

This measures the configured candidate route relative to the recorded model.
It does not add a compressor or predict the quality of an unexecuted transformation.

## Replay routing cost offline

`scripts/replay_routing_cost.py` imports only the standard library, reads two local
JSON files and makes no network or generation requests. Export only content-free
sample metadata plus observed token usage; do not export requests, answers, keys or
principal identifiers. For example, observations can contain:

```json
[{"sample_id":"sample-1","production_model":"openai:baseline","latency_ms":37,
  "usage":{"prompt_tokens":100,"completion_tokens":20}}]
```

The prices file maps candidate model IDs to USD per million tokens:

```json
{"openai:candidate":{"input_per_million":2,"output_per_million":4},
 "openai:unknown":null}
```

Run from the checkout:

```sh
python scripts/replay_routing_cost.py --observations observations.json --prices prices.json
```

Input is bounded to 16 MiB per file, 10000 observations and 128 candidate prices.
Unknown prices, missing input/output usage, or unrepresentable costs yield `null`
cells. Only explicit numeric zero is free. A candidate total is `null` if any cell
is unknown; `known_subtotal_usd`, cell counts and coverage expose the measured part.
The replay holds observed input/output tokens fixed. It does not forecast compression
ratios, candidate output length, cache discounts, capability, quality or latency.
Actual observed latency is reported separately; counterfactual latency is `null`.
