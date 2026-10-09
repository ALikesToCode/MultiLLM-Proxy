# Latency-SLO admission

Latency admission predicts completion risk before provider handoff. It uses measured
time to first visible output and output throughput from completed observations.
It never sends generation probes, writes routing policy, changes an explicit model,
or grants permission to retry a request that may have generated output.

## Configuration

`LATENCY_SLO_MODE=off` is the default. Empty values also mean off. In this mode,
admission, routing, responses, headers and observation storage remain unchanged.
Malformed settings disable admission and produce one warning per setting without
including the value. Both runtimes use the same settings and prediction formula.

To reject predicted misses on an exact managed route:

```sh
LATENCY_SLO_MODE=reject
LATENCY_SLO_MIN_SAMPLES=20
LATENCY_SLO_MAX_MODELS=128
LATENCY_SLO_POLICY_JSON='{"routes":{"/v1/chat/completions":{"deadline_ms":5000,"require_coverage":false}}}'
```

To allow eligible alternatives for an automatic route:

```sh
LATENCY_SLO_MODE=reroute
LATENCY_SLO_POLICY_JSON='{"routes":{"auto:intelligence":{"deadline_ms":5000,"require_coverage":true}},"keys":{"account-42":{"deadline_ms":3000}}}'
```

`routes` matches exact HTTP paths or exact automatic model identifiers. `keys`
matches an authenticated key/account identifier, never a caller-provided header
or API credential. Each entry requires integer `deadline_ms` between 1 and
300000; `require_coverage` is an optional boolean, default false. If several
entries match, the smallest deadline and any coverage requirement win. No match
means ordinary policy. The default policy is `{}`.

Policies reject duplicate keys, unknown fields, invalid identifiers, more than
128 entries per scope, or more than 32768 UTF-8 bytes. The sample minimum is an
integer between 1 and 1000, default 20. The model cap is an integer between 1 and
512, default 128. Invalid numeric settings disable the feature.

## Prediction and admission

Each model retains at most 1000 paired observations from the last 15 minutes.
The oldest inactive models are evicted when the model cap is reached. Partial
measurements, nonpositive throughput, invalid timing, and future samples do not
provide coverage. Measurements are process/isolate-local and are lost on restart.
Stored routing-health averages and reviewed latency estimates do not count as
recent SLO samples. With admission disabled, no new SLO observations are stored.

For each recent pair, predicted milliseconds are
`ttft_ms + requested_output_tokens * 1000 / tokens_per_second`. The prediction is
the empirical p95 using the nearest-rank method, rounded up. If both `max_tokens`
and `max_completion_tokens` are present, the smaller valid limit is used. The
default is 1024 output tokens. Intelligence selection uses its already validated
output limit. Limits must be integers from 1 to 131072; requests outside this
prediction bound are unknown and remain subject to ordinary request validation.
Admission never rewrites the payload to impose a prediction limit.

The decision reports sample count, required sample count, coverage fraction,
latest observation age, window length, requested output, and predicted time.
Successful Flask decisions are request-local; errors include this content-free
report in `error.prediction`. No response header is added.

Sparse or old evidence yields `prediction_unknown`. Ordinary policy applies
unless coverage is required, in which case admission returns HTTP 503 with
`latency_slo_unavailable`. A known miss in reject mode returns HTTP 503 with
`latency_slo_predicted_miss` before provider handoff. Both errors have
`retryable: false` and `Cache-Control: no-store`.

Reroute mode changes only automatic selections, using alternatives already
eligible under the existing authorization, entitlement, privacy, capabilities,
context, billing and approved session-lane policy. Alternatives must have the
same reviewed quality tier as the original selection and a known prediction
within the deadline. Missing tier approval never authorizes rerouting. An
explicit model receives the reject behavior on a known miss; unknown predictions
pass through when coverage is optional. A reroute removes unsafe alternatives
from that selection rather than adding models or retry attempts.

Generation deadlines remain the hard runtime limit. Admission uses the remaining
runtime budget when present and never extends, resets, or cancels that deadline.
A passing prediction can still time out or fail. Predictions are neither billing
facts nor a guarantee of provider latency, and rejected admission creates no
provider usage or fabricated successful completion.

## Runtime interfaces

Flask registers `latency_slo_request_hook` immediately after the generation
deadline hook and before the idempotency claim. Managed chat, messages, Responses
and intelligence requests are covered; provider passthrough is unchanged.
Flask registers `latency_slo_candidate_policy` as an explicit read-only collaborator returning an
ordered list from reviewed eligibility without claiming a session-lane lease or seeding storage. Unknown reviewed policy, session-lane preparation, precision lookup, health probes and traffic cohorts have unknown coverage at this early boundary. Later selection preserves candidates removed by an early reroute. Intelligence selection
and automatic route-health ordering enforce the policy again on their actual
candidate lists before dispatch. Existing provider validation still applies.

Native Worker routes call `prepareLatencySLO` after verified authentication and
deadline setup, with canonical provider/model IDs, the verified key identifier,
and already eligible approved candidates. The returned rejection must be handled
before dispatch, and rerouted candidates must remain restricted at dispatch.
`recordLatencyObservation` consumes the existing telemetry finalization event.
Only successful, measured, non-cache observations with positive observed output
and time after first output contribute throughput. Forwarded or passthrough
traffic must not call this native admission interface twice.

Observation windows contain model IDs and numeric timings only. They store no
prompts, completions, credentials, identity, queue size, prices or usage ledgers.
Content retention controls remain independent. No database table or migration is
required.
