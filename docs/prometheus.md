# Prometheus scrapes

Set `PROMETHEUS_ENABLED=true` to enable exposition. The default is false. The
Worker forwards this setting to its Flask Container. There is no new scrape
credential, exporter process, dependency, migration or stored scrape data.

## Public Worker status

`GET /status.prometheus` and `HEAD /status.prometheus` expose only health facts
already published by `/status.json`. The shared reader uses the retained D1
snapshot first, then `fetchIfRunning` for an already running Container, and then
an unknown fallback. A scrape never wakes the Container or renews its sleep timer.
The response uses `Cache-Control: public, max-age=30, s-maxage=60` and the same
30-second isolate memo as the status page. HEAD returns the same headers without
a body. This public endpoint is Worker-only; standalone Flask serves the detailed
endpoint below and retains its existing public status endpoints.

- `multillm_status_state{scope="overall|route|provider",name="...",state="up|degraded|down|unknown"}`:
  one-hot gauges preserving the public snapshot's four states. Unrecognized
  states become unknown. Overall uses `name="overall"`; routes and providers use
  their public IDs. Candidate model names are not labels. Down does not assert
  that a circuit is open.
- `multillm_status_snapshot_available`: 1 for retained or live data; 0 for fallback.
- `multillm_status_snapshot_age_seconds`: nonnegative age of a retained/live
  snapshot with a valid timestamp. It is absent for the fabricated fallback or
  an invalid timestamp. Availability does not imply freshness.

## Detailed operator window

`GET /v1/metrics/prometheus` requires an existing authenticated API key whose
scopes contain `admin` and whose user has `is_admin=true`. Browser dashboard
sessions do not grant access. Missing/invalid credentials return 401; scope or
user denial returns 403. On Worker deployments this endpoint forwards to Flask
and may wake the Container. Detailed responses use `Cache-Control: no-store`, including denials.

The serializer reads `MetricsService.get_stats(hours=24)` without changing
collection, accounting or the usage ledger. These rolling-window values are
**gauges**, not monotonic counters or histogram buckets:

- `multillm_requests_window{window="24h",status_class="2xx|3xx|4xx|5xx|other"}`:
  observed response counts by class.
- `multillm_latency_window_seconds{window="24h",quantile="0.50|0.95"}`:
  observed latency quantiles, converted from milliseconds to seconds. Omitted
  when there are no observations or a quantile is nonfinite.
- `multillm_observed_requests_window{window="24h",source="flask_ledger"}`:
  count of observations in the Flask metrics window, including restored ledger
  records. Native edge requests not recorded there are outside this coverage.

The endpoint does not claim complete native-edge coverage, provider-billed
usage, cost, TTFT or token totals. It exposes no prompt, key/prefix, principal,
URL, request ID, provider breakdown or arbitrary requested model labels.

## Format and limits

Both surfaces use `Content-Type: text/plain; version=0.0.4; charset=utf-8`, with
HELP/TYPE declarations. Labels escape backslash, double quote and newline;
nonfinite numeric samples are omitted. Public names are capped at 256 code units
and repeated names within a scope are deduplicated. Snapshot traversal is bounded.

Each response is capped at 512 total series and 256 KiB of UTF-8 output,
including `multillm_prometheus_truncated`. This gauge is 1 when names, traversal,
series or bytes have been truncated, and 0 otherwise. Public states are admitted
as complete four-sample groups. Selection follows public snapshot order and is
deterministic for the same snapshot and scrape time.

Disabled metric paths return 404 without snapshot access or Container forwarding.
Enabled unsupported methods return 405 with `Allow: GET, HEAD` for the public
endpoint and `Allow: GET, OPTIONS` for the detailed endpoint. Existing API OPTIONS
preflight handling stays available even when metrics are disabled.

The Container environment allowlist registers `PROMETHEUS_ENABLED` only;
no broad environment wildcard is added.
