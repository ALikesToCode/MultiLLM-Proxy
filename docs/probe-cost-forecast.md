# Health probe cost forecast

`scripts/probe_cost_forecast.py` calculates conservative API-call and USD bounds from
a nonsecret JSON snapshot. It reads only the supplied plan file or stdin. It does
not load application environment, discover credentials, import the application,
contact providers, write storage, or enable probes. There is no execution flag.
Existing requests, responses, headers, logs and schedules are unchanged.

Run from the repository with the installed Python:

```sh
python -I scripts/probe_cost_forecast.py --plan-json plan.json
printf '{}\n' | python -I scripts/probe_cost_forecast.py
python -I scripts/probe_cost_forecast.py --plan-json plan.json --max-calls 24 --max-cost-usd 0.008640
```

No configuration is inferred from the environment. Copy the relevant nonsecret
schedule, route descriptors and prices into the plan before use. Do not provide
keys, endpoint URLs, prompts or responses. The tool accepts `.json` files or `-`
(stdin, also the default); application `.env` paths are rejected.

## Disabled plan

`{}` produces zero calls and `0.000000` USD for every horizon. The default plan has
no included schedule or generation probes. Each inclusion needs `enabled: true`.
This flag controls the forecast only; it changes no runtime configuration.

## Existing scheduled model-list checks

```json
{
  "version": 1,
  "days": 30,
  "run_minutes": 60,
  "schedule": {
    "enabled": true,
    "interval_minutes": 30,
    "admin_configured": true,
    "container_running": true,
    "checks_wake": false,
    "keep_warm": false
  },
  "routes": [
    {"id": "auto:example", "candidates": ["nanogpt:model-a", "nanogpt:model-b", "openrouter:model-a"]}
  ],
  "providers": {
    "nanogpt": {"catalog_check": true, "base_url_configured": true, "key_count": 8},
    "openrouter": {"catalog_check": true, "base_url_configured": true, "public_catalog": true, "key_count": 0}
  }
}
```

This yields 96 provider calls per day, 2,880 for 30 days and four per declared run,
with **zero generation calls**. Its USD totals are `null`, with `incomplete: true`:
absence of generation is not evidence that API quotas or API charges are free.
Set `model_list_request_usd` on a provider descriptor only when its per-GET upper
bound is known (an explicit zero is supported). Token prices cannot establish a
model-list GET price.

The snapshot models `worker/health-schedule.mjs`, `services/health_checks.py` and
`services/route_health.py` as follows:

- The checked-in cron ticks every five minutes. Checks occur at whole epoch-minute
  multiples of the configured interval. The effective interval is the least common
  multiple of five and the interval, so an interval of seven means 35 minutes.
- Defaults are 30 minutes, with wake and keep-warm off. The forecast requires an
  admin credential presence boolean. Sleeping Containers are skipped unless wake
  or keep-warm is included. `container_running: true` bounds the case where all
  check ticks reach an already-running Container; it is not a measured uptime.
- Every unique provider in automatic-route candidates receives at most one GET per
  check tick. Extra models, routes and keys do not multiply these GETs. NanoGPT uses
  its first available key. Public catalogs need no key. No catalog endpoint, no
  base URL or no required key means zero calls.
- Every used provider needs a descriptor. `catalog_check` means membership in the
  repository's `PROVIDER_CATALOG_SPECS`; `public_catalog` means membership in its
  `PUBLIC_CATALOG_PROVIDERS` (currently cline-pass, navyai and openrouter). Inspect
  the repository configuration when preparing the snapshot; no discovery occurs.
- Including `keep_warm` adds one gateway `/healthz` call every five minutes,
  independently of the check interval or admin-key presence. Its API price remains
  unknown unless `schedule.keep_warm_request_usd` is supplied.

Provider presence fields default to false and key counts to zero. The tool accepts
only effective schedule intervals in 5..1440; unlike runtime configuration parsing,
it rejects invalid inputs instead of silently clamping or repairing them.

## Explicit paid-probe scenario

The existing scheduler does not generate completions. A `generation` row is an
operator's proposed recurring scenario, not a claim that a paid schedule exists:

```json
{
  "days": 30,
  "run_minutes": 60,
  "probes": [{
    "kind": "generation", "enabled": true, "provider": "openai",
    "models": ["model-a", "model-b"], "key_count": 3,
    "probes_per_interval": 2, "interval_minutes": 30,
    "input_token_cap": 100, "output_token_cap": 20
  }],
  "pricing": {"openai:*": {"input": "2", "output": "8"}}
}
```

The plan has 576 generation calls/day, 17,280/30 days and 24/run. Maximum exposure
is `0.207360`, `6.220800` and `0.008640` USD respectively. Disabled rows have zero
calls and zero cost, even if pricing is absent.

For horizon minutes H and interval I, calls equal
`ceil(H / I) * models * key_count * probes_per_interval`. This bounds an unknown
start phase; the monthly horizon is calculated directly rather than multiplying
a rounded daily tick count. A call's maximum cost is
`(input_token_cap * input_price + output_token_cap * output_price) / 1000000 + request_price`.

Pricing follows `services/cost_service.py` configuration semantics: case-insensitive
exact `provider:model`, then `provider:*`, then `*`. `input` / `output` prices are
USD per million tokens; `input_cost_per_million` / `output_cost_per_million` are
accepted aliases. `request` is an additive per-call USD charge, defaulting to zero
on a configured token-price entry. A request-only entry sets both token rates to
zero. Missing entries or partial token prices remain unknown; invalid rates are
errors. Prices never come from environment or a provider-price lookup.

## Half-open circuit traffic

`services/resilience_service.py` admits normal routed traffic when a circuit is
half-open. `CIRCUIT_BREAKER_HALF_OPEN_MAX_PROBES` limits concurrent in-flight
requests, not daily volume. Neutral outcomes can admit further traffic without
closing the circuit. No cooldown/concurrency multiplication establishes a spend
bound. `AUTO_ROUTE_EXPLORE_EVERY` in `services/route_health.py` changes the first
candidate of ordinary traffic; it does not add scheduled generation calls.

Supply explicit bounds for *all upstream attempts* admitted in half-open state:

```json
{
  "run_minutes": 60,
  "probes": [{
    "kind": "half_open", "enabled": true, "provider": "openai",
    "models": ["model-a", "model-b"], "key_count": 3,
    "calls_per_day": 12, "max_run_calls": 2,
    "input_token_cap": 100, "output_token_cap": 20
  }],
  "pricing": {"openai:*": {"input": "2", "output": "8"}}
}
```

Bounds are provider-wide, across all keys and candidate models. Cost uses the
most expensive candidate; any unknown candidate prevents a complete maximum.
Monthly volume is `calls_per_day * days`. Omit either bound to report that horizon
as `null`, never zero. Concurrency, cooldown and recurrence are not volume bounds;
half-open output uses no recurrence interval and `probes_per_interval: 0`.

## Report, budget decisions and limits

The report contains per-provider/model components, key counts, token caps,
intervals, probes per interval, daily/month/max-run calls, generation calls,
`zero_generation`, and cost bounds. `priced_components` and `unknown_components`
are zero-based component indexes. `known_cost_usd` is the priced subtotal, not the
complete maximum when unknown components exist. `incomplete` describes any unknown
cost or volume. Report money is a decimal string or `null`; `cost_micro_usd` is an
integer or `null`. Totals round upward to microUSD after exact decimal aggregation.

`--max-calls` and `--max-cost-usd` check **max_run**, whose duration is
`run_minutes` (default 30). Use `run_minutes: 1440` for a daily budget or
`run_minutes: days * 1440` for a monthly budget; half-open rows must supply the
matching `max_run_calls`. Decisions compare unrounded costs. Equality passes.
Exit 0 means valid forecast and any requested limits passed; exit 1 means a limit
was exceeded or its bound could not be verified; exit 2 means invalid JSON,
invalid schema/numbers, unreadable input or unsupported CLI arguments. Invalid
plan errors produce a fixed JSON error without echoing input. Argument-parser
errors go to stderr. Without budget flags, an incomplete forecast exits 0 but
still shows `null` and `incomplete: true`.

Input is capped at 1 MiB. Lists, pricing tables and combined components are bounded
at 512; route candidates also total at most 512. Days are 1..366 and run minutes
1..527040. Counts/products must fit a JSON-safe integer (2^53 - 1); keys, probes
per interval and token caps are at most 10^9. Recurring generation intervals are
1..525600 minutes. Decimals are nonnegative finite numbers up to 10^12, with at
most 18 fractional places and 64 characters. Boolean and fractional counts,
duplicate fields/models, unknown fields, and nonfinite values are rejected.

This is an exposure forecast, not an invoice or an execution permission. Token
caps must bound billed input, output and reasoning; images, tools, retries,
provider-specific metering, manual checks and rate limits need explicit accounting.
Infrastructure, Container keep-warm runtime, network tariffs and taxes are excluded
from API USD bounds. Configuration and tariffs can change; an incomplete or stale
snapshot cannot certify a future bill. W12 separately enforces execution budgets.
The tool retains nothing; shell redirection and plan/report file retention are
operator decisions. No live provider, deployment or metering validation occurs.
