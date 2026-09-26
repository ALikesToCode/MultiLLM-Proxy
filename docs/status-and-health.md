# Status and health

MultiLLM records how every automatic-route attempt ends, publishes the result on
a public status page, can use it to order route candidates, and checks providers
on a schedule without spending money. This page covers those parts; the
failover rules themselves are in [automatic model priorities](auto-routing.md#failover-boundary).

## Status page

`GET /status` is an HTML page and `GET /status.json` the same data as JSON. Both
need no login. For every automatic route they list each candidate in its
configured order, and they list every provider those routes use:

| Field | Meaning |
| --- | --- |
| `status` | `up`, `degraded`, `down` or `unknown` |
| `success_rate` | Share of routed attempts that succeeded in the last hour, 0 to 1 |
| `p50_latency_ms` | Median time from sending a request to receiving the response status, successful attempts only |
| `last_check_at` | When the provider's last free check ran |
| `last_check` | `ok` or `failed` (providers only) |

A candidate is `up` at a success rate of 95% or more, `degraded` from 50%, and
`down` below that, after three consecutive failures, or while its provider's
circuit is open. With no attempt in the last hour a recent free check decides
(`up` or `down`); without either it is `unknown`. A route is `up` when its first
candidate with data is up, `degraded` while another candidate still serves, and
`down` when none does. `overall` summarises the routes the same way.

The documents contain statuses, rates, medians and times only: no keys, request
counts, token usage, costs, URLs or hostnames. `/status.json` sends
`Access-Control-Allow-Origin: *` so monitors can read it from a browser.

On Cloudflare the Worker answers both paths from the snapshot the Container
stores in D1, so a status visit never wakes a sleeping Container or keeps it
awake. `source` is `snapshot` there and `live` when the Container answers
directly (other deployments, or the fallback below). Responses carry
`Cache-Control: public, max-age=30, s-maxage=60`. The Worker also stores them in
the edge cache, which works on a custom domain; the Cache API does nothing on
`workers.dev`, where each Worker isolate instead reuses a snapshot for 30
seconds. Before the first snapshot exists the Worker asks a running Container
without starting it, and otherwise shows every status as `unknown`.

## Route health

Each attempt an automatic route sends records success or failure and, when it
succeeds, the time to the response status. A `429`, `401`, `402`, `403`, `404`,
any `5xx`, a transport failure and a candidate that became unavailable just
before sending count as failures. Client errors such as `400` or `422` and
answers from an open circuit are not counted. For a stream the time is the
time to the first response headers.

Per candidate and per provider the Container keeps an exponentially weighted
success average (each attempt moves it 20% of the way), a latency average, the
last 32 attempts for the status page, and the last check. Averages decay back
to healthy with a half-life of `AUTO_ROUTE_HEALTH_HALF_LIFE_SECONDS` (600) while
no new evidence arrives. At most 512 entries are held; the least recently
updated is dropped first.

On Cloudflare a background thread writes changed entries to D1 in batches of up
to 64 every `ROUTE_HEALTH_FLUSH_SECONDS` (60), together with the public
snapshot. The snapshot is also rewritten at least every ten minutes while the
Container is awake. When a Container starts it reads the stored entries once
before writing, so health survives sleep and replacement; a newer entry always
wins, so instances could share the table. No request ever waits on D1 for this:
a failed write keeps the entries for the next pass. `ROUTE_HEALTH_PERSIST=false`
turns persistence off. The rows live in the `route_health` and
`route_health_snapshot` tables from migration `0009_route_health.sql`.

## Health-aware ordering

`AUTO_ROUTE_ORDERING` sets the default for every route (`priority` or `health`)
and `AUTO_ROUTE_ORDERING_OVERRIDES` sets individual routes, for example
`auto:glm-5.2=health,auto:image=priority`. The default is `priority`: the
configured order, exactly as before.

With `health` each candidate receives a score:

```text
score = success - latency_weight × latency / (latency + 10 s) - cost_weight × relative price
```

`success` is the decayed success average (1.0 without evidence), `latency` the
decayed latency average, and the relative price is the candidate's
`MODEL_PRICING_USD_PER_MILLION` input plus output price divided by the most
expensive priced candidate on the route. Starting from the configured order, a
candidate moves ahead of the one before it only when its score is higher by more
than `AUTO_ROUTE_SCORE_MARGIN`. Candidates whose provider circuit is open go
last; they are still tried when nothing else can serve, and answer at once.
The result depends only on the recorded figures and the configured order, so it
is reproducible in tests.

A provider that failed is not starved: its score decays back toward healthy, so
within a few half-lives it returns to its configured place and real traffic
tests it again; a successful free check moves it back faster. For quicker
recovery, `AUTO_ROUTE_EXPLORE_EVERY=N` sends every Nth request on a route to the
candidate heard from least recently (`X-MultiLLM-Auto-Ordering: health-probe`).
It is off by default because such a probe can cost a caller a slow attempt.

| Setting | Default | Purpose |
| --- | --- | --- |
| `AUTO_ROUTE_ORDERING` | `priority` | `priority` or `health` for every route |
| `AUTO_ROUTE_ORDERING_OVERRIDES` | empty | `route=mode` pairs that win over the default |
| `AUTO_ROUTE_HEALTH_HALF_LIFE_SECONDS` | `600` | How fast old evidence fades (30 to 86400) |
| `AUTO_ROUTE_LATENCY_WEIGHT` | `0.2` | Weight of the latency penalty (0 to 1) |
| `AUTO_ROUTE_COST_WEIGHT` | `0` | Weight of the relative price (0 to 1); needs `MODEL_PRICING_USD_PER_MILLION` |
| `AUTO_ROUTE_SCORE_MARGIN` | `0.05` | Score lead needed to pass an earlier candidate |
| `AUTO_ROUTE_EXPLORE_EVERY` | `0` | Probe the stalest candidate every N requests; 0 is off |
| `ROUTE_HEALTH_FLUSH_SECONDS` | `60` | Interval between D1 writes (10 to 3600) |
| `ROUTE_HEALTH_PERSIST` | `true` | Store health in D1 when the Worker provides it |

The Operations API (`GET /admin/auto-routes`) reports each route's `ordering`
and each candidate's `health`.

## Scheduled checks and keep-warm

The Worker has a cron trigger that runs every five minutes
(`triggers.crons` in `wrangler.jsonc`). Every `HEALTH_CHECK_INTERVAL_MINUTES`
(30, at least 5) it asks the Container to run the free checks at
`POST /v1/health/checks`, authenticated with the Worker's `ADMIN_API_KEY`. The
Container requests the model list (`GET /v1/models` or the provider's
equivalent) of every provider used by an automatic route that has such an
endpoint and a configured credential. A model list proves the credential and the
connection and never generates anything. Providers without one, such as Gemini
and Cloudflare AI, are reported as `no_free_check`. Results update the status
page and nudge the provider's candidates, then the snapshot is written to D1.
An administrator can call the same endpoint by hand; it returns each provider's
result, HTTP status and time.

The Container sleeps 15 minutes after its last request (`sleepAfter`). The
checks do not change that:

| Setting (Worker vars) | Default | Behaviour |
| --- | --- | --- |
| `HEALTH_CHECKS_WAKE` | `false` | `false`: checks run only while the Container is already running, and reach it without renewing its sleep timer. `true`: a check starts a sleeping Container and keeps it awake for another 15 minutes |
| `KEEP_WARM` | `false` | `true`: every five-minute tick requests `/healthz`, so the Container never sleeps and checks always run |
| `HEALTH_CHECK_INTERVAL_MINUTES` | `30` | Minutes between checks; ticks at whole multiples of it (UTC) run them |

The defaults keep the scale-to-zero cost profile: a deployment that is idle
overnight stays asleep, and its status page shows the last stored figures.

Keep-warm removes the cold start after idle periods but keeps a `basic`
instance (1/4 vCPU, 1 GiB memory, 4 GB disk) running all month, about 730
hours. On the Workers Paid plan that is roughly 705 GiB-hours of memory beyond
the 25 included ($0.0000025 per GiB-second, about $6.35) and 2,720 GB-hours of
disk beyond the 200 included ($0.00000007 per GB-second, about $0.69): about
$7 a month on top of the plan, before CPU. CPU is billed only while active, and
an idle Container stays well inside the 375 included vCPU-minutes. The figures
assume the included allowances are not already used by normal traffic; see
[Containers pricing](https://developers.cloudflare.com/containers/pricing/).
The cron itself adds about 8,700 Worker invocations a month.

## Operator steps

1. Apply the D1 migration before deploying code that uses it:
   `npx wrangler d1 migrations apply multillm-intelligence --remote`, or run
   `npm run deploy`, which applies and verifies migrations first. Until
   `0009_route_health.sql` is applied, `/ready` reports `d1_schema_missing`.
2. Deploying `wrangler.jsonc` creates the cron trigger; new or changed triggers
   can take up to 15 minutes to start.
3. Set `KEEP_WARM`, `HEALTH_CHECKS_WAKE` and `HEALTH_CHECK_INTERVAL_MINUTES` in
   the Worker's `vars`, and the Container settings above in the Worker's
   variables; the Worker passes them to the Container.
