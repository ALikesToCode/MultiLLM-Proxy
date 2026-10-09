# Spend, pool and health alerts

Alerts report gateway spend estimates, unknown-price coverage, open provider circuits,
exhausted credential pools and recent provider health failures. They never start a
generation or a health probe. Paid health probes require their own explicit action.

Alerts are disabled by default. Empty environment values use the defaults:

```text
GATEWAY_ALERTS_ENABLED=false
GATEWAY_ALERT_WEBHOOK_ALLOWLIST=[]
```

Enable the feature and allow an exact HTTPS origin before configuring delivery:

```text
GATEWAY_ALERTS_ENABLED=true
GATEWAY_ALERT_WEBHOOK_ALLOWLIST=["https://hooks.example"]
```

The allowlist accepts at most 20 public DNS origins on port 443. IP literals, local
hostnames, credentials, query strings, fragments and redirects are rejected. A
destination can have a path, but it must belong to an allowlisted origin. Addresses
are stored as private configuration and are omitted from status and alert payloads.
Use an operator-controlled origin with public DNS; this origin policy does not pin DNS
answers or certify the destination's downstream behavior. Remove the origin or clear
the allowlist to stop delivery without changing generation traffic.

`GET /admin/alerts` requires an administrator's existing dashboard session. It returns
the current revision, normalized rules, whether a webhook is configured, and up to
100 recent event states. All responses have `Cache-Control: no-store`. POST retains
the dashboard's CSRF protection; supply the existing CSRF token with the request.
Use the revision from GET to replace the configuration:

```json
{
  "revision": 0,
  "destination": "https://hooks.example/operator-hook",
  "rules": [
    {"kind": "spend", "period": "day", "budget_usd": 25},
    {"kind": "unknown_price", "period": "day"},
    {"kind": "provider_circuit", "provider": "openai"},
    {"kind": "pool_exhaustion", "provider": "nanogpt"},
    {"kind": "provider_health", "provider": "openai", "failures": 3}
  ]
}
```

Spend rules use an operator-supplied global gateway budget in USD, with default
thresholds of 85% and 100%. `day` and `month` use UTC ledger periods. At most 20 rules
and four distinct spend thresholds per rule are accepted. Set `thresholds` explicitly
to change the spend percentages. An unknown-price rule defaults to alerting whenever
any recorded request lacks a price; `threshold_percent` can raise that minimum.
Provider names must belong to the reviewed provider catalog. An empty rule list stops
new observations. Replacing configuration fails waiting events from the old revision.

Spend payloads label their basis as `gateway_cost_estimate`; they are estimates from
recorded usage and configured model prices, never actual provider invoices. Coverage
payloads label `unknown_price_coverage`; an unpriced request is unknown, not free.
Provider alerts label `observed_health`. Health failure counts expire after one hour.
No prompt, response, tool content, raw credential, username or recipient appears in
an alert payload, status response or delivery diagnostic. Numeric observations can
still reveal aggregate traffic and spend; protect the webhook's access and retention.

The durable store deduplicates each event type, rule, threshold, period and revision
for 15 minutes. A sustained condition can create a new event after that interval.
Delivery is limited to ten events per scheduled run and three attempts per event,
with a hard three-second timeout per attempt. Retries are due after 60 seconds and
only run on the next scheduled invocation. Delivery claims prevent concurrent
runners from sending the same event simultaneously. Timeouts and process termination
can leave ambiguous delivery: consumers should deduplicate the stable event identity
and rule/revision/occurrence fields. A successful delivery means the destination
returned HTTP 2xx; it does not prove an operator read the notification.

States distinguish waiting, delivered and failed events; `attempts`,
`last_attempt_at` and a fixed `error_code` expose failures without response bodies.
Each event stores at most three attempt timestamps. History is logically retained
for seven days, physically pruned in batches of 100 during scheduled runs, and capped
at 2,000 dedupe records. A full queue cannot accept a new distinct event until pruning
makes room. Delivery JSON and configuration requests are bounded to 8 KiB; status
responses are bounded to 64 KiB.

Disabled or malformed settings return HTTP 404. Invalid rules and destinations return
400, revision conflicts 409, oversized configuration 413, and unavailable durable
state 503 with `gateway_alert_storage_unavailable`. The feature requires the D1
migration and private state dispatcher. An enabled flag with absent tables fails
closed. Configuration and observation do not deliver webhooks synchronously.

The Worker scheduler calls `runAlertDelivery` with a fixed aggregate collector and
redirect-rejecting transport. The collector receives normalized rules and returns
only `{rule_id, value, basis, window}` observations; a provider window is `current`.
The private dispatcher calls `handleAlertState` only after internal authentication.
The Flask registrar mounts the admin route and exposes `gateway_alert_observer`;
free checks observe existing results through the same service. Generation requests
are never replayed or delayed to send alerts. No live webhook or paid metering check
is needed to run the deterministic tests.
