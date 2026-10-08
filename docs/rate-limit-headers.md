# Rate-limit advisory headers

`RATE_LIMIT_HEADERS_ENABLED` defaults to false. Missing, empty, `false`, `0`,
`no` and `off` leave response headers and usage JSON unchanged. Enable with
`true`, `1`, `yes` or `on`. Values are case insensitive and trimmed. Malformed
values disable advice and log one warning per process without the value.

Managed, authenticated responses with a gateway admission snapshot can expose:

- `X-MultiLLM-RateLimit-Limit`: the selected gateway counter's positive limit.
- `X-MultiLLM-RateLimit-Remaining`: capacity at admission, after reserving the
  current request. A known exhausted counter has remaining `0`.
- `X-MultiLLM-RateLimit-Reset`: positive integer seconds until capacity expires,
  captured at admission rather than recalculated when the response finishes.

Unknown, unlimited, invalid and unavailable fields are omitted. No header contains
principal names, key prefixes, client addresses, provider credentials or provider
quota information. Provider `RateLimit-*`, `X-RateLimit-*` and `Retry-After`
headers are preserved. Raw provider paths receive no advisory headers. Streaming
bodies are forwarded unchanged; advice does not read or buffer them.

With advice disabled, a successful managed response has no new headers. With
advice enabled, a request admitted against a two-request minute limit can return:

```http
HTTP/1.1 200 OK
X-MultiLLM-RateLimit-Limit: 2
X-MultiLLM-RateLimit-Remaining: 1
X-MultiLLM-RateLimit-Reset: 60
```

An exhausted minute counter, observed 17 seconds after the first admission:

```http
HTTP/1.1 429 Too Many Requests
X-MultiLLM-RateLimit-Limit: 2
X-MultiLLM-RateLimit-Remaining: 0
X-MultiLLM-RateLimit-Reset: 43
Retry-After: 43
```

The ordinary counter is requests per minute. On rejection, the selected counter
follows the existing enforcement order: RPM, TPM, then daily requests. The JSON
error identifies the rejected counter. Daily reset advice uses the rolling
24-hour window, not midnight. A token denial conservatively uses the last token
usage expiry; advice is not a guarantee that the next request will fit. Existing
replay rules remain authoritative: neither these headers nor a 429 authorizes a
retry of a request that may have produced output. Upstream errors and bodies are
not replaced. Only a known gateway rejection fills a missing `Retry-After`.

SQLite snapshots are read under the admission transaction. Request-local copies
survive preprocessing, finalization and subsequent admissions unchanged. The D1
ledger supplies its current gateway counts, including cached shared figures;
precise expiry is unavailable and `Reset` is omitted. D1 consistency remains
bounded by its existing synchronization behavior; this feature does not make it
a globally atomic limiter. When exact expiry is unavailable on a gateway denial,
`Retry-After` uses the applicable full rolling window as conservative advice.

When enabled, `GET /v1/usage` adds `rate_limits`, a mapping of at most 32 observed
providers to bounded counter snapshots for the authenticated caller. Selected
principal responses from `/usage/data` include the same shape, respecting existing
administrator authorization. Usage reads are current snapshots, not admissions:
no request is reserved or charged. SQLite reads use a read-only transaction;
missing storage or tables returns an empty mapping. D1 usage snapshots are empty
because its existing public interface lacks a bounded provider inventory; there
is no additional D1 synchronization or remote request. These are gateway limits,
not monetary budgets or provider free quotas.

No new table, durable state, remote call or content retention is introduced.
Copies live only for the current request. Enabled SQLite requests add one bounded
expiry query under the existing lock; usage reads have a 32-provider bound.
Disabled traffic does not query expiry or usage storage. This feature adds no
provider token cost and does not change admission, reservation or retry policy.

## Where the headers apply

Flask adds the headers to managed `/v1/` responses; raw provider routes are
excluded. Counters are never read from request headers or payloads. Requests the
Worker forwards to the Container keep the Container's headers unchanged. Native
Worker routes (codex-easy, linkapi, opencode direct) enforce no gateway request
counters, so their responses carry no advisory headers. Set
`RATE_LIMIT_HEADERS_ENABLED` on the Container.
