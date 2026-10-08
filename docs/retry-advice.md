# Bounded upstream Retry-After advice

`UPSTREAM_RETRY_AFTER_ADVICE_ENABLED` defaults to false. Unset or empty settings
use their defaults. Disabled traffic keeps its existing retries, waits, headers,
response bodies and free-pool cooldown timing. Native Worker and raw Flask paths
continue to forward upstream bytes without parsing or scheduling retries.

Enable local advice with:

```text
UPSTREAM_RETRY_AFTER_ADVICE_ENABLED=true
UPSTREAM_RETRY_AFTER_MAX_SECONDS=3600
```

The maximum defaults to 3600 seconds and accepts whole seconds from 1 to 604800,
matching the existing free-pool cooldown ceiling. An invalid flag or enabled
maximum disables advice and logs the setting name once per process, without its
value. The maximum is ignored while advice is disabled.

`services.retry_advice.parse_retry_advice` returns immutable local advice with
`source`, `observed_at`, `retry_at`, `delay_seconds` and `scope`. Times are Unix
seconds. It recognizes these formats, using case-insensitive header names:

- `Retry-After`: nonnegative decimal seconds or an HTTP-date with a timezone.
- `X-RateLimit-Reset`: an absolute Unix timestamp in seconds.
- `X-RateLimit-Reset-Requests` and `X-RateLimit-Reset-Tokens`: duration strings,
  such as `1h2m3.4s`, when the matching remaining counter is finite and exhausted.
- `Anthropic-RateLimit-Requests-Reset` and `Anthropic-RateLimit-Tokens-Reset`:
  ISO timestamps with a timezone, when the matching remaining counter is exhausted.

Malformed, nonfinite, zero-delay and stale hints are ignored. Individual values
are limited to 512 characters. When several active hints are valid, the latest
reset wins so an exhausted dimension is not bypassed. Only local advice is
clamped; the upstream header is never replaced. With observation time 100,
`Retry-After: 20` yields retry time 120. With maximum 5 it yields local retry time
105, while the header remains `20`.

The [upstream outcome](upstream-outcomes.md) classifier keeps 429 throttling neutral for provider health.
Exhausted remaining counters label advice `quota_exhausted`; other 429 advice
uses `rate_limit`; provider failures use `provider`. Authentication and caller
errors do not supply retry advice. Successful exhausted responses can supply
cooldown advice without changing their health classification.

Managed retries still require the existing method/idempotency/transport policy
and attempt limit. Parsing never grants replay permission. An ambiguous POST or
stream does not gain a retry from headers. While enabled, legacy timeout-body
retries additionally require a safe method or an idempotency key. Connect-timeout
retries remain allowed by the existing policy because nothing reached upstream.
Existing managed response normalization remains in the proxy service.

For an allowed retry, the scheduler waits for the greater of existing backoff
and bounded advice. Invalid or absent advice uses existing backoff. An optional
monotonic `deadline` on `_make_base_request`, or the existing Flask
`g.cascade_deadline`, must cover the entire wait. A refused wait returns the
original upstream result. The scheduler rechecks the deadline after sleeping and
does not dispatch a late retry. Without a shared deadline, existing per-attempt
timeouts remain unchanged; the feature does not create a request-wide deadline
or reserve time for another attempt. Free-pool `retry_seconds` uses the same
bounded parser while enabled, including a bounded fallback cooldown.

There are no new routes, response headers, storage tables or dependencies. Advice
reads headers only and retains no credentials, prompts or response content.
Existing cooldown storage and its monotonic extension rules remain in use;
enabling a lower maximum does not shorten a previously stored cooldown. Advice
is neither proof of provider capacity nor authorization for additional cost.
Retries can consume additional quota only when already authorized by transport
policy. The Worker forwards both settings to the Container.
