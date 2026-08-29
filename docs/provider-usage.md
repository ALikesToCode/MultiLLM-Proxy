# Provider usage aggregation

`GET /admin/providers/usage` gives an administrator one credential-safe view of
provider-account allowances and MultiLLM's local operational telemetry. The
route requires a signed administrator dashboard session and returns
`Cache-Control: no-store`.

The endpoint never returns provider credentials or unfiltered upstream
payloads. An upstream failure affects only that provider's entry; the overall
request still returns `200` so the dashboard can display the providers that did
respond.

## Response contract

```json
{
  "object": "provider_usage.list",
  "generated_at": "2026-08-29T12:00:00Z",
  "cache_ttl_seconds": 60,
  "currency": "USD",
  "providers": [
    {
      "provider": "navyai",
      "configured": true,
      "supports_authoritative_usage": true,
      "status": "available",
      "source": {
        "endpoint": "GET /v1/usage",
        "fetched_at": "2026-08-29T12:00:00Z",
        "cached": false
      },
      "account": {"plan": "pro", "state": null},
      "balances": [],
      "windows": [
        {
          "name": "daily",
          "unit": "tokens",
          "limit": 250000,
          "used": 18420,
          "remaining": 231580,
          "percent_used": 7.4,
          "resets_at": "2026-08-30T00:00:00Z",
          "resets_in_ms": 41523000
        }
      ],
      "local": {
        "requests_24h": 3,
        "success_rate": 100.0,
        "error_rate": 0,
        "errors": 0,
        "avg_latency_ms": 125.5,
        "p95_latency_ms": 180.0,
        "last_request_at": "2026-08-29 10:00:00",
        "cost_usd": {
          "estimated": 0.12,
          "actual": 0,
          "effective": 0.12
        }
      },
      "error": null
    }
  ],
  "summary": {
    "providers": 29,
    "configured": 7,
    "authoritative_available": 3,
    "unsupported": 4,
    "unconfigured": 22,
    "errors": 0
  }
}
```

`status` is one of:

- `available`: the provider returned authoritative account usage;
- `error`: the provider supports usage lookup but the lookup failed;
- `unsupported`: credentials exist, but the provider has no configured usage
  adapter;
- `unconfigured`: MultiLLM has no credential for the provider.

## Authoritative sources

| Provider | Upstream source | Normalized data |
| --- | --- | --- |
| NavyAI | `GET /v1/usage` | Plan, daily token allowance, and RPM window |
| NanoGPT | `GET /api/subscription/v1/usage` | Subscription state and daily/monthly operation allowances |
| OpenRouter | `GET /api/v1/key` | Free/paid tier and USD credit usage |

OpenCode Go remains visible with local telemetry and `status: unsupported`.
OpenCode documents inference and model-catalog endpoints, but does not publish
an account-quota API. Its console remains the authoritative source.

NanoGPT usage lookup follows configured key preference order and advances past
definitive credential rejections. It does not expose which key succeeded.

## Caching and timeouts

Authoritative results are cached independently per provider. Local request and
cost telemetry is rebuilt on every endpoint request.

```env
PROVIDER_USAGE_CACHE_TTL_SECONDS=60
PROVIDER_USAGE_TIMEOUT_SECONDS=8
```

Concurrent cache misses for the same provider share one refresh. Different
providers are fetched in parallel. Errors are not cached, allowing the next
dashboard request to recover immediately.

Local costs remain configured estimates unless a request supplied provider
cost data. They are operational signals, not provider invoices.

## Design rationale

The endpoint uses normalized provider adapters rather than forwarding raw
account responses. This keeps provider schema drift and sensitive fields behind
one interface while giving the dashboard a stable contract. A raw-payload
endpoint was rejected because every caller would need provider-specific parsing
and sanitization. A persistent background polling system was deferred because
short-lived on-demand caching solves the current control-plane need without a
new scheduler or database ownership boundary.
