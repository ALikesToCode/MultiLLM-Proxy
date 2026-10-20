# Key data controls

For an app whose requests carry personal data, set controls through the existing
administrator-only `PUT /users/{username}/controls` endpoint or the user's Limits
form:

```json
{
  "official_only": true,
  "forced_provider_preferences": {"data_collection": "deny"}
}
```

`official_only` defaults to false. A restricted key receives HTTP 403 with
`provider_class_not_allowed` for a direct non-official provider. Auto, intelligence
and cascade routes filter concrete candidates before dispatch, including fallback
and background submissions. No eligible candidate means refusal. Model allowlists
still apply independently. Disabling a control requires an administrator; request
headers and routing overrides cannot disable it.

`forced_provider_preferences` is an optional JSON object, limited to 4 KiB. It is
merged recursively into the `provider` object on every OpenRouter request made for
the key, including raw passthrough and internally routed requests. Administrator
values win; a caller's `data_collection: "deny"` stays `deny` even if the stored
value says `allow`. Other caller preferences remain unless overridden. See
[provider routing](https://openrouter.ai/docs/guides/routing/provider-selection)
for the supported preference fields. This control does not change another
provider's request format.

Realtime ticket issuance and socket admission re-read current key data controls.
Restricted keys cannot open non-official models. Realtime refuses any key with
forced preferences, including an empty object, because those preferences cannot
be enforced throughout the socket session. Existing tickets do not bypass a
subsequent control change.

Requests from keys with either data control are excluded from shadow sampling.
Stored samples recheck their source key before replay and before every candidate
or judge dispatch, including three-arm comparisons. Controlled, inactive, missing
or unverifiable source accounts are skipped; existing samples expire normally.

Restricted Gemini requests reject caller credential overrides in query parameters,
provider headers or a separate Authorization header. Only the operator's current
`GEMINI_API_KEY` binding is covered by `GEMINI_DATA_TIER=paid`; a missing binding
fails closed, without a cached or legacy-alias fallback. The same restriction
applies to automatic fallback and background dispatch.

## Provider classes

`providers/data-classes.json` is shared by Flask and the Worker. Registry adapters
expose `data_class`; classification follows the configured provider namespace,
not a claim in a request or a model's name. Unknown namespaces are conservatively
`reseller`, and unknown `ce-*` namespaces are `subscription`.

| Class | Provider namespaces | Evidence and scope |
| --- | --- | --- |
| official | openrouter, openai, anthropic, azure | Direct API endpoints in `config.py` and `providers/registry.py`; [router API](https://openrouter.ai/docs/quickstart), [direct model API](https://platform.openai.com/docs/api-reference), [Messages API](https://platform.claude.com/docs/en/api/overview), [Azure inference](https://learn.microsoft.com/en-us/azure/ai-foundry/model-inference/how-to/use-chat-completions). |
| official | groq, together, cerebras, xai | Direct inference service endpoints; [Groq](https://console.groq.com/docs/overview), [Together](https://docs.together.ai/docs/quickstart), [Cerebras](https://inference-docs.cerebras.ai/quickstart), [xAI](https://docs.x.ai/docs/overview). |
| official | scaleway, sambanova, hyperbolic | Configured service APIs; [Scaleway](https://www.scaleway.com/en/docs/generative-apis/quickstart/), [SambaNova](https://docs.sambanova.ai/docs/en/get-started/quickstart), [Hyperbolic](https://docs.hyperbolic.xyz/docs/getting-started). The current Hyperbolic overview emphasizes compute; the historical inference endpoint's availability needs operator confirmation. |
| official | googleai, cloudflare | Cloud-hosted inference endpoints; [Google Cloud](https://cloud.google.com/vertex-ai/docs/start/introduction-unified-platform), [Workers AI](https://developers.cloudflare.com/workers-ai/). |
| official or free | gemini | Defaults to `free`. Set `GEMINI_DATA_TIER=paid` only after confirming every credential used for this namespace belongs to the paid tier. [Pricing and data-use distinctions](https://ai.google.dev/gemini-api/docs/pricing). The proxy cannot discover an account's tier. |
| subscription | ce-gpt-plus, ce-gpt-pro, ce-grok-heavy, ce-claude-kiro, ce-claude-kiro-cheap, ce-claude-max, ce-image, codex-easy | Subscription/pool adapters in `providers/codex_everywhere.py`, `providers/image_relays.py` and the existing README. Pool provenance and current vendor terms remain unverified; these are excluded from restricted keys. |
| subscription | opencode, cline-pass, kimi-code, mimo | Configured coding-plan endpoints, rather than ordinary pay-as-you-go endpoints: [Go](https://opencode.ai/docs/go/), [Cline Pass](https://docs.cline.bot/getting-started/clinepass), [Kimi Code membership](https://www.kimi.com/code/docs/en/kimi-code/membership), [MiMo plan distinction](https://platform.xiaomimimo.com/static/docs/price/pay-as-you-go.md). |
| reseller | aihubmix, navyai, linkapi, nanogpt, a6api, aimlapi, ephone, gguu, gguu-grok, latix | Relay endpoints in `config.py`, `providers/image_relays.py` and the existing README. [Navy's multi-provider API](https://api.navy/docs) also uses subscription billing; the reseller tag takes precedence here. The other relays' current sourcing and data terms remain unverified. |
| reseller | chutes, nineteen | Conservative classification of distributed inference networks: [Chutes](https://chutes.ai/docs/guides/starter-guide), [Nineteen](https://nineteen.ai/app). Whether a separately reviewed deployment should qualify as official remains an operator decision. |
| free | free, gemma, palm | Explicit free pools and conservatively excluded legacy Google aliases; the latter's credential tier is not established by the adapters. |
| free | ollama, vllm, lmstudio, llamacpp, sglang | Operator-configured local inference adapters in `providers/local_inference.py`. This is a conservative exclusion within the four-class vocabulary, not a claim about hosting cost or local data handling. |

`FREE_ROUTE_FREE_TIER_PROVIDERS` takes precedence over the table, including the
Gemini paid setting. A class describes the integration; it does not certify
retention, training policy, a data-processing agreement, or a custom base URL.
Review operator-supplied endpoints and credentials before admitting traffic.

## Migration and usage

Apply `0041_key_data_guards.sql`, `0042_usage_token_details.sql` and
`0043_integration_data_policy.sql` through the tracked migration runner first.
Deploy the matching Worker (including the private Knowledge Worker) next, then
the Container. Enable controls only after both runtimes enforce them. Do not
roll back to a runtime that lacks enforcement while restricted keys are enabled.
Repeat the tracked migration command rather than replaying bare ALTER statements.
An old Worker response, missing column or unsupported policy envelope makes the
new Container refuse generation; it never supplies unrestricted defaults.

The version-1 `data_policy` envelope requires `version`, `official_only` and
`forced_provider_preferences`, with explicit nulls for unrestricted values.
Bootstrap administrative recovery remains available for management, but cannot
authorise provider dispatch without a current durable account and verified policy.

`services/provider_dispatch.py` and `worker/provider-dispatch.mjs` are the outbound
provider boundaries. HTTP adapters and SDK/binding operations reread the account
at every dispatch, including retries, fallbacks, video polls, background work,
Realtime, roleplay and Knowledge/MCP. Deferred work carries only identity; it does
not carry a policy snapshot. Stored Knowledge sources and ingestion jobs retain
their source account identity across scheduling, retries and reconciliation.
Imported-skill watches also retain the importing account; legacy imports without
that identity refuse upstream checks until explicitly imported again.
Restricted requests replace cached credentials with
the current attested operator binding, and reject caller Gemini credentials.
Forced routing preferences merge at the final JSON submission. Realtime and
roleplay refuse forced preferences because their full transports cannot enforce
them. Missing accounts, missing fields, malformed envelopes and store outages
refuse dispatch. The outbound inventory test pins reviewed transport modules and
rejects new call sites; private persistence, storage management, authentication,
telemetry, public capability metadata and webhook delivery are classified separately.

New columns hold
the two controls and provider-reported `cached_input_tokens` / `reasoning_tokens`.
Existing keys remain unrestricted and existing event details remain null; daily
totals start at zero. Flask adds the same columns to its SQLite or PostgreSQL
ledger. Missing or malformed durable controls fail closed on dispatch.

Chat Completions and Responses usage-detail objects, including final streaming
usage, populate the counters. Native Messages cache-read and cache-creation input
counts are included in total input, while only cache reads count as cache hits.
Reasoning is a detail of output usage and is not added to output a second time.
Absent details remain unknown on individual events. Recording these counters does
not depend on the optional prompt-cache price-bucket feature. See the router's
[usage accounting](https://openrouter.ai/docs/cookbook/administration/usage-accounting).

The Usage page shows cache-hit rate and reasoning tokens per key and model.
Cache-hit rate is reported cached input divided by all ledger input in that
group, multiplied by 100; upstreams that omit cache details lower the observed
rate. This is not a request-level cache-hit percentage. No webhook budget alert
is included.
