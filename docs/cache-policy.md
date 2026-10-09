# Cache policy isolation

The managed `POST /v1/chat/completions` endpoint can isolate complete response cache
entries by the current route and guardrail policy. Flask owns this cache; the Worker
forwards requests and responses. There is no new native Worker cache.

## Defaults and opt-in

`RESPONSE_CACHE_ENABLED=true`, `RESPONSE_CACHE_TTL_SECONDS=300`, and
`RESPONSE_CACHE_POLICY_REVISION=legacy` preserve existing behavior. Each request must
still opt in with `X-MultiLLM-Cache: on`. Without that header, the cache is untouched.
The `legacy` revision preserves the original internal cache key format as well as
response bodies, headers, storage bounds and accounting. It does not add policy
isolation. Existing deterministic, non-streaming, single-choice eligibility applies.

Enable policy isolation on the Container with:

```sh
RESPONSE_CACHE_POLICY_REVISION=v1
```

Example request (authorization is supplied separately by the existing client):

```http
POST /v1/chat/completions
Content-Type: application/json
X-MultiLLM-Cache: on

{"model":"opencode:glm-5.2","messages":[{"role":"user","content":"2+2?"}],"temperature":0}
```

Disable response caching with `RESPONSE_CACHE_ENABLED=false`, or omit the opt-in
header on a request. `Cache-Control: no-store` bypasses both reads and writes without
adding a cache header. `X-MultiLLM-Cache: refresh` and `Cache-Control: no-cache`
continue to generate a fresh response. `Cache-Control: max-age=N` limits hit age.

Only `legacy` and `v1` revisions are supported. An unset or empty value means `legacy`.
An unknown revision bypasses reads and writes with the existing `X-MultiLLM-Cache: bypass` marker on eligible
opted-in responses. It leaves normal dispatch and error handling unchanged.

## Identity

The `v1` internal key format adds the revision and a SHA-256 digest of canonical
policy JSON to the existing principal, request path and canonical body identity.
Object member ordering does not affect either digest. Ordered route candidates
remain ordered; model permission patterns are lowercased, deduplicated and sorted.
The policy includes:

- Direct provider/model, model enablement status, resolved Chat endpoint and
  applicable OpenCode Zen or AIHubMix backup endpoint.
- Automatic route ID, saved revision, ordered candidate identities and priority
  ordering. Route configuration is read from the current main route service.
- The authenticated key's model permission patterns and effective secret scan mode,
  including per-key overrides and the deployment default.
- Retention mode and revision, and the managed Chat workflow version, together with
  prompt-cache, NanoGPT billing/speed and adaptive GLM context settings.

Principal isolation is unchanged: the authenticated user and a SHA-256 digest of
the presented API key scope every entry. Raw API keys are never stored as cache keys
or included in policy JSON. No prompts, completions or policy values are logged.

Changing from `legacy` to `v1` makes legacy entries unreachable in the new namespace.
Changing any resolved policy component likewise selects a different key. Nothing
purges the store: old entries remain bounded by TTL and eviction. Switching back
can reuse still-live entries in that earlier namespace. An in-flight `v1` response
is not stored if its policy or revision changed before completion; its normal
response body and cache miss marker are preserved.

## Retention and workflow boundary

Current main has no general content-retention policy service. Its explicit snapshot
is `{"mode":"legacy","revision":"legacy"}`, and the workflow version is `chat-v1`.
Trusted server middleware can supply `g.multillm_retention_policy` with exactly
`mode` and `revision` fields and `g.multillm_workflow_version` before dispatch.
These are internal collaborators, never client-controlled headers or body fields.
Only the existing `legacy` storage mode is understood; other retention modes or
malformed snapshots bypass caching. A future retention feature must implement its
own controls and extend this contract before enabling caching for another mode.
This feature does not introduce zero-content retention or a workflow management API.

## Bounds and limitations

`v1` bypasses caching when the policy cannot be loaded safely, a model is disabled,
or a route's effective plan is unavailable. Free pools, cascades, health-ordered
automatic routes, query parameters and provider-selection headers bypass because
their effective workflow is not fully represented. Endpoints carrying credentials
in userinfo, query strings or fragments also bypass. Normal dispatch still handles
availability, authorization and errors. Unknown policy never receives a shared
fallback identity. Default `legacy` behavior for these requests is unchanged.

This is the existing bounded in-process store, lost on Container sleep or restart.
Defaults remain 512 entries, 16 MiB total response bytes and 300 seconds TTL. Existing
configuration clamps remain: 1–10,000 entries, 64 KiB–256 MiB total bytes, 1–86,400
seconds TTL. Bodies larger than one eighth of the byte budget are not stored.
Errors, streaming/passthrough responses, truncated/filtered finishes and runnable
tool calls are never stored. Concurrent misses generate independently; this feature
adds no request coalescing, synthetic answers or retry permission.

A hit replays a previously completed result with existing cache provenance and
no-new-provider accounting. A miss or bypass can incur ordinary upstream cost.
Isolation is not a live provider capability, metering or deployment certification.
Route/policy reads are not a cross-service atomic configuration transaction; the
completion-time comparison prevents detected changes from being stored but does
not lock administrator writes. The Worker forwards
`RESPONSE_CACHE_POLICY_REVISION` to the Container with its other environment settings.
