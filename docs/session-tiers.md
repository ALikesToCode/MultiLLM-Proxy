# Role-scoped sticky session tiers

Session tiers keep an approved route stable across tool calls in the `main`,
`delegation` and `aux` lanes. They are disabled by default:

```text
SESSION_TIER_MODE=off
SESSION_TIER_TTL_SECONDS=1800
```

With the feature disabled, existing routing, response headers and storage are
unchanged. An empty setting uses its default. A malformed mode or TTL disables
the feature and logs one warning without its value. The TTL must be 1–86400 seconds.

Enable sticky routing with `SESSION_TIER_MODE=sticky`. Requests without tier
metadata continue to use ordinary routing. An explicit model or pinned roleplay
route remains caller-selected and never acquires a tier binding.

Managed Chat Completions requests use this metadata alongside the normal body:

```json
{
  "model": "auto:intelligence",
  "messages": [{"role": "user", "content": "Continue the task."}],
  "session_tier": {
    "session": "example-session",
    "lane": "main",
    "approved_model": "openai:reviewed-model",
    "approved_tier": 2
  }
}
```

The managed dispatcher must bind the session to its authenticated principal,
remove this metadata before request parsing and upstream dispatch, and supply
the current reviewed policy revision. `prepare_session_tier` accepts only already
eligible candidates and an optional credential/cooldown admission predicate.
`select_candidates(..., session_tier=turn)` preserves the existing eligibility
checks and applies the lane's ordering. Finalization records the actual candidate
and tool-call IDs after classified completion. It does not authorize another attempt.

Public roleplay requests carry the approval inside `routing`:

```json
{
  "model": "roleplay:intelligence",
  "session_id": "example-session",
  "messages": [{"role": "user", "content": "Continue."}],
  "routing": {
    "session_tier": {
      "lane": "main",
      "approved_model": "opencode:glm-5.3-flash",
      "approved_tier": 1
    }
  }
}
```

Roleplay storage belongs to the existing authenticated session's Durable Object.
The tier is an explicit numeric label, not a model-quality measurement. Roleplay
has no reviewed numeric tier catalogue, so fallback can use only an identical
native model name on another eligible provider. Provider aliases with different
native names do not qualify. General managed candidates must match both the approved
native model and reviewed `quality_tier`. Billing, entitlement, capability, context limits,
credential availability and cooldown always take precedence over stickiness.

A different approved model or tier takes effect only at a user-turn boundary
after successful completion and all matching tool results. Partial or unrelated
results leave the outstanding calls unresolved. A continuation without a new user
turn cannot change the approval. Failures, cancellations and ambiguous results
cannot open a safe boundary. Streaming roleplay observes bounded tool-call IDs
without changing response bytes; incomplete or oversized observations prevent a
safe boundary. Unknown streamed tool state stays unresolved until expiry or revision
invalidation. Roleplay automatic continuation, refusal fallback and output-contract
repair are disabled for an opted-in tier turn; existing pre-output fallback rules
still apply within the constrained candidate list.

The approved route and actual fallback route are separate fields. A fallback is
recorded honestly and preferred on subsequent turns without rewriting the approved
route. Expiry, a policy revision change or confirmed credential failure invalidates
only the affected lane. An in-flight request holds a lease; another request for
that lane receives HTTP 409 `session_tier_busy`. Late completion cannot overwrite
a replacement lease. A lease expires with the lane's TTL, including after a crash.

Bindings retain hashed principal/session identities, lane, route identifiers, a
hashed revision, expiry, a completed-generation marker, hashed outstanding tool
IDs and a lease. They add no prompt, response, tool arguments or result content
retention. Existing zero-retention restrictions and response headers still apply.
Live bindings expire after the configured idle TTL; the local adapter prunes
expired entries during access and the Durable Object reuses its bounded three-lane
storage. This feature does not create a transcript or change existing conversation
memory behavior.

The local Python adapter is process-local and permits at most 10,000 live lanes.
Use the injected SQLite adapter when persistence across restarts is required;
it also limits live rows to 10,000. Apply the additive `session_tiers` migration
before using that adapter. It never creates tables during a request. Missing or
unavailable enabled storage returns HTTP 503 `session_tier_storage_unavailable`.
Capacity exhaustion and unavailable approved routes return HTTP 503; invalid
approval metadata returns HTTP 400. Tool markers are limited to 128 outstanding
calls, with identifiers at most 200 characters. Worker storage needs no D1 table
because roleplay retains its existing Durable Object ownership.

Stickiness does not reserve spend, guarantee a provider's capabilities or metering,
grant paid access, or promote a model autonomously. Every approval still passes
the existing operator policy and budget checks. A remote classifier cannot choose
the approved tier. Storage failure is an error, never a synthetic completion.
