# LinkAPI and Cloudflare Optimization Design

## Objective

Add LinkAPI as a first-class provider while minimizing latency, Cloudflare Container runtime, memory pressure, and accidental duplicate model charges. Native Claude Messages, Gemini `generateContent`, and OpenAI Responses traffic must retain its original authentication, schema, status code, headers, and streaming event format.

## Current constraints

- A Cloudflare Worker fronts one named `basic` Container instance.
- Almost every request currently wakes the Container and keeps it eligible to run for a 15-minute idle tail.
- The Worker and the Flask proxy buffer request bodies before forwarding them.
- The generic Flask proxy always injects Bearer authentication and normalizes streams as OpenAI chat chunks.
- Application state and spend controls use SQLite files in `/tmp`; shortening the Container sleep window or adding instances would reset or fragment that state.
- Generation POSTs cannot be retried safely unless the upstream protocol provides a proven idempotency guarantee.

## Selected architecture

Use a hybrid data-plane/control-plane design:

1. The Worker handles `/linkapi/*` directly and forwards the remainder of the path to the configurable LinkAPI origin.
2. The direct path authenticates the proxy caller with the protocol-native credential location, removes that credential, then injects `LINKAPI_KEY` in LinkAPI's required location:
   - OpenAI: `Authorization: Bearer ...`
   - Claude: `x-api-key: ...` plus `anthropic-version`
   - Gemini: a replacement `key` query parameter
3. Request and response bodies remain streams. The Worker does not parse, translate, buffer, normalize, append `[DONE]`, or automatically retry generation requests.
4. The Flask provider registry also gains LinkAPI so dashboard, local, Vercel, and unified chat usage remain available. Native LinkAPI catch-all traffic uses path-sensitive auth and raw pass-through behavior.
5. Existing providers and routes retain their behavior.

This makes LinkAPI's latency-sensitive path a single edge-to-upstream hop and avoids waking the paid Container for those calls. It also preserves the semantic SSE events required by Claude tool use, Gemini function calling, and the OpenAI Responses API.

## Worker request flow

```text
Client native SDK
  -> /linkapi/<native path>
  -> validate ADMIN_API_KEY in Bearer, x-api-key, x-goog-api-key, or ?key
  -> strip downstream credentials and hop-by-hop headers
  -> inject LINKAPI_KEY for the selected native protocol
  -> stream fetch to LinkAPI
  -> stream the unmodified upstream body/status/safe headers to the client
```

Only `/linkapi/v1beta/*` uses the upstream query key. Incoming query credentials are never reflected or logged. A configurable `LINKAPI_BASE_URL` permits deliberate regional selection, but there is no automatic POST failover because a timeout may occur after a billable generation has already started.

## Safe platform optimizations

- Remove the redundant `startAndWaitForPorts()` call; `container.fetch()` already starts the Container and waits for its default port.
- Stream requests into the Container rather than calling `arrayBuffer()`.
- Enable and propagate request cancellation so disconnected clients stop downstream work where the platform and upstream honor abort signals.
- Remove routine per-request environment logging and sample observability logs instead of recording every invocation.
- Keep a cheap Worker liveness endpoint and add a separate Container-backed readiness endpoint.
- Return a real unavailable status if the Container cannot serve the dashboard rather than masking failure with a 200 response.

## Optimizations intentionally deferred

- Do not reduce `sleepAfter`, switch from `basic` to `lite`, or increase `max_instances` without measured memory/concurrency data.
- Do not scale the Container horizontally until mutable SQLite state and rate/spend controls move to durable shared storage.
- Do not cache model-generation responses or LinkAPI pricing metadata in the request path.
- Do not upgrade deployment dependencies in the provider feature commits; dependency changes have separate operational risk and no direct request-runtime benefit.

## Security and correctness requirements

- Support native client proxy authentication without exposing the upstream secret.
- Use timing-resistant proxy-key comparison on Worker-native routes.
- Preserve repeated query parameters while replacing only the downstream Gemini key.
- Forward only an explicit set of safe request/response headers.
- Keep CORS protocol headers aligned with the native APIs.
- Never include secret values in tests, logs, errors, URLs returned to clients, commits, or command output.
- Never retry non-idempotent generation POSTs automatically.

## Verification strategy

Every behavior change starts with a focused failing test. The Worker tests must prove protocol auth replacement, path/query mapping, byte-for-byte native SSE pass-through, streaming request forwarding, cancellation propagation, no redundant startup RPC, and readiness behavior. Python tests must prove provider registration, the `LINKAPI_KEY` alias, dynamic model acceptance, native auth, raw streaming, and native Responses handling. Final verification runs the complete Python and Worker suites plus static secret, schema, lint, and type checks without invoking `build` or `dev`.
