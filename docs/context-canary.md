# Context-leak canary tokens

Context canaries detect disclosure of a request-specific marker in opted-in managed generation. They do not detect every context leak. An absent marker is not proof that private instructions or other context stayed private.

## Configuration

`CONTEXT_CANARY_MODE` accepts `off`, `log`, or `block`. The default and an empty value mean `off`. A malformed mode disables the feature and produces one warning that names the setting without its value.

`CONTEXT_CANARY_POLICY_JSON` defaults to `{}`. It accepts only `routes` and `keys`, each an array of exact scope names. Each array is limited to 512 nonempty strings of at most 256 characters, without control characters. Configuration is limited to 65,536 UTF-8 bytes. Unknown fields, invalid JSON, and invalid array values disable the feature with one warning. An empty value means `{}`. Enabling the mode alone does not opt in any requests.

Disabled example:

```text
CONTEXT_CANARY_MODE=off
CONTEXT_CANARY_POLICY_JSON={}
```

Opt in one managed route for removal and detection logging:

```text
CONTEXT_CANARY_MODE=log
CONTEXT_CANARY_POLICY_JSON={"routes":["/v1/roleplay/chat/completions"]}
```

Opt in an authenticated key scope for blocking:

```text
CONTEXT_CANARY_MODE=block
CONTEXT_CANARY_POLICY_JSON={"keys":["key-7"]}
```

Key scopes are identifiers established by authentication, never API credentials or caller-supplied policy overrides. Roleplay uses its canonical `/v1/roleplay/chat/completions` scope for compatible aliases. Raw provider passthrough does not insert or inspect canaries. With mode off or no applicable opt-in, the original payload and response objects pass through unchanged, and no canary trace or log record is created.

## Request and response handling

An opted-in managed request receives one clearly labelled gateway system annotation. Its 32-character hexadecimal marker is an HMAC-SHA256 result derived from a fresh random 32-byte secret. No persistent canary secret or remote classifier is used. The annotation is placed in a system message for chat, in the system field for Messages, or in instructions for Responses. Existing instructions remain present. The marker belongs only to that request; a marker from another request is not recognised.

`log` removes detected markers and continues delivering the provider response. `block` returns HTTP 502 with `error.code=context_canary_leak` when detection occurs before the response is committed. After streaming begins, the client receives a real SSE error event with that code, without a fabricated completion or `[DONE]` event. The upstream is cancelled and generation is classified as unsuccessful. Detection never grants a retry or replay permission.

Earlier emitted text cannot be withdrawn. Some safe text may already have reached the client before detection. The canary does not prevent the disclosure of unrelated context or encoded, altered, or partial markers.

JSON strings are decoded before inspection, including Unicode escapes. SSE JSON data is assembled across reads and UTF-8 boundaries. Content, reasoning, text and tool argument fragments use independent text lanes with semantic choice and tool indices. A scanner retains only a possible marker prefix, at most 31 characters per lane. Unmatched prefixes are delivered at termination. Complete SSE frames are limited to 65,536 bytes, with at most 32 text lanes, structural depth 32, and 32,768 JSON nodes per frame. Nonstream response bodies are limited to 16 MiB. Unsupported, malformed, invalid UTF-8, or oversized opted-in responses fail with `context_canary_scan_failed`. These checks do not alter disabled traffic.

## Costs, retention and lifecycle

Cancellation does not prove that the provider stopped work or avoided billing. Blocked, interrupted or client-cancelled generation remains ambiguous. The finalizer marks the captured accounting context as ambiguous rather than releasing a cost hold. Measured provider usage and the existing accounting authority remain responsible for settlement. A stream error does not settle unknown spend as zero.

Canary event records contain only the marker digest, the rule `context_canary_leak`, and the trace ID. They contain no marker, annotation, prompt or response content. Each request records at most one detection. Roleplay's trace journal validates these fields and preserves the same restriction under zero-content retention. Request annotations are excluded from retained conversation and recovery inputs; output is inspected before completion persistence. Request-local parser state is released on completion, abort and client cancellation.

## Managed integration interfaces

Python request preparation calls `services.context_canary.prepare_request(payload, env, route=..., key_scope=..., protocol=...)` after authentication and content policy checks. It returns the original payload and a null context when disabled, or a transformed payload and a request-local context when opted in. Request preparation must run before request identity, cache eligibility, admission and reservation; preserve the context on the managed turn. Use only authenticated key scopes and explicitly managed routes. Supply `raw=True` for passthrough.

Response and stream finalization calls `services.context_canary.finalize_response(response, context, cancel=..., accounting=...)` before cache, replay, receipt and accounting finalization. Capture the cancellation collaborator and accounting context while the Flask request context is active; lazy generators do not consult Flask globals. Treat context changes as cache-policy changes and avoid replaying a result generated with another request's marker. The caller retains ownership of measured usage and reservations.

The Worker equivalents are `prepareRequest` and `finalizeResponse`. The response finalizer accepts an upstream abort controller, request signal, cancellation callback and captured accounting object. Native roleplay prepares its context before generation, annotates only dispatch payloads, scans initial and continuation responses before observing completion, and translates a late inspection failure into the client protocol error. Managed Worker forwarding must use the same finalizer before its own settlement and replay decisions.
