# SAML federation through a trusted broker

The gateway accepts a signed identity token from an operator-run SAML broker. The broker validates the IdP response, XML signatures, destination, audience, timing and SAML request correlation. The gateway does not download IdP metadata, parse XML or implement native SAML validation. `/auth/saml/acs` and `/auth/saml/metadata` return JSON HTTP 503 `saml_native_unavailable` when federation is enabled. They do not publish an ACS descriptor.

Federation is off by default. `SAML_ENABLED=false` or an empty value makes every `/auth/saml/*` and subject-link endpoint return HTTP 404 before session, CSRF or storage work. Existing gateway requests keep their behavior. Malformed configuration disables federation and emits one warning without configuration values.

## Configuration

Use an HTTPS broker URL without credentials or a fragment. Its query may contain broker-specific settings, but cannot contain `nonce`, `state` or `recipient`. Configure a fixed HTTPS callback URL ending in `/auth/saml/callback`, without a query or fragment. It is never derived from caller headers or a redirect parameter.

```text
SAML_ENABLED=true
SAML_BROKER_URL=https://broker.example/login
SAML_CALLBACK_URL=https://gateway.example/auth/saml/callback
```

`SAML_TRUST_CONFIG_JSON` defaults to `{}`. An enabled deployment must supply exactly these fields:

```json
{
  "issuer": "https://broker.example/issuer",
  "audience": "gateway.example",
  "keys": [
    {"kid": "broker-2026", "alg": "EdDSA", "public_key_pem": "<public Ed25519 PEM>"}
  ],
  "max_age_seconds": 300
}
```

Each key pins one unique `kid` and exact algorithm: `RS256` with an RSA public key of at least 2048 bits, or `EdDSA` with an Ed25519 public key. There may be at most 16 keys. No private key belongs in gateway configuration. Symmetric algorithms, unsigned tokens, mismatched key types and remotely supplied key URLs are rejected. Rotate keys by temporarily pinning both public keys, then remove the old key after all assertions issued under it expire. `max_age_seconds` must be an integer from 1 to 300. The callback URL may instead be supplied as the Flask application's `SAML_CALLBACK_URL` configuration.

## Login and callback

`GET /auth/saml/login` stores SHA-256 digests of a random nonce, random request state and recipient with a five-minute expiry, then redirects HTTP 302 only to the configured broker. It also binds the state digest to the browser's signed dashboard session. A new login replaces that browser's active state. Caller `next` parameters are ignored.

The broker returns one compact JWS in `token` and the request state in `state`, using `GET /auth/saml/callback` or a URL-encoded POST. Use exactly one of each field. A token must include `iss`, `aud`, `sub`, integer `iat` and `exp`, `nonce`, `state` and `recipient`. `aud` is one exact string. `state` is the original request ID; `nonce` and recipient must match the original login. A token's lifetime cannot exceed `max_age_seconds`; a fixed five-second clock skew is allowed by signature verification. Durable requests still expire at five minutes without extending their claim lifetime.

The callback must retain the original browser session cookie. A top-level GET is compatible with a SameSite=Lax dashboard cookie; a cross-site POST requires an operator-reviewed secure cookie policy or a same-site broker. State binding replaces CSRF form-token validation only on the broker callback. GET tokens can appear in browser history and intermediary access logs: configure the broker and gateway edge to suppress or redact callback query strings. The gateway adds `Cache-Control: no-store` and `Referrer-Policy: no-referrer` and never stores assertion contents.

The nonce is claimed atomically once. A replay or expired durable request returns HTTP 400 `saml_assertion_replayed`. Invalid signature, issuer, audience, key, algorithm, recipient or browser binding returns HTTP 400 `saml_assertion_invalid`. Unknown or duplicate callback fields return HTTP 400 `saml_request_invalid`.

After verification, an active `(issuer, subject)` link must name an existing, unrevoked, unexpired gateway account. No link returns HTTP 403 `saml_subject_unlinked`; the gateway never creates accounts from broker attributes. Assertion roles, administrator flags and organisation names grant nothing. The stored link supplies organisation, team and grants revision; the injected `IdentityAuthority` must return that exact `TenantContext`. Its `IdentityAssertion` uses digests for identifiers so arbitrary broker subjects fit the enterprise opaque-ID contract. Account names outside that contract use `account:<SHA-256>` as principal ID, while session issuance still receives the actual account name.

The service requires a named dashboard session issuer that accepts `(account, TenantContext)` and returns `True` only after issuing the existing dashboard session. The default returns HTTP 503 `saml_session_unavailable`: API-key authentication has no separate session-creation function. The issuer must revalidate account permissions and populate the same session fields as dashboard login, using stored grants. The service uses the stored-link authority by default; an organisation authority can be injected to revalidate current membership. An unavailable authority returns HTTP 503 `saml_identity_unavailable`, and a scope mismatch returns HTTP 403 `saml_identity_denied`.

## Administrator subject links

These routes require an administrator dashboard session. PUT and DELETE also require the existing dashboard CSRF token.

- `GET /admin/saml/links?offset=0` lists up to 100 links, including inactive links; use `offset` to paginate.
- `GET /admin/saml/links/<id>` reads one link.
- `PUT /admin/saml/links` creates or updates the stable subject link.
- `PUT /admin/saml/links/<id>` edits the same issuer/subject binding. It cannot rebind that identifier to a different subject.
- `DELETE /admin/saml/links/<id>` deactivates the link and retains its row and audit history.

PUT accepts `issuer`, `subject`, `account`, and optional `org_id`, `team_id`, `grants_revision`. `issuer` must equal the configured issuer. A team requires an organisation. Tenant IDs use the enterprise opaque-ID format. Omitting scope fields selects the linked account's legacy scope. Account existence is checked by the service and again against durable dashboard accounts in the private handler. Link identifiers are stable 32-character hex digests. Only issuer and subject digests are persisted, so operators must retain their own subject-to-account mapping outside the gateway.

## Storage, audit and operational bounds

Apply `0035_saml_federation.sql` to D1 before enabling federation. It adds `saml_requests`, `saml_subject_links` and `saml_audit` and preserves existing accounts. The private handler is `handleSamlIdentityRequest` at `http://intelligence.internal/v1/managed-state/saml`. Its dispatcher and private client endpoint must be registered, and `register_saml_federation_routes(app, csrf)` must be mounted. The core login guard must include `SAML_PUBLIC_ENDPOINTS` in its public endpoint allowlist. The link routes retain their administrator guard. Until storage wiring is available, login fails closed.

Every private operation validates the required tables and columns before changing state. Missing storage or a missing migration returns JSON HTTP 503 `saml_storage_unavailable` without admitting login. There is no local-memory identity fallback or automatic replay of uncertain writes. Login audit records contain an issuer digest, linked account if known, outcome and time. `authorized` means signature, link and authority checks passed before session issuance; a later session failure adds its failure outcome. Link changes also record the operator's digest. Neither audit nor nonce rows contain tokens, raw subjects, nonce or request state.

Assertions are limited to 16 KiB; private RPC bodies to 8 KiB; trust configuration to 64 KiB; subjects to 1,024 characters. Expiry prevents reuse but does not delete request rows. No automatic audit or link pruning is performed: retention and database capacity are operator responsibilities. Retain inactive links and their audit history. D1 operations and external broker hosting may incur their normal charges; this feature makes no model-provider calls and defines no additional billing rate. Live IdP compatibility, deployment and native XML validation require separate operational verification.
