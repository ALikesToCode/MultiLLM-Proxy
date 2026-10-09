# SCIM user and group provisioning

SCIM 2.0 provisions non-administrator gateway accounts and organisation teams. The
API is disabled by default. Unset, empty, `false`, `0`, `off` and `no` values for
`SCIM_ENABLED` return 404 for every `/scim/v2/*` route. An invalid value also disables
the API and emits one warning without the value. Existing account creation is unchanged.

## Configuration and authentication

Set `SCIM_ENABLED=true` only after applying the SCIM storage migration and configuring
the account and tenant authorities. `AUTH_STORAGE_BACKEND` and
`INTELLIGENCE_STORAGE_BACKEND` must both be `d1`, and
`CONFIG_REVISION_SYNC_ENABLED=true` must be enabled for the Worker and Container.
Security revisions expire within `CONFIG_SECURITY_TTL_SECONDS` (default and maximum:
five seconds); an unavailable or stale security copy denies generation.

Configure token references, never token values:

```json
{"tenants":{"org:example":{"token_ref":"SCIM_PROVISIONING_EXAMPLE"}}}
```

This is the value of `SCIM_TRUST_CONFIG_JSON`. The named environment variable or
Worker secret binding supplies the provisioning token privately. Supply each reference
to the Container through the deployment's reviewed secret-binding configuration.
An empty trust config uses `{}` and authorises nobody. Each tenant needs a distinct
token. Missing, unknown, ambiguous or invalid trust entries return a SCIM 401 error.
The server compares SHA-256 digests in constant time, fixes the organisation from the
matched reference, and ignores caller-supplied organisation headers. Provisioning
tokens and account credentials are never returned or logged.

Send the token in `Authorization: Bearer <provisioning-token>`. Browser sessions do
not authorise this API. It is exempt from dashboard CSRF checks and accepts
`application/scim+json` or `application/json` request bodies. Responses use
`application/scim+json` and `Cache-Control: no-store`.

## Endpoints and supported attributes

The discovery endpoints are `/scim/v2/ServiceProviderConfig`, `/scim/v2/Schemas`
and `/scim/v2/ResourceTypes`; schema and resource-type entries can also be read by ID.
`Users` and `Groups` support list, get, POST, PUT, PATCH and DELETE. PATCH uses the
SCIM PatchOp schema and `Operations` array. Unsupported schemas, attributes, paths,
operations and list parameters return a SCIM 400 error.

Users accept `userName`, `externalId`, `active`, `displayName`, `name` and `emails`.
Names support `formatted`, `familyName`, `givenName`, `middleName`, `honorificPrefix`
and `honorificSuffix`. Emails support `value`, `type`, `display` and `primary`, with
at most one primary entry. `userName` is immutable and globally unique among gateway
accounts. IDs and external identities remain stable across deactivation.
Administrator roles, permission escalation and environment-managed administrator
names cannot be provisioned. New accounts receive only the default `chat` and
`models` scopes. Their generated key is discarded; an authorised operator must issue
a new key through the existing key-rotation flow when key access is needed.

Groups accept `displayName`, `externalId` and `members` (`value`, optional `display`
and `$ref`). Member values are SCIM user IDs in the same organisation. Membership
must also pass the tenant authority. Teams and members cannot grant administrator
roles. Group writes require an atomic team authority; missing authorities return 503.

PATCH supports `add`, `replace` and `remove` for mutable user attributes and group
attributes. A missing path with an object value applies its named mutable attributes.
Adding a name merges its subattributes; adding emails appends entries; adding members
merges by member ID. Removing `active` deactivates the account. A member can be removed
with `members[value eq "<id>"]`. Other selectors and nested PATCH paths are unsupported.
PUT replaces the supported attributes; omitted user `active` defaults to true and
omitted group members defaults to an empty list.

For example, create a user using the User schema:

```json
{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"alice","externalId":"directory-subject-1","active":true}
```

POST returns 201 with `Location` and `ETag`. Repeating an external ID in the same
organisation and resource type returns its existing resource with 200, including
after deactivation. A conflicting username returns 409 `uniqueness`.

Each resource's `meta.version` is its weak ETag. Send the current ETag in `If-Match`
on PUT, PATCH or DELETE. A stale ETag returns 412; omitting the header still uses
an atomic stored-version check, so concurrent writers cannot silently overwrite.
`If-Match: *` requires the resource to exist.

## Limits, deactivation and retention

List responses use `startIndex` (one-based, default 1) and `count` (default 100,
maximum 100; zero returns no rows). The only filter expressions are
`userName eq "..."`, `externalId eq "..."` and `displayName eq "..."`. Other expressions
return 400 `invalidFilter`. Sorting, projections, bulk operations and password changes
are unsupported. Requests are limited to 128 KiB, 100 PATCH operations, 100 email
entries and 1,000 group members. Page positions are not snapshot cursors.

Setting `active=false` or deleting a user deactivates it. The account, external identity
and historical usage remain. The server rotates and discards its key, marks it revoked,
and advances the existing key-control and model-grant security revisions in the same
transaction. Dashboard sessions fail persisted revocation and key-prefix checks.
Reactivation clears the revocation marker without restoring the old key or sessions.
DELETE returns 204. Deleting a group removes its current memberships and deactivates
its mapped team while retaining the group identity and audit history.

SCIM storage contains directory identity attributes, external mappings, token digests,
membership state and content-free operation audits. It does not record prompts,
generated responses or provisioning bearer values. These records have no automatic
retention expiry; deactivation does not purge them. Operators must account for that
retention when enrolling a directory. SCIM has no provider calls, inference cost,
payment processing or automatic billing; D1 operations incur the deployment's normal
storage costs. Responses do not assert directory-provider certification.

Errors use `urn:ietf:params:scim:api:messages:2.0:Error` with string `status`, `scimType`
and a bounded detail. With SCIM enabled, missing tables, account columns, security
revision storage, atomic collaborators or durable storage return JSON 503 before
account changes. Storage outages never fall back to local account writes or retry
uncertain mutations. The Worker forwards the public path, body, bearer and `If-Match`
to the Container; the private SCIM domain only accepts its fixed internal POST target.
