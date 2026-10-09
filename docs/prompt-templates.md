# Versioned prompt templates

`PROMPT_TEMPLATES_ENABLED` defaults to `false`. Set it to `true` on the Worker and
forward it to the Flask Container to enable these endpoints. With it unset or
false, the admin endpoints, render endpoint and private D1 domain return 404
before reading the body or template storage. Existing generation requests are
unchanged. Rendering never replaces messages or dispatches generation.

## Publish and list

An administrator uses the existing dashboard session and CSRF token:

```http
POST /admin/workbench/prompts
Content-Type: application/json
X-CSRFToken: <dashboard-token>

{"slug":"greeting","version":1,"content":"Hello {{name}}","variables":["name"]}
```

The response is HTTP 201 with `slug`, `version`, `content`, `variables` and
`content_hash`. The hash is SHA-256 of the exact UTF-8 content, without whitespace
or newline normalization. A supplied `content_hash` must match that hash.
Every successful POST publishes an immutable version. Reusing the same owner,
slug and version returns 409, including after expiration. Publish a new integer
version to change content; there is no update or delete endpoint.

`GET /admin/workbench/prompts` returns `{"templates":[...],"next":null}`.
Pages contain at most two complete records, ordered by slug and numeric version.
When `next` is an object, pass its values as `after_slug` and `after_version`:

```http
GET /admin/workbench/prompts?after_slug=greeting&after_version=2
Accept: application/json
```

No caller-supplied principal or owner is accepted. Dashboard publication and
listing use the authenticated username (or ID). The render credential must
resolve to that same principal; administrators also see only their own records.

## Render explicitly

```http
POST /v1/prompt-templates/greeting/render
Authorization: Bearer <proxy-key>
Content-Type: application/json

{"version":1,"variables":{"name":"Ada"}}
```

The key requires `prompts:render`; existing administrator scope rules also apply.
The response is `{"rendered":"Hello Ada","slug":"greeting","version":1,
"content_hash":"<sha256>"}`. The hash identifies the published source, not the
rendered output. Bearer rendering is CSRF-exempt and does not use dashboard
session authentication. Integration credentials remain subject to their existing
route restrictions. Responses use `Cache-Control: no-store`.

Placeholders must be exactly `{{name}}`. Declared names must exactly match the
placeholders, with no duplicates or unused declarations. Names use ASCII letters,
digits and underscores, starting with a letter or underscore, up to 64 characters.
Values must be strings, and missing or extra values fail with 400. Substitution
runs once: braces, backslashes, expressions or paths inside values stay literal.
There is no code evaluation, Jinja syntax, include directive, file read or network
access in rendering. Expression and malformed placeholder syntax in templates is
refused rather than interpreted. Ordinary single braces are literal text.

Slugs contain lowercase ASCII letters, digits, underscores or hyphens, start with
a letter or digit, and are at most 64 characters. Versions are integers from 1 to
2,147,483,647. Other fields are refused. Template source is 1 byte to 64 KiB in
UTF-8 with at most 32 variables. Each value is at most 64 KiB, values together are
at most 256 KiB, and rendered output is at most 256 KiB. Expansion is checked before
allocating the output. JSON request bodies are capped at 512 KiB, including
escaping; unusually escape-heavy inputs can reach this bound first.

## Storage, policy and errors

Locally, an additive migration creates `prompt_templates` in the existing
workbench SQLite database (`CONNECTION_PROFILES_DB_PATH`). Existing workbench rows
are preserved. Under `INTELLIGENCE_STORAGE_BACKEND=d1`, the service submits fixed
operations to `http://intelligence.internal/v1/state/prompt-templates`. The Worker
accepts only bounded `create`, `get` and `list` operations with fixed SQL. It
validates declarations and recomputes the hash before writing. Writes and the
100-version lifetime limit per principal are atomic, including concurrent
publication. Reads also validate stored content and hash. Two-record list pages
keep escaped private responses below 1 MiB.

Apply additive D1 migration `0014_prompt_templates.sql` before enabling the flag.
A deployment does not apply it. With the feature enabled and the table missing,
new routes return JSON HTTP 503 with `error: prompt_templates_storage_unavailable`.
They never fall back to local storage or return a fabricated empty list. This
error also covers unavailable, malformed or corrupt storage responses. Private
Worker errors use `storage_unavailable`. Private transport submits once, waits at
most five seconds with four concurrent slots, refuses redirects and does not
retry an uncertain write. A missing or expired version returns 404; wrong scope
or a non-admin dashboard principal returns 403; invalid fields return 400; body
or rendered-output bounds return 413. Missing bearer authentication returns 401.

Existing secret policy is checked before publication and rendering. High-confidence
secrets are refused with 422 unless the owner has explicitly disabled scanning.
Content is never silently redacted into a different immutable template. Publication
uses the existing best-effort `setting_change` audit event with principal,
operation and outcome only. Template content, variable values and rendered output
are not logged or written to audit events. Rendering values and results are not
persisted by this feature. No provider request or generation charge occurs;
ordinary D1 operations and storage can still incur infrastructure costs.

Versions are available for 30 days from publication. Expired versions are omitted
from lists and unavailable for rendering, but their namespace remains reserved.
This is logical expiration: source content remains in SQLite/D1 until an operator
deletes the rows. There is no automatic physical erasure, export,
backup integration, encryption layer or cross-principal sharing in this feature.
The lifetime limit includes expired versions, bounding stored content to 100
versions per principal. Operators needing physical deletion or a different
retention policy must arrange that maintenance before storing sensitive content.
