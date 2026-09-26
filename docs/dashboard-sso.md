# Dashboard single sign-on and the audit log

The dashboard can accept a [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/access-controls/)
identity in addition to, or instead of, a username and API key. Single sign-on is
opt-in: nothing changes until the Access settings below are configured. API keys
are never affected; proxy, Knowledge and roleplay clients keep authenticating with keys.

Single sign-on signs a person in to an **existing** dashboard account. It never
creates accounts and never grants administration by itself.

## Set up the Access application

1. In the Cloudflare dashboard, go to **Zero Trust → Access controls → Applications**
   and add a **self-hosted** application for the dashboard hostname.
2. Set its path to `login/access`. That is the only path single sign-on needs. You may
   also cover dashboard pages such as `/`, `/users` and `/admin/*`, but never the API
   paths (`/v1`, provider prefixes such as `/openai` or `/linkapi`, `/mcp`,
   `/knowledge`, `/health`, `/ready`): API clients authenticate with keys and cannot
   complete an interactive Access login. For the same reason, do not put the whole
   hostname behind Access.
3. Add an **Allow** policy for the people or groups who operate the gateway.
4. From the application's **Additional settings**, copy the **Application Audience
   (AUD) tag**. The tag changes only if the application is deleted and recreated.
5. Note the team domain, `https://<team>.cloudflareaccess.com`.

## Configure the Worker

| Variable | Where | Value |
| --- | --- | --- |
| `CF_ACCESS_TEAM_DOMAIN` | Worker variable | `https://<team>.cloudflareaccess.com` |
| `CF_ACCESS_AUD` | Worker variable | The AUD tag. Several tags may be comma-separated. |
| `CF_ACCESS_PROOF_SECRET` | Worker secret | A random value of at least 32 characters, for example `openssl rand -base64 48`. |
| `CF_ACCESS_ALLOWED_EMAILS` | Worker variable or secret | Comma-separated `email=username` pairs, or a bare email for an account named by that address. |
| `DASHBOARD_SSO_ONLY` | Worker variable, optional | `true` disables password sign-in to the dashboard. |
| `ADMIN_USERNAMES` | Worker variable, optional | Extra usernames allowed to hold administration, beside `ADMIN_USERNAME`. |

```bash
npx wrangler secret put CF_ACCESS_PROOF_SECRET
```

For example, `CF_ACCESS_ALLOWED_EMAILS="alice@example.com=alice, ops@example.com=admin"`
lets `alice@example.com` sign in as `alice` and `ops@example.com` as `admin`. Emails
are compared without regard to case. Any email that is not listed is refused, and so
is a listed email whose account does not exist or has been revoked. The Worker passes
every variable except `CF_ACCESS_AUD` to the Container.

Single sign-on is active only when the team domain, at least one AUD tag and the proof
secret are all set. The Worker logs `access_sso_misconfigured` once if some of them are
set but invalid; the team domain must be an `https` origin under
`cloudflareaccess.com`.

## Signing in and out

The sign-in page shows **Continue with Cloudflare Access**, a link to `/login/access`.
Access authenticates the person on that path; the page then shows which email Access
verified and which account it maps to. **Continue** posts the form, with its CSRF
token, and starts the session. Visiting the confirmation page never signs anyone in.

Starting a session discards the previous one, including its CSRF token, and issues a
new session identifier. The session ends when the Access token expires, after twelve
hours at most, when the account is revoked or its key is rotated, or when single
sign-on is switched off.

Signing out clears the dashboard session. The Access session is separate, so the
sign-in page then links to `https://<team>.cloudflareaccess.com/cdn-cgi/access/logout`
to end it as well.

Password sign-in stays available unless `DASHBOARD_SSO_ONLY=true`. With that setting
the password form is hidden, password sign-in answers 403 and existing password
sessions end at their next request. If `DASHBOARD_SSO_ONLY` is set while single sign-on
is not configured, nobody can sign in to the dashboard until it is: the setting fails
closed.

## How verification works

1. Access authenticates the person and adds its application token to the request in
   the `Cf-Access-Jwt-Assertion` header.
2. For every request it forwards to the Container, the Worker first removes any
   client-supplied `X-MultiLLM-Access-*` header and the raw `Cf-Access-Jwt-Assertion`.
3. On `/login/access` only, the Worker verifies the token:
   - The algorithm must be `RS256`. `none`, `HS256` and every other algorithm are
     refused before any key is used.
   - The key is chosen by the token's `kid` from the team's published keys at
     `<team domain>/cdn-cgi/access/certs`. Keys are cached for an hour. An unknown
     `kid` (Access rotated its key) triggers a refetch at most once every ten seconds,
     so forged key ids cannot drive fetches. If the endpoint fails, cached keys stay
     usable for a day; with no usable keys the sign-in is refused.
   - The signature is checked before any claim is trusted.
   - `iss` must equal the team domain and `aud` must contain a configured tag.
   - `exp` must not have passed, and `nbf` and `iat` must not lie in the future, each
     with 60 seconds of clock skew.
   - `type`, when present, must be `app`, and the token must carry an `email`.
     Service tokens carry no email and are refused.
4. The Worker then sets `X-MultiLLM-Access-Identity`, a base64url JSON assertion with
   the result (verified email and expiry, or the failure reason), the request method
   and path, the issue time and the client address from `CF-Connecting-IP`, and
   `X-MultiLLM-Access-Proof`, the base64url HMAC-SHA256 of
   `multillm-access-identity-v1.` followed by that exact header value, keyed with
   `CF_ACCESS_PROOF_SECRET`.
5. The Container accepts the assertion only when the proof matches (compared in
   constant time), it names the same method and path, and it was issued within five
   minutes. A copied header cannot be replayed on another path or later.
6. The verified email is mapped through `CF_ACCESS_ALLOWED_EMAILS` to an account.
7. A single sign-on session holds administration only while the account is an
   administrator **and** its username is named by `ADMIN_USERNAME` or
   `ADMIN_USERNAMES`. This is checked on every request, so removing a name from the
   list takes effect immediately.

Every refused attempt counts toward the sign-in throttle (`LOGIN_MAX_ATTEMPTS`,
`LOGIN_ATTEMPT_WINDOW_SECONDS`, `LOGIN_LOCKOUT_SECONDS`), keyed by the client address
and the verified email, and is recorded in the audit log with its reason.

## Audit log

Administrators open **Audit log** from the Access page, or `/admin/audit`. It lists,
newest first:

- account writes the Worker records in `control_user_audit`: saved, deleted, missing
  and refused (an administrator grant for a username the Worker does not allow). The
  Worker records these itself, so they have no actor; the matching setting change
  names the administrator.
- security events in `control_audit_events` (migration `0010`): sign-ins with their
  method (`password` or `access`), refused single sign-on attempts with the reason,
  sign-outs, and administrator setting changes. Setting changes cover account
  creation, deletion and key rotation, automatic route edits, model catalog refreshes,
  model disables, and Knowledge source, job and allowance changes. Attempts refused
  with 401 or 403 are recorded too.

Filter by actor, target or action. Pages hold 50 entries by default (at most 100,
with `limit`) and continue with a cursor. The same data is returned as JSON with
`Accept: application/json`.

The Container reads and writes the log only through two fixed operations on the
private `intelligence.internal/v1/users` handler: `audit_list` and `audit_record`.
There is no operation that changes or deletes an entry, and the table accepts only
the known actions and outcomes. Recording is best effort: if D1 cannot be reached the
event is logged and the action still takes effect. The audit log exists only with D1
account storage (`AUTH_STORAGE_BACKEND=d1`); otherwise the page says so.

## Page hardening

Dashboard HTML pages send a Content Security Policy that allows only same-origin
scripts, styles, fetches, workers and forms and no inline code, plus
`Permissions-Policy`, `Cross-Origin-Opener-Policy: same-origin` and, over HTTPS,
`Strict-Transport-Security`. The existing `X-Frame-Options: DENY`,
`X-Content-Type-Options: nosniff` and `Referrer-Policy: same-origin` still apply.
Session cookies are `HttpOnly`, `SameSite=Lax` and, outside development, `Secure`.

## Failure modes

| What the person sees | Likely cause | What to check |
| --- | --- | --- |
| "did not carry a verified Cloudflare Access identity" | The Access application does not cover `/login/access`, or the Worker's Access settings are incomplete. | The application's path; Worker logs for `access_sso_misconfigured`. |
| "could not verify this sign-in" | Expired token, wrong AUD tag (the application was recreated), wrong team domain, or a token without an email. | The reason on the refused `sign_in` entry in the audit log. |
| "cannot be checked right now" (503) | The Worker could not fetch Access keys and had none cached. | Worker logs for `access_keys_unavailable`; retry shortly. |
| "not allowed to sign in" | The email is not in `CF_ACCESS_ALLOWED_EMAILS`, or its account is missing or revoked. | The allowlist and the Access page. |
| "Too many sign-in attempts" (429) | Repeated refusals for the same identity and address. | Wait for `LOGIN_LOCKOUT_SECONDS`. |
| Signed in without administrator pages | The username is not named by `ADMIN_USERNAME` or `ADMIN_USERNAMES`. | Add it to `ADMIN_USERNAMES`. |
| No **Continue with Cloudflare Access** button | The Container lacks the team domain or a proof secret of 32 or more characters. | `CF_ACCESS_TEAM_DOMAIN` and `CF_ACCESS_PROOF_SECRET`. |
| `/ready` lists `control_audit_events` as missing | Migration `0010` was not applied. | `npm run deploy` applies migrations. |

Sources: Cloudflare's [Validate JWTs](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/),
[Application token](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/application-token/)
and [Session management](https://developers.cloudflare.com/cloudflare-one/access-controls/access-settings/session-management/).
