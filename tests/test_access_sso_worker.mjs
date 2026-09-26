import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import test from "node:test";

import {
  ACCESS_IDENTITY_HEADER, ACCESS_PROOF_HEADER, accessIdentityProof, accessSsoConfig, resetAccessKeyCache,
  stripAccessHeaders, verifyAccessJwt, withAccessIdentity,
} from "../worker/access-sso.mjs";
import { collectContainerEnv } from "../worker/container-env.mjs";
import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";

const TEAM = "https://acme.cloudflareaccess.com";
const AUD = "4714c1358e65fe4b408ad6d432a5f878f08194bdb4752441fd56faefa9b2b6f2";
const SECRET = "synthetic-access-proof-secret-0123456789";
const NOW = Date.UTC(2026, 8, 26, 12);
const SECONDS = Math.floor(NOW / 1000);
const ENV = { CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD, CF_ACCESS_PROOF_SECRET: SECRET };
const config = accessSsoConfig(ENV);
const encoder = new TextEncoder();
const b64url = value => Buffer.from(value).toString("base64url");

async function keyPair(kid) {
  const pair = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  const { n, e } = await crypto.subtle.exportKey("jwk", pair.publicKey);
  return { kid, privateKey: pair.privateKey, jwk: { kid, kty: "RSA", alg: "RS256", use: "sig", e, n } };
}

async function sign(key, claims = {}, header = {}) {
  const head = b64url(JSON.stringify({ alg: "RS256", kid: key.kid, typ: "JWT", ...header }));
  const body = b64url(JSON.stringify({ aud: [AUD], email: "Alice@Example.com", exp: SECONDS + 3600, iat: SECONDS,
    nbf: SECONDS, iss: TEAM, type: "app", identity_nonce: "nonce", sub: "7335d417", country: "US", ...claims }));
  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key.privateKey, encoder.encode(`${head}.${body}`));
  return `${head}.${body}.${b64url(new Uint8Array(signature))}`;
}

// A mocked https://<team>.cloudflareaccess.com/cdn-cgi/access/certs endpoint.
function certs(keys) {
  const server = { keys, calls: 0, down: false };
  server.fetch = async (url, init) => {
    server.calls += 1;
    assert.equal(String(url), `${TEAM}/cdn-cgi/access/certs`);
    assert.equal(init.redirect, "manual");
    if (server.down) return new Response("unavailable", { status: 503 });
    return Response.json({ keys: server.keys.map(key => key.jwk), public_cert: { kid: server.keys[0]?.kid, cert: "PEM" } });
  };
  return server;
}

const verify = (token, server, now = NOW) => verifyAccessJwt(token, config, { now, fetchImpl: server.fetch });
const primary = await keyPair("a1c3986a44ce6390be42ec772b031df8f433fdc71716db821dc0c39af3bce49");

test("a valid Access token verifies against the published keys, which are cached", async () => {
  resetAccessKeyCache();
  const server = certs([primary]);
  assert.deepEqual(await verify(await sign(primary), server), { ok: true, email: "alice@example.com", exp: SECONDS + 3600 });
  assert.equal((await verify(await sign(primary, { aud: AUD }), server)).ok, true, "aud may be a single string");
  assert.equal((await verify(await sign(primary), server, NOW + 30 * 60 * 1000)).ok, true);
  assert.equal(server.calls, 1, "keys are fetched once and reused");
});

test("issuer, audience and the validity window are enforced with bounded clock skew", async () => {
  resetAccessKeyCache();
  const server = certs([primary]);
  for (const [claims, reason] of [
    [{ aud: ["another-application"] }, "audience"],
    [{ aud: [] }, "audience"],
    [{ aud: [7] }, "audience"],
    [{ iss: "https://other.cloudflareaccess.com" }, "issuer"],
    [{ iss: `${TEAM}/` }, "issuer"],
    [{ exp: SECONDS - 61 }, "expired"],
    [{ exp: String(SECONDS + 3600) }, "expired"],
    [{ exp: undefined }, "expired"],
    [{ nbf: SECONDS + 120 }, "not_yet_valid"],
    [{ iat: SECONDS + 120 }, "not_yet_valid"],
    [{ type: "org" }, "token_type"],
    [{ email: undefined, sub: "", common_name: "e367826f93b8d71185e03fe518aff3b4.access" }, "no_email"],
    [{ email: "not an email" }, "no_email"],
  ]) assert.deepEqual(await verify(await sign(primary, claims), server), { ok: false, reason }, JSON.stringify(claims));
  assert.equal((await verify(await sign(primary, { exp: SECONDS - 30, nbf: SECONDS + 30 }), server)).ok, true,
    "60 seconds of clock skew are tolerated");
});

test("a wrong key, a tampered payload and algorithm substitution are refused", async () => {
  resetAccessKeyCache();
  const server = certs([primary]);
  const impostor = await keyPair(primary.kid);
  assert.deepEqual(await verify(await sign(impostor), server), { ok: false, reason: "signature" }, "same kid, other key");
  const [head, , signature] = (await sign(primary)).split(".");
  const forged = b64url(JSON.stringify({ aud: [AUD], email: "mallory@example.com", exp: SECONDS + 3600, iss: TEAM }));
  assert.deepEqual(await verify(`${head}.${forged}.${signature}`, server), { ok: false, reason: "signature" });

  const claims = b64url(JSON.stringify({ aud: [AUD], email: "mallory@example.com", exp: SECONDS + 3600, iss: TEAM }));
  const none = b64url(JSON.stringify({ alg: "none", kid: primary.kid }));
  assert.equal((await verify(`${none}.${claims}.`, server)).ok, false, "unsigned alg none");
  assert.deepEqual(await verify(`${none}.${claims}.${b64url("x")}`, server), { ok: false, reason: "algorithm" });
  const hs256 = b64url(JSON.stringify({ alg: "HS256", kid: primary.kid }));
  const mac = createHmac("sha256", primary.jwk.n).update(`${hs256}.${claims}`).digest("base64url");
  assert.deepEqual(await verify(`${hs256}.${claims}.${mac}`, server), { ok: false, reason: "algorithm" },
    "the public key is never used as an HMAC secret");
  for (const header of [{ alg: "RS256" }, { alg: "RS256", kid: "" }, { alg: "RS256", kid: primary.kid, crit: ["exp"] },
    { alg: "RS256", kid: primary.kid, typ: "at+jwt" }]) {
    const token = `${b64url(JSON.stringify(header))}.${claims}.${signature}`;
    assert.deepEqual(await verify(token, server), { ok: false, reason: "malformed" }, JSON.stringify(header));
  }
  for (const token of ["abc", "a.b", "a.b.c.d", "a.b!.c", `${"a".repeat(20000)}.b.c`]) {
    assert.deepEqual(await verify(token, server), { ok: false, reason: "malformed" });
  }
  assert.deepEqual(await verify("", server), { ok: false, reason: "missing" });
  assert.equal(server.calls, 1, "only the verified-signature path fetched keys");
});

test("an unknown key id refreshes the keys at most once per interval and rotation is picked up", async () => {
  resetAccessKeyCache();
  const server = certs([primary]);
  assert.equal((await verify(await sign(primary), server)).ok, true);
  const rotated = await keyPair("6c3bffef71bb0a90c9cbef3b7c0d4a1c7b4b8b76b80292a623afd9dac45d1c65");
  assert.deepEqual(await verify(await sign(rotated), server, NOW + 1000), { ok: false, reason: "unknown_key" },
    "within the refresh interval an unknown id does not fetch again");
  assert.equal(server.calls, 1);
  server.keys = [rotated, primary];
  assert.equal((await verify(await sign(rotated), server, NOW + 11_000)).ok, true, "a new key id triggers one refresh");
  assert.equal(server.calls, 2);
  assert.equal((await verify(await sign(primary), server, NOW + 12_000)).ok, true, "the previous key stays valid");
  const forgedIds = await Promise.all(["x1", "x2", "x3"].map(async kid => verify(await sign({ ...primary, kid }), server, NOW + 13_000)));
  assert.deepEqual(forgedIds.map(result => result.reason), ["unknown_key", "unknown_key", "unknown_key"]);
  assert.equal(server.calls, 2, "forged key ids cannot drive fetches");
});

test("an unavailable key endpoint fails closed but cached keys survive a short outage", async () => {
  resetAccessKeyCache();
  const server = certs([primary]);
  server.down = true;
  assert.deepEqual(await verify(await sign(primary), server), { ok: false, reason: "keys_unavailable" });
  server.down = false;
  assert.equal((await verify(await sign(primary), server, NOW + 11_000)).ok, true);
  server.down = true;
  const later = NOW + 2 * 60 * 60 * 1000;
  assert.equal((await verify(await sign(primary, { exp: later / 1000 + 60 }), server, later)).ok, true,
    "stale keys are used while the endpoint fails");
  const muchLater = NOW + 25 * 60 * 60 * 1000;
  assert.deepEqual(await verify(await sign(primary, { exp: muchLater / 1000 + 60 }), server, muchLater),
    { ok: false, reason: "keys_unavailable" }, "keys older than a day are not trusted");

  resetAccessKeyCache();
  const junk = { fetch: async () => Response.json({ keys: [{ kty: "RSA", kid: "short", n: "AQAB", e: "AQAB" }, { kty: "EC", kid: "ec" }] }) };
  assert.deepEqual(await verify(await sign(primary), junk), { ok: false, reason: "keys_unavailable" }, "weak and non-RSA keys are ignored");
  resetAccessKeyCache();
  const huge = { fetch: async () => new Response("x".repeat(70000), { headers: { "content-type": "application/json" } }) };
  assert.deepEqual(await verify(await sign(primary), huge), { ok: false, reason: "keys_unavailable" });
});

test("single sign-on is on only with a Cloudflare Access team domain, audience and a strong proof secret", () => {
  assert.equal(accessSsoConfig({}), null);
  assert.deepEqual(accessSsoConfig({ ...ENV, CF_ACCESS_TEAM_DOMAIN: "acme.cloudflareaccess.com", CF_ACCESS_AUD: `${AUD}, second` }),
    { teamDomain: TEAM, audiences: [AUD, "second"], secret: SECRET });
  for (const changes of [
    { CF_ACCESS_PROOF_SECRET: undefined }, { CF_ACCESS_PROOF_SECRET: "short" }, { CF_ACCESS_AUD: " , " },
    { CF_ACCESS_TEAM_DOMAIN: "http://acme.cloudflareaccess.com" }, { CF_ACCESS_TEAM_DOMAIN: "https://attacker.example" },
    { CF_ACCESS_TEAM_DOMAIN: `${TEAM}/cdn-cgi` }, { CF_ACCESS_TEAM_DOMAIN: "https://user@acme.cloudflareaccess.com" },
  ]) assert.equal(accessSsoConfig({ ...ENV, ...changes }), null, JSON.stringify(changes));
});

test("the proof is HMAC-SHA256 over the exact identity value and matches a fixed vector", async () => {
  const identity = "eyJ2IjoxLCJzdGF0dXMiOiJ2ZXJpZmllZCJ9";
  const expected = createHmac("sha256", SECRET).update(`multillm-access-identity-v1.${identity}`).digest("base64url");
  assert.equal(await accessIdentityProof(SECRET, identity), expected);
  // Shared with tests/test_dashboard_sso.py so both sides frame the proof identically.
  assert.equal(expected, "oaPbB60bwqnp7F2jVzAydieQ_uEJovA6b8WqBnpa1Wo");
});

function decodeIdentity(headers) {
  const identity = headers.get(ACCESS_IDENTITY_HEADER);
  const proof = createHmac("sha256", SECRET).update(`multillm-access-identity-v1.${identity}`).digest("base64url");
  assert.equal(headers.get(ACCESS_PROOF_HEADER), proof, "the Container can verify the proof");
  return JSON.parse(Buffer.from(identity, "base64url").toString("utf8"));
}

test("identity headers are asserted only on the sign-in path, with the verification result", async () => {
  resetAccessKeyCache();
  const server = certs([primary]);
  const request = (path, headers = {}, method = "POST") => new Request(`https://gateway.example${path}`, { method, headers });
  const spoofed = { [ACCESS_IDENTITY_HEADER]: "forged", [ACCESS_PROOF_HEADER]: "forged", "X-MultiLLM-Access-Email": "admin@example.com" };
  const token = await sign(primary);

  const verified = await withAccessIdentity(request("/login/access", { ...spoofed, "Cf-Access-Jwt-Assertion": token,
    "CF-Connecting-IP": "203.0.113.7" }), ENV, new Headers({ ...spoofed, "Cf-Access-Jwt-Assertion": token }), { now: NOW, fetchImpl: server.fetch });
  assert.deepEqual(decodeIdentity(verified), { v: 1, status: "verified", method: "POST", path: "/login/access", iat: SECONDS,
    email: "alice@example.com", exp: SECONDS + 3600, client: "203.0.113.7" });
  assert.equal(verified.get("x-multillm-access-email"), null);
  assert.equal(verified.get("cf-access-jwt-assertion"), null, "the raw Access token is not forwarded");

  const impostor = await keyPair(primary.kid);
  const refused = await withAccessIdentity(request("/login/access", { "Cf-Access-Jwt-Assertion": await sign(impostor) }, "GET"),
    ENV, new Headers(spoofed), { now: NOW, fetchImpl: server.fetch });
  assert.deepEqual(decodeIdentity(refused), { v: 1, status: "failed", method: "GET", path: "/login/access", iat: SECONDS, reason: "signature" });
  const missing = await withAccessIdentity(request("/login/access"), ENV, new Headers(spoofed), { now: NOW, fetchImpl: server.fetch });
  assert.equal(decodeIdentity(missing).reason, "missing");

  for (const [path, env] of [["/", ENV], ["/v1/chat/completions", ENV], ["/login/access/", ENV], ["/login/access", {}]]) {
    const headers = await withAccessIdentity(request(path, { "Cf-Access-Jwt-Assertion": token }), env,
      new Headers({ ...spoofed, "Cf-Access-Jwt-Assertion": token }), { now: NOW, fetchImpl: server.fetch });
    assert.deepEqual([...headers.keys()].filter(name => name.includes("access")), [], `${path} carries no Access headers`);
  }
  assert.deepEqual([...stripAccessHeaders(new Headers({ "x-multillm-access-anything": "1", accept: "text/html" })).keys()], ["accept"]);
});

test("the Worker strips spoofed identity headers from every Container request", async () => {
  resetAccessKeyCache();
  const { default: worker } = await loadWorkerModule();
  const server = certs([primary]);
  const forwarded = [];
  const container = { getByName: () => ({ fetch: async request => {
    forwarded.push(request.headers);
    return new Response("ok", { headers: { "content-type": "text/plain" } });
  } }) };
  const originalFetch = globalThis.fetch;
  globalThis.fetch = server.fetch;
  try {
    const spoofed = { [ACCESS_IDENTITY_HEADER]: "forged", [ACCESS_PROOF_HEADER]: "forged" };
    const send = (path, env, headers = {}) => worker.fetch(new Request(`https://gateway.example${path}`, { headers: { ...spoofed, ...headers } }),
      { MULTILLM_PROXY_CONTAINER: container, ...env });
    await send("/", {});
    await send("/login/access", {});
    await send("/users", ENV);
    await send("/v1/models", ENV, { Authorization: "Bearer synthetic", "Cf-Access-Jwt-Assertion": await sign(primary) });
    for (const headers of forwarded) {
      assert.equal(headers.get(ACCESS_IDENTITY_HEADER), null);
      assert.equal(headers.get(ACCESS_PROOF_HEADER), null);
      assert.equal(headers.get("cf-access-jwt-assertion"), null);
    }
    await send("/login/access", ENV, { "Cf-Access-Jwt-Assertion": await sign(primary, { exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000), nbf: Math.floor(Date.now() / 1000) }) });
    const identity = decodeIdentity(forwarded.at(-1));
    assert.deepEqual([identity.status, identity.email, identity.method, identity.path], ["verified", "alice@example.com", "GET", "/login/access"]);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("the Container receives the SSO settings it needs but never the audience tag", () => {
  const env = collectContainerEnv({ ...ENV, CF_ACCESS_ALLOWED_EMAILS: "alice@example.com=alice", DASHBOARD_SSO_ONLY: "true",
    ADMIN_USERNAMES: "deputy" });
  assert.equal(env.CF_ACCESS_TEAM_DOMAIN, TEAM);
  assert.equal(env.CF_ACCESS_PROOF_SECRET, SECRET);
  assert.equal(env.CF_ACCESS_ALLOWED_EMAILS, "alice@example.com=alice");
  assert.equal(env.DASHBOARD_SSO_ONLY, "true");
  assert.equal(env.ADMIN_USERNAMES, "deputy");
  assert.equal(env.CF_ACCESS_AUD, undefined);
});
