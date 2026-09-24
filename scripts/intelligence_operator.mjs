#!/usr/bin/env node
/**
 * Explicit operator access to the intelligence D1 domain.
 *
 * Operations run the Worker's own private handlers in this process against a remote
 * D1 binding from Wrangler's getPlatformProxy. Nothing is served over HTTP, and SQL,
 * policy documents and credentials are never accepted on the command line.
 */
import { randomBytes, randomInt, scrypt } from "node:crypto";
import { constants, realpathSync } from "node:fs";
import { lstat, mkdtemp, open, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs, promisify } from "node:util";
import { handleIntelligenceAuthRequest } from "../worker/intelligence-auth-d1.mjs";
import { handleIntelligenceStoreRequest } from "../worker/intelligence-d1.mjs";

const KEY_NAMESPACE = "mllm_intelligence_";
const SALT_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
// Werkzeug's scrypt:32768:8:1 needs 32 MiB, which Node's default ceiling rejects.
const SCRYPT = { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
const POLICY_FILE_BYTES = 256 * 1024;
const RESPONSE_BYTES = 512 * 1024;
const OPEN_TIMEOUT_MS = 120_000;
const OPERATION_TIMEOUT_MS = 30_000;
const DISPOSE_TIMEOUT_MS = 10_000;
const ACCOUNT_ID = /^[a-f0-9]{32}$/;
const DATABASE_ID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const TABLES = {
  policy: "intelligence_policy", reservations: "intelligence_reservations",
  principals: "intelligence_principals", credentials: "intelligence_credentials",
};
const OPTIONS = {
  "account-id": { type: "string" }, "database-id": { type: "string" }, apply: { type: "boolean" },
  "policy-file": { type: "string" }, principal: { type: "string" }, scopes: { type: "string" },
  "credential-file": { type: "string" }, help: { type: "boolean" },
};
const ALLOWED = {
  status: ["account-id", "database-id"],
  seed: ["account-id", "database-id", "apply", "policy-file"],
  provision: ["account-id", "database-id", "apply", "principal", "scopes", "credential-file"],
};
const FAILURES = {
  usage: [2, "Invalid arguments; run with --help."],
  invalid_policy_file: [1, "The policy file is unreadable, oversized or not JSON; nothing was submitted."],
  invalid_policy: [1, "The Worker domain rejected the policy; nothing was submitted."],
  invalid_request: [1, "The Worker domain rejected the principal or scopes; nothing was submitted."],
  credential_target_exists: [1, "The credential file target already exists or is a link; choose a new path."],
  credential_target_invalid: [1, "The credential file target must be a new path in an existing directory."],
  credential_write_failed: [1, "The credential file could not be saved; nothing was submitted. Discard any partial file."],
  remote_unavailable: [1, "The remote database could not be opened; nothing was submitted."],
  credential_conflict: [1, "The principal exists, was revoked, or the prefix is reserved; nothing was stored. The saved key file is retained unregistered."],
  status_unavailable: [1, "Status could not be read."],
  outcome_uncertain: [3, "The outcome is uncertain and was not retried. Run status and inspect durable state before any further action; a saved key file is retained."],
  internal_error: [1, "The operation failed."],
};
const USAGE = `Usage: node scripts/intelligence_operator.mjs <operation> --account-id <id> --database-id <uuid> [options]

Operations:
  status      Report whether a policy is stored and table row counts. Read-only.
  seed        Insert a reviewed policy when none is stored: --policy-file <path>.
  provision   Create a new integration principal and key:
              --principal integration:<name> --scopes chat,models,audio,embeddings
              --credential-file <new path>
              Knowledge clients use --scopes knowledge:read (add knowledge:manage
              only for administration). These keys survive Container restarts.

seed and provision are dry runs unless --apply is given. Dry runs validate with the
Worker domain handlers, make no remote call and create no file.
`;

class OperatorFailure extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

function fail(code) {
  throw new OperatorFailure(code);
}

export async function hashIntegrationKey(key, salt) {
  const digest = await promisify(scrypt)(key, salt, 64, SCRYPT);
  return `scrypt:${SCRYPT.N}:${SCRYPT.r}:${SCRYPT.p}$${salt}$${digest.toString("hex")}`;
}

export async function generateIntegrationCredential() {
  const key = KEY_NAMESPACE + randomBytes(48).toString("base64url");
  const salt = Array.from({ length: 16 }, () => SALT_CHARS[randomInt(SALT_CHARS.length)]).join("");
  return { key, keyPrefix: key.slice(0, KEY_NAMESPACE.length + 16), keyHash: await hashIntegrationKey(key, salt) };
}

async function within(promise, milliseconds) {
  let timer;
  const expired = new Promise((_, reject) => { timer = setTimeout(reject, milliseconds, new Error("timed out")); });
  try { return await Promise.race([promise, expired]); }
  finally { clearTimeout(timer); }
}

async function callDomain(endpoint, db, body) {
  const handler = endpoint === "auth" ? handleIntelligenceAuthRequest : handleIntelligenceStoreRequest;
  const response = await handler(new Request(`http://intelligence.internal/v1/${endpoint}`, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, ...body }),
  }), { INTELLIGENCE_DB: db });
  const text = await response.text();
  if (text.length > RESPONSE_BYTES) throw new Error("oversized domain response");
  return { status: response.status, body: JSON.parse(text) };
}

// The domain validates before touching storage, so a binding that refuses every
// statement proves a request valid without a remote call or duplicated rules.
async function validateWithDomain(endpoint, body, code) {
  let reached = false;
  const refuse = () => { reached = true; throw new Error("validation only"); };
  await callDomain(endpoint, { prepare: refuse, batch: refuse }, body);
  if (!reached) fail(code);
}

async function loadPlatformProxy() {
  // Keep Wrangler diagnostics off stdout and out of its on-disk debug logs.
  process.env.WRANGLER_LOG = "warn";
  process.env.WRANGLER_WRITE_LOGS = "false";
  return (await import("wrangler")).getPlatformProxy;
}

async function release(proxy, directory) {
  try { await proxy?.dispose(); }
  finally { await rm(directory, { recursive: true, force: true }); }
}

/** Opens only INTELLIGENCE_DB through a fresh temporary config; no .env, .dev.vars or local state. */
export async function openRemoteDatabase({ accountId, databaseId }, load = loadPlatformProxy) {
  const directory = await mkdtemp(join(tmpdir(), "multillm-intelligence-operator-"));
  let proxy;
  try {
    const configPath = join(directory, "wrangler.json");
    await writeFile(configPath, JSON.stringify({
      name: "multillm-intelligence-operator",
      compatibility_date: "2026-07-30",
      account_id: accountId,
      d1_databases: [{ binding: "INTELLIGENCE_DB", database_id: databaseId, remote: true }],
    }), { flag: "wx", mode: 0o600 });
    const getPlatformProxy = await load();
    proxy = await getPlatformProxy({ configPath, envFiles: [], persist: false, remoteBindings: true });
    const db = proxy.env?.INTELLIGENCE_DB;
    if (typeof db?.prepare !== "function" || typeof db.batch !== "function") fail("remote_unavailable");
    return { db, dispose: () => release(proxy, directory) };
  } catch (error) {
    await release(proxy, directory);
    throw error;
  }
}

async function withDatabase(context, work) {
  const opening = Promise.resolve().then(() => context.openDatabase(context.target));
  let session;
  try { session = await within(opening, OPEN_TIMEOUT_MS); }
  catch {
    // A session that finishes opening after the deadline is still released.
    opening.then((late) => late.dispose(), () => {}).catch(() => {});
    fail("remote_unavailable");
  }
  try { return await work(session.db); }
  finally { await within(Promise.resolve().then(() => session.dispose()), DISPOSE_TIMEOUT_MS).catch(() => {}); }
}

// Once a request may have reached D1 its outcome is uncertain; it is never replayed.
async function submitOnce(context, endpoint, body, beforeSubmit = async () => {}) {
  let submitted = false;
  try {
    return await withDatabase(context, async (db) => {
      await beforeSubmit();
      submitted = true;
      return within(callDomain(endpoint, db, body), OPERATION_TIMEOUT_MS);
    });
  } catch (error) {
    if (submitted) fail("outcome_uncertain");
    throw error;
  }
}

async function readPolicyFile(path) {
  let handle;
  try {
    handle = await open(resolve(path), constants.O_RDONLY | constants.O_NONBLOCK);
    if (!(await handle.stat()).isFile()) throw new Error("not a file");
    const buffer = Buffer.alloc(POLICY_FILE_BYTES + 1);
    let size = 0;
    while (size < buffer.length) {
      const { bytesRead } = await handle.read(buffer, size, buffer.length - size, size);
      if (bytesRead === 0) break;
      size += bytesRead;
    }
    if (size > POLICY_FILE_BYTES) throw new Error("oversized");
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(buffer.subarray(0, size)));
  } catch { fail("invalid_policy_file"); }
  finally { await handle?.close(); }
}

async function checkCredentialTarget(path) {
  const exists = await lstat(path).then(() => true, (error) => {
    if (error?.code !== "ENOENT") fail("credential_target_invalid");
    return false;
  });
  if (exists) fail("credential_target_exists");
  if (!(await stat(dirname(path)).catch(() => null))?.isDirectory()) fail("credential_target_invalid");
}

async function saveCredential(path, key) {
  let handle;
  try {
    // O_EXCL refuses every existing entry, including dangling links; O_NOFOLLOW is a second guard.
    handle = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
  } catch (error) {
    fail(["EEXIST", "ELOOP"].includes(error?.code) ? "credential_target_exists" : "credential_target_invalid");
  }
  try {
    await handle.chmod(0o600);
    await handle.writeFile(`${key}\n`);
    await handle.sync();
    await handle.close();
    handle = null;
    const directory = await open(dirname(path), constants.O_RDONLY | constants.O_DIRECTORY);
    try { await directory.sync(); }
    finally { await directory.close(); }
  } catch {
    await handle?.close().catch(() => {});
    fail("credential_write_failed");
  }
}

async function status(context) {
  const names = Object.keys(TABLES);
  try {
    return await withDatabase(context, async (db) => {
      const [policy, counts] = await within(Promise.all([
        callDomain("store", db, { operation: "policy" }),
        db.batch(names.map((name) => db.prepare(`SELECT COUNT(*) AS n FROM ${TABLES[name]}`))),
      ]), OPERATION_TIMEOUT_MS);
      const rows = Object.fromEntries(names.map((name, index) => [name, counts?.[index]?.results?.[0]?.n]));
      if (Object.values(rows).some((count) => !Number.isSafeInteger(count) || count < 0)) fail("status_unavailable");
      const stored = policy.status === 200 ? policy.body.policy : undefined;
      const state = stored === null ? "unseeded" : stored ? "configured"
        : policy.status === 503 && policy.body.error?.code === "invalid_intelligence_policy" ? "invalid" : fail("status_unavailable");
      return { policy: state, rows };
    });
  } catch (error) {
    if (error instanceof OperatorFailure && error.code === "remote_unavailable") throw error;
    fail("status_unavailable");
  }
}

async function seed(context) {
  const body = { operation: "seed", policy: await readPolicyFile(context.values["policy-file"]) };
  await validateWithDomain("store", body, "invalid_policy");
  if (!context.apply) return { applied: false, valid: true };
  const response = await submitOnce(context, "store", body);
  if (response.status !== 200 || typeof response.body.inserted !== "boolean") fail("outcome_uncertain");
  return { applied: true, inserted: response.body.inserted };
}

async function provision(context) {
  const path = resolve(context.values["credential-file"]);
  const summary = { principal: context.values.principal, scopes: context.values.scopes.split(",") };
  await checkCredentialTarget(path);
  const credential = await generateIntegrationCredential();
  const body = {
    operation: "provision", principalId: summary.principal, keyPrefix: credential.keyPrefix,
    keyHash: credential.keyHash, scopes: summary.scopes,
  };
  await validateWithDomain("auth", body, "invalid_request");
  if (!context.apply) return { applied: false, valid: true, ...summary };
  const response = await submitOnce(context, "auth", body, () => saveCredential(path, credential.key));
  if (response.status === 409) fail("credential_conflict");
  if (response.status !== 201 || response.body.credentialVersion !== 1) fail("outcome_uncertain");
  return { applied: true, ...summary, credentialVersion: 1, credentialFile: "saved" };
}

const OPERATIONS = { status, seed, provision };

function parse(argv) {
  let parsed;
  try { parsed = parseArgs({ args: argv, options: OPTIONS, allowPositionals: true, strict: true }); }
  catch { fail("usage"); }
  const { values, positionals } = parsed;
  if (values.help) return { help: true };
  const [operation] = positionals;
  if (positionals.length !== 1 || !Object.hasOwn(ALLOWED, operation)) fail("usage");
  const allowed = ALLOWED[operation];
  if (Object.keys(values).some((name) => !allowed.includes(name))
    || allowed.some((name) => name !== "apply" && typeof values[name] !== "string")
    || !ACCOUNT_ID.test(values["account-id"]) || !DATABASE_ID.test(values["database-id"])) fail("usage");
  return {
    operation, values, apply: values.apply === true,
    target: { accountId: values["account-id"], databaseId: values["database-id"] },
  };
}

/** Writes one sanitized JSON line: results to stdout, failures to stderr. Returns the exit code. */
export async function runOperator(argv, {
  openDatabase = openRemoteDatabase, stdout = process.stdout, stderr = process.stderr,
} = {}) {
  let operation = null;
  try {
    const context = parse(argv);
    if (context.help) {
      stdout.write(USAGE);
      return 0;
    }
    operation = context.operation;
    const result = await OPERATIONS[operation]({ ...context, openDatabase });
    stdout.write(`${JSON.stringify({ version: 1, operation, ok: true, ...result })}\n`);
    return 0;
  } catch (error) {
    const code = error instanceof OperatorFailure ? error.code : "internal_error";
    const [exitCode, message] = FAILURES[code];
    stderr.write(`${JSON.stringify({ version: 1, operation, ok: false, error: code, message })}\n`);
    return exitCode;
  }
}

// Compare real paths: the checkout may be reached through a symlinked directory.
if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  // Exit explicitly so a lingering platform handle cannot keep the process alive.
  process.exit(await runOperator(process.argv.slice(2)));
}
