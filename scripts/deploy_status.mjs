#!/usr/bin/env node
/**
 * What is deployed, for humans and agents. Prints no secrets.
 *
 *   node scripts/deploy_status.mjs [--json] [--url <origin>]
 *   node scripts/deploy_status.mjs --verify --commit <sha> --main-worker actions|workers-builds
 *                                  [--wait <seconds>] [--markdown <file>]
 *
 * Reports each Worker's live version and the commit it was built from, the D1 migrations
 * not yet applied, and GET /ready. Wrangler reads deployments and D1 with `wrangler login`
 * or CLOUDFLARE_API_TOKEN. When CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID are set, it
 * also reads the release fingerprint of the deployed main Worker bundle and the commit of a
 * Workers Builds deploy from the Cloudflare API.
 *
 * --verify exits 1 unless migrations are applied, /ready answers 200 and the Workers run
 * the expected commit, retrying for --wait seconds. With --main-worker workers-builds the
 * main Worker is deployed by Workers Builds, so a mismatch there is only a warning.
 */
import { execFileSync } from "node:child_process";
import { appendFileSync, readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { localMigrations, pendingMigrations, remoteAppliedMigrations } from "./verify_d1_migrations.mjs";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const COMMIT = /^[0-9a-f]{40}$/;
const FINGERPRINT = /^[0-9a-f]{64}$/;
export const WORKERS = Object.freeze({
  main: { label: "Main Worker", name: "multillm-proxy", config: "wrangler.jsonc", fingerprinted: true },
  knowledge: { label: "Knowledge Worker", name: "multillm-knowledge", config: "wrangler.knowledge.jsonc", fingerprinted: false },
});
const USAGE = `Usage: node scripts/deploy_status.mjs [--json] [--url <origin>] [--database <name>]
       node scripts/deploy_status.mjs --verify --commit <sha> --main-worker actions|workers-builds
                                      [--wait <seconds>] [--markdown <file>]`;

const SOURCES = { workersci: "Workers Builds", wrangler: "Wrangler", dash: "the dashboard", api: "the API" };
const short = value => (value ? value.slice(0, 12) : "unknown");
const versionId = version => version.id?.slice(0, 8) ?? "unknown";

export function parseJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    const start = text.search(/[[{]/);
    if (start < 0) throw new Error("wrangler did not return JSON");
    return JSON.parse(text.slice(start));
  }
}

/** A one-line reason from a failed Wrangler run, without its banner or colour codes. */
export function wranglerFailure(error) {
  const lines = `${error?.stderr ?? ""}\n${error?.stdout ?? ""}`.replace(/\u001b\[[0-9;]*m/g, "").split("\n")
    .map(line => line.trim()).filter(Boolean);
  const line = lines.find(item => /\[ERROR\]|✘|error/i.test(item)) ?? lines.at(-1) ?? error?.message ?? "failed";
  return line.replace(/^✘\s*/, "").replace(/^\[ERROR\]\s*/, "").slice(0, 200);
}

export function describeVersion(version, percentage) {
  const annotations = version?.annotations ?? {};
  const tag = annotations["workers/tag"] ?? null;
  const commit = [tag, annotations["workers/commit_sha"]].find(value => COMMIT.test(value ?? "")) ?? null;
  return {
    id: version?.id ?? null, percentage, created_on: version?.metadata?.created_on ?? null,
    source: version?.metadata?.source ?? null, triggered_by: annotations["workers/triggered_by"] ?? null,
    tag, message: annotations["workers/message"] ?? null, commit, commit_source: commit ? "version tag" : null,
  };
}

export function buildIdFromBundle(text) {
  return /\bBUILD_ID\s*=\s*"([0-9a-f]{64})"/.exec(text)?.[1] ?? null;
}

export function readyVerdict(status, body) {
  if (status === 200) return { ok: true, status, detail: "ready" };
  if (body?.reason === "d1_schema_missing") {
    return { ok: false, status, detail: `D1 schema is missing tables: ${(body.missing_tables ?? []).join(", ") || "unknown"}` };
  }
  return { ok: false, status, detail: body?.reason ? `not ready (${body.reason})` : `HTTP ${status}` };
}

export function cloudflareApi(env, fetchImpl = fetch) {
  const token = env.CLOUDFLARE_API_TOKEN;
  const account = env.CLOUDFLARE_ACCOUNT_ID;
  if (!token || !/^[0-9a-f]{32}$/.test(account ?? "")) return null;
  return async path => {
    const response = await fetchImpl(`https://api.cloudflare.com/client/v4/accounts/${account}${path}`, {
      headers: { Authorization: `Bearer ${token}` }, redirect: "error", signal: AbortSignal.timeout(30_000),
    });
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error(`Cloudflare API returned HTTP ${response.status}`);
    }
    return response;
  };
}

async function workerStatus(worker, { run, api }) {
  const result = { name: worker.name, deployed_at: null, versions: [], fingerprint: null, error: null, notes: [] };
  try {
    const deployment = parseJson(run(["deployments", "status", "--json", "--config", worker.config]));
    result.deployed_at = deployment.created_on ?? null;
    for (const { version_id: id, percentage } of deployment.versions ?? []) {
      result.versions.push(describeVersion(parseJson(run(["versions", "view", id, "--json", "--config", worker.config])), percentage));
    }
  } catch (error) {
    result.error = wranglerFailure(error);
    return result;
  }
  if (!api) return result;
  const unresolved = result.versions.filter(version => !version.commit && version.id);
  if (unresolved.length) {
    try {
      const body = await (await api(`/builds/builds?version_ids=${unresolved.map(version => version.id).join(",")}`)).json();
      for (const version of unresolved) {
        const hash = body?.result?.builds?.[version.id]?.build_trigger_metadata?.commit_hash;
        if (COMMIT.test(hash ?? "")) Object.assign(version, { commit: hash, commit_source: "Workers Builds" });
      }
    } catch (error) {
      result.notes.push(`Workers Builds lookup unavailable: ${error.message}`);
    }
  }
  if (worker.fingerprinted) {
    try {
      result.fingerprint = buildIdFromBundle(await (await api(`/workers/scripts/${worker.name}/content/v2`)).text());
      if (!result.fingerprint) result.notes.push("the deployed bundle has no release fingerprint");
    } catch (error) {
      result.notes.push(`bundle fingerprint unavailable: ${error.message}`);
    }
  }
  return result;
}

function d1Status(database, run) {
  const files = localMigrations();
  try {
    const applied = remoteAppliedMigrations(database, run);
    return { database, local: files.length, applied: applied.length, pending: pendingMigrations(files, applied),
      unknown: pendingMigrations(applied, files), error: null };
  } catch (error) {
    return { database, local: files.length, applied: null, pending: null, unknown: [], error: wranglerFailure(error) };
  }
}

async function probeReady(origin, fetchImpl) {
  const url = new URL("/ready", origin).href;
  try {
    const response = await fetchImpl(url, { redirect: "manual", signal: AbortSignal.timeout(30_000) });
    let body = null;
    try {
      body = await response.json();
    } catch {
      // Not JSON; the status code is enough.
    }
    return { url, ...readyVerdict(response.status, body) };
  } catch (error) {
    return { url, ok: false, status: null, detail: `request failed (${error.name})` };
  }
}

export function localRelease(root, exec) {
  const attempt = (file, args) => {
    try {
      return exec(file, args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
    } catch {
      return null;
    }
  };
  const commit = attempt("git", ["rev-parse", "HEAD"]);
  // The deploy build rewrites worker/build-id.mjs, which is not a source change.
  const changes = attempt("git", ["status", "--porcelain", "--untracked-files=no", "--", ".", ":(exclude)worker/build-id.mjs"]);
  const fingerprint = attempt(process.env.PYTHON || "python3",
    ["-c", "from scripts.build_release_metadata import fingerprint; print(fingerprint())"]);
  return { commit: COMMIT.test(commit ?? "") ? commit : null, dirty: changes === null ? null : changes !== "",
    fingerprint: FINGERPRINT.test(fingerprint ?? "") ? fingerprint : null };
}

export async function collectStatus({ run, api, fetchImpl, origin, database, local }) {
  const workers = {};
  for (const [key, worker] of Object.entries(WORKERS)) workers[key] = await workerStatus(worker, { run, api });
  return { checked_at: new Date().toISOString(), local, workers, d1: d1Status(database, run), ready: await probeReady(origin, fetchImpl) };
}

function liveCommitCheck(worker, commit, { buildsExpected = false } = {}) {
  if (worker.error) return { state: "fail", detail: `could not read the deployment: ${worker.error}` };
  if (worker.versions.length !== 1) return { state: "fail", detail: `traffic is split across ${worker.versions.length} versions` };
  const [version] = worker.versions;
  if (version.commit === commit) return { state: "pass", detail: `version ${versionId(version)} runs ${short(commit)}` };
  const running = version.commit ? `runs ${short(version.commit)}` : "has no commit tag";
  const hint = version.source === "workersci" && !buildsExpected
    ? " (Workers Builds deployed it; see docs/deployment-cloudflare.md#workers-builds)" : "";
  return { state: "fail", detail: `version ${versionId(version)} ${running}, expected ${short(commit)}${hint}` };
}

export function evaluate(status, { commit, mainWorker }) {
  const checks = [];
  const add = (name, state, detail, retry = false) => checks.push({ name, state, detail, retry });
  const { d1, ready, workers, local } = status;
  if (d1.error) add("D1 migrations", "fail", `could not read applied migrations: ${d1.error}`);
  else if (d1.pending.length) add("D1 migrations", "fail", `pending: ${d1.pending.join(", ")}`);
  else add("D1 migrations", "pass", `${d1.applied} applied, none pending`);
  add("/ready", ready.ok ? "pass" : "fail", `${ready.status ?? "no response"}: ${ready.detail}`);
  const knowledge = liveCommitCheck(workers.knowledge, commit);
  add("Knowledge Worker", knowledge.state, knowledge.detail);
  const main = workers.main;
  const fingerprint = main.fingerprint && local.fingerprint ? main.fingerprint === local.fingerprint : null;
  if (mainWorker === "actions") {
    const live = liveCommitCheck(main, commit);
    add("Main Worker", live.state, live.detail);
    if (fingerprint === null) {
      add("Release fingerprint", "warn", main.notes.find(note => note.includes("fingerprint")) ?? (local.fingerprint
        ? "not compared; needs CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID" : "not compared; the checkout fingerprint needs Python"));
    } else add("Release fingerprint", fingerprint ? "pass" : "fail",
      fingerprint ? `bundle matches ${short(local.fingerprint)}` : `bundle has ${short(main.fingerprint)}, checkout has ${short(local.fingerprint)}`);
  } else {
    const live = liveCommitCheck(main, commit, { buildsExpected: true });
    if (live.state === "pass" || fingerprint) {
      add("Main Worker (Workers Builds)", "pass", fingerprint && live.state !== "pass"
        ? `bundle fingerprint matches ${short(local.fingerprint)}` : live.detail);
    } else {
      add("Main Worker (Workers Builds)", "warn", `${live.detail}; Workers Builds may still be building, may have failed, `
        + "or a newer commit replaced it", true);
    }
  }
  return checks;
}

function describeWorker(worker, local) {
  if (worker.error) return `${worker.name}: unavailable (${worker.error})`;
  const versions = worker.versions.map(version => {
    const source = SOURCES[version.source] ?? version.source ?? "unknown source";
    const trigger = version.triggered_by && version.triggered_by !== "upload" ? ` (${version.triggered_by})` : "";
    const commit = version.commit ? `commit ${short(version.commit)} (${version.commit_source})` : "commit unknown";
    return `version ${versionId(version)} at ${version.percentage}% from ${source}${trigger}, ${version.created_on ?? "date unknown"}, ${commit}`;
  });
  const parts = [`${worker.name}: ${versions.join("; ") || "no deployment"}`];
  if (worker.fingerprint) {
    const comparison = !local.fingerprint ? "" : worker.fingerprint === local.fingerprint ? " (matches checkout)" : " (differs from checkout)";
    parts.push(`fingerprint ${short(worker.fingerprint)}${comparison}`);
  }
  return [...parts, ...worker.notes].join(", ");
}

function describeD1(d1) {
  if (d1.error) return `${d1.database}: unavailable (${d1.error})`;
  const pending = d1.pending.length ? `pending ${d1.pending.join(", ")}` : "none pending";
  const unknown = d1.unknown.length ? `, applied but missing locally ${d1.unknown.join(", ")}` : "";
  return `${d1.database}: ${d1.applied} applied, ${d1.local} local, ${pending}${unknown}`;
}

function describeLocal(local) {
  const state = local.dirty === null ? "" : local.dirty ? " with uncommitted changes" : " (clean)";
  return `${local.commit ? short(local.commit) : "no git commit"}${state}, fingerprint ${short(local.fingerprint)}`;
}

function rows(status) {
  return [
    ["Local checkout", describeLocal(status.local)],
    ...Object.entries(WORKERS).map(([key, worker]) => [worker.label, describeWorker(status.workers[key], status.local)]),
    ["D1 migrations", describeD1(status.d1)],
    ["/ready", `${status.ready.status ?? "no response"} ${status.ready.detail} (${status.ready.url})`],
  ];
}

export function renderText(status, checks) {
  const lines = [`Deploy status at ${status.checked_at}`, ...rows(status).map(([name, value]) => `${name.padEnd(17)} ${value}`)];
  if (checks) lines.push("", ...checks.map(check => `${check.state.toUpperCase().padEnd(4)} ${check.name}: ${check.detail}`));
  return `${lines.join("\n")}\n`;
}

export function renderMarkdown(status, checks) {
  const cell = value => String(value).replaceAll("|", "\\|").replaceAll("\n", " ");
  const lines = ["### Deployed state", "", "| Component | State |", "| --- | --- |",
    ...rows(status).map(([name, value]) => `| ${cell(name)} | ${cell(value)} |`)];
  if (checks) {
    const icon = { pass: "pass", warn: "warning", fail: "FAILED" };
    lines.push("", "### Checks", "", "| Check | Result | Detail |", "| --- | --- | --- |",
      ...checks.map(check => `| ${cell(check.name)} | ${icon[check.state]} | ${cell(check.detail)} |`));
  }
  return `${lines.join("\n")}\n`;
}

export async function verifyUntilSettled({ collect, evaluateOptions, waitSeconds, sleep, now }) {
  const deadline = now() + waitSeconds * 1000;
  for (;;) {
    const status = await collect();
    const checks = evaluate(status, evaluateOptions);
    if (!checks.some(check => check.state === "fail" || check.retry) || now() >= deadline) return { status, checks };
    await sleep(Math.min(20_000, Math.max(1_000, deadline - now())));
  }
}

function defaultOrigin() {
  const config = JSON.parse(readFileSync(new URL("../wrangler.jsonc", import.meta.url), "utf8"));
  return config.vars?.WORKBENCH_WORKER_URL;
}

async function main(argv) {
  let options;
  try {
    ({ values: options } = parseArgs({ args: argv, options: {
      json: { type: "boolean" }, verify: { type: "boolean" }, commit: { type: "string" }, url: { type: "string" },
      "main-worker": { type: "string" }, wait: { type: "string", default: "0" }, markdown: { type: "string" },
      database: { type: "string", default: "multillm-intelligence" }, help: { type: "boolean" },
    } }));
  } catch (error) {
    console.error(`${error.message}\n${USAGE}`);
    return 2;
  }
  const wait = Number(options.wait);
  const mainWorker = options["main-worker"] ?? "actions";
  if (options.help) {
    console.log(USAGE);
    return 0;
  }
  if (!Number.isFinite(wait) || wait < 0 || !["actions", "workers-builds"].includes(mainWorker)
      || (options.verify && !COMMIT.test(options.commit ?? ""))) {
    console.error(`--verify needs --commit <40-character sha>; --main-worker is actions or workers-builds.\n${USAGE}`);
    return 2;
  }
  const origin = options.url || process.env.DEPLOY_STATUS_URL || defaultOrigin();
  if (!URL.canParse(origin ?? "")) {
    console.error(`Pass the Worker origin with --url; ${JSON.stringify(origin ?? null)} is not a URL.`);
    return 2;
  }
  const run = args => execFileSync("npx", ["--no-install", "wrangler", ...args], {
    cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], maxBuffer: 16 * 1024 * 1024,
    env: { ...process.env, WRANGLER_SEND_METRICS: "false", FORCE_COLOR: "0" },
  });
  const local = localRelease(ROOT, execFileSync);
  const collect = () => collectStatus({ run, api: cloudflareApi(process.env), fetchImpl: fetch, origin,
    database: options.database, local });
  const { status, checks } = options.verify
    ? await verifyUntilSettled({ collect, evaluateOptions: { commit: options.commit, mainWorker }, waitSeconds: wait,
      sleep: ms => new Promise(resolve => setTimeout(resolve, ms)), now: Date.now })
    : { status: await collect(), checks: null };
  if (options.json) console.log(JSON.stringify({ status, checks }, null, 2));
  else process.stdout.write(renderText(status, checks));
  if (options.markdown) appendFileSync(options.markdown, renderMarkdown(status, checks));
  if (process.env.GITHUB_ACTIONS === "true" && checks) {
    const escape = value => value.replaceAll("%", "%25").replaceAll("\r", "%0D").replaceAll("\n", "%0A");
    for (const check of checks.filter(item => item.state !== "pass")) {
      console.log(`::${check.state === "fail" ? "error" : "warning"} title=${check.name}::${escape(check.detail)}`);
    }
    if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `url=${origin}\n`);
  }
  return checks?.some(check => check.state === "fail") ? 1 : 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await main(process.argv.slice(2));
}
