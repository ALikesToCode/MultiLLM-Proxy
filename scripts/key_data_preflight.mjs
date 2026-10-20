#!/usr/bin/env node
/** Release admission, before uploading a Worker or replacing its Container. */
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { deploymentTarget } from "./deployment_target.mjs";
import { localMigrations, remoteAppliedMigrations } from "./verify_d1_migrations.mjs";

const ROOT = new URL("../", import.meta.url);
const MAIN_CONFIG = process.env.MAIN_WORKER_CONFIG || "wrangler.jsonc";
const KNOWLEDGE_CONFIG = process.env.KNOWLEDGE_WORKER_CONFIG || "wrangler.knowledge.jsonc";
const REQUIRED_SECRETS = ["ADMIN_API_KEY", "FLASK_SECRET_KEY", "JWT_SECRET"];
const REQUIRED_COLUMNS = {
  control_users: ["official_only", "forced_provider_preferences", "max_stream_cost_microusd"],
  intelligence_principals: ["official_only", "forced_provider_preferences"],
};
class PreflightError extends Error {}
const requireThat = (condition, message) => { if (!condition) throw new PreflightError(message); };

export function checkConfig(main, knowledge) {
  const database = config => config.d1_databases?.find(item => item.binding === "INTELLIGENCE_DB");
  const first = database(main), second = database(knowledge);
  requireThat(main.vars?.AUTH_STORAGE_BACKEND === "d1", "AUTH_STORAGE_BACKEND must explicitly select d1");
  requireThat(first?.database_id && first.database_name && first.migrations_dir === "intelligence-migrations",
    "Main Worker needs the migrated INTELLIGENCE_DB binding");
  requireThat(second?.database_id === first.database_id && second?.database_name === first.database_name
    && second?.migrations_dir === first.migrations_dir, "Both Workers must bind the same migrated D1");
  requireThat(main.services?.some(item => item.binding === "KNOWLEDGE_SERVICE" && item.service === knowledge.name),
    "KNOWLEDGE_SERVICE must target the configured private Worker");
  requireThat(knowledge.workers_dev === false && knowledge.preview_urls === false,
    "Knowledge Worker must remain private");
  requireThat(main.containers?.some(item => item.class_name === "MultiLLMProxyContainer" && item.image === "./Dockerfile")
    && main.durable_objects?.bindings?.some(item => item.name === "MULTILLM_PROXY_CONTAINER"
      && item.class_name === "MultiLLMProxyContainer"), "Main Worker needs its Container binding and image");
  return first.database_name;
}

export function checkPrerequisites({ main, knowledge, run, migrations = localMigrations() }) {
  const database = checkConfig(main, knowledge);
  const applied = remoteAppliedMigrations(database, run);
  requireThat(migrations.every(name => applied.includes(name)) && applied.every(name => migrations.includes(name)),
    "D1 migration ledger must exactly match this release");
  for (const [table, required] of Object.entries(REQUIRED_COLUMNS)) {
    const results = JSON.parse(run(["d1", "execute", database, "--remote", "--json", "--command", `PRAGMA table_info(${table})`]));
    requireThat(Array.isArray(results) && results.every(item => item.success === true && Array.isArray(item.results)),
      "Account schema could not be verified");
    const columns = results.flatMap(item => item.results).map(item => item.name);
    requireThat(required.every(name => columns.includes(name)), "Account policy columns are missing from D1");
  }
  const secrets = JSON.parse(run(["secret", "list", "--config", MAIN_CONFIG]));
  requireThat(REQUIRED_SECRETS.every(name => main.vars?.[name] || secrets.some(item => item.name === name)),
    "Main Worker needs ADMIN_API_KEY, FLASK_SECRET_KEY and JWT_SECRET bindings");
}

export function sourceCapability(commit) {
  if (!/^[0-9a-f]{40}$/.test(commit)) return null;
  try {
    const source = execFileSync("git", ["show", `${commit}:worker/key-controls-capability.mjs`],
      { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    const match = /protocol: ([12]), enforcement: (true|false)/.exec(source);
    return match ? { protocol: Number(match[1]), enforcement: match[2] === "true" } : null;
  } catch { return null; }
}

export function checkRelease(options) {
  checkPrerequisites(options);
  const { commit, run } = options;
  requireThat(/^[0-9a-f]{40}$/.test(commit), "Release needs a full commit identity");
  const deployment = JSON.parse(run(["deployments", "status", "--json", "--config", KNOWLEDGE_CONFIG]));
  requireThat(deployment.versions?.length === 1 && deployment.versions[0].percentage === 100,
    "Private Worker must have one fully active version");
  const version = JSON.parse(run(["versions", "view", deployment.versions[0].version_id, "--json", "--config", KNOWLEDGE_CONFIG]));
  const capability = (options.sourceCapability ?? sourceCapability)(version.annotations?.["workers/tag"]);
  requireThat(capability?.protocol >= 1, "Deploy and verify the expansion private Worker before the main Worker");
}

function main(args) {
  const mainConfig = JSON.parse(readFileSync(new URL(MAIN_CONFIG, ROOT)));
  const knowledge = JSON.parse(readFileSync(new URL(KNOWLEDGE_CONFIG, ROOT)));
  try {
    checkConfig(mainConfig, knowledge);
    if (args[0] === "--check" || process.env.WRANGLER_COMMAND === "dev") {
      console.log("Release configuration checked (no deployment admission).");
      return 0;
    }
    requireThat(["--prepare", "--deploy"].includes(args[0]), "Use --check, --prepare or --deploy");
    deploymentTarget({ mainConfig: MAIN_CONFIG, knowledgeConfig: KNOWLEDGE_CONFIG });
    const git = args => execFileSync("git", args, { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
    const commit = git(["rev-parse", "HEAD"]);
    requireThat(!git(["status", "--porcelain", "--untracked-files=no", "--", ".", ":(exclude)worker/build-id.mjs"]),
      "Deploy from a clean committed checkout");
    const run = args => execFileSync("npx", ["--no-install", "wrangler", ...args, ...(args[0] === "d1" ? ["--config", MAIN_CONFIG] : [])], {
      cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 60000,
      env: { ...process.env, WRANGLER_SEND_METRICS: "false" },
    });
    const options = { main: mainConfig, knowledge, commit, run };
    if (args[0] === "--prepare") {
      checkPrerequisites(options);
      console.log("Release prerequisites checked before private Worker deployment.");
      return 0;
    }
    checkRelease(options);
    console.log("Release admitted: migrations, account schema, required bindings and private Worker expansion verified.");
    return 0;
  } catch (error) {
    // CLI output may contain environment details; print only our own diagnostics.
    const message = error instanceof PreflightError ? error.message : "Could not verify release prerequisites";
    console.error(`Deployment preflight refused: ${message}. No main upload is admitted.`);
    return 1;
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = main(process.argv.slice(2));
