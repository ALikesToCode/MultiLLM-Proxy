#!/usr/bin/env node
/** Verify application detail and the responding image, never the stale list version. */
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { pathToFileURL } from "node:url";
import { deploymentTarget } from "./deployment_target.mjs";
import { localRelease, parseJson } from "./deploy_status.mjs";

const STAMP = /^[0-9a-f]{64}$/;
export function snapshot(application) {
  if (!application?.id || !Number.isInteger(application.version) || application.version < 1
      || typeof application.configuration?.image !== "string") throw Error("Container detail has no verified version/image");
  return { id: application.id, version: application.version, image: application.configuration.image };
}
export function releaseConfig(config, releaseId = randomUUID()) {
  if (config.containers?.length !== 1 || config.containers[0].image !== "./Dockerfile") {
    throw Error("Verified deployment requires one Dockerfile Container");
  }
  return { ...config, containers: config.containers.map(container => ({ ...container,
    image_vars: { ...container.image_vars, MULTILLM_RELEASE_IMAGE_ID: releaseId } })) };
}
export async function verifyRollout({ before, readApplication, probe, expected, waitSeconds = 600,
  now = Date.now, sleep = ms => new Promise(resolve => setTimeout(resolve, ms)) }) {
  if (!STAMP.test(expected)) throw Error("Missing expected source fingerprint");
  const deadline = now() + waitSeconds * 1000;
  for (;;) {
    try {
      const after = snapshot(await readApplication());
      const ready = await probe();
      if (after.version > before.version && after.image !== before.image && ready.ok
          && ready.worker === expected && ready.container === expected) return after;
    } catch { /* A swap can temporarily have no live Container; the deadline still applies. */ }
    if (now() >= deadline) throw Error("Container rollout unverified: version/image did not advance or Worker/Container fingerprints differ; stop deployment");
    await sleep(Math.min(10000, Math.max(1, deadline - now())));
  }
}
export function captureApplication(target, run) {
  const container = target.main.containers?.[0];
  const name = container?.name || `${target.main.name}-${container?.class_name?.toLowerCase()}`;
  const applications = parseJson(run(["containers", "list", "--json", "--config", target.mainConfig]));
  if (!Array.isArray(applications)) throw Error("Container list is not an array");
  const matches = applications.filter(application => application.name === name);
  if (matches.length !== 1) throw Error("Select an existing, unique Container application before deployment");
  // Only use the list for identity. Its version/image may lag application detail.
  return snapshot(parseJson(run(["containers", "info", matches[0].id, "--json", "--config", target.mainConfig])));
}
async function main(argv) {
  const { values: options } = parseArgs({ args: argv, options: {
    prepare: { type: "boolean" }, verify: { type: "boolean" }, state: { type: "string" }, output: { type: "string" },
    config: { type: "string" }, "knowledge-config": { type: "string" }, wait: { type: "string", default: "600" },
  } });
  if (!options.state || options.prepare === options.verify || !Number.isFinite(Number(options.wait)) || Number(options.wait) < 0) {
    throw Error("Use --prepare --state <file> --output <config>, or --verify --state <file>");
  }
  const target = deploymentTarget({ mainConfig: options.config, knowledgeConfig: options["knowledge-config"] });
  if (!URL.canParse(target.origin ?? "")) throw Error("Configure DEPLOY_STATUS_URL or WORKBENCH_WORKER_URL");
  const run = args => execFileSync("npx", ["--no-install", "wrangler", ...args], {
    encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 60000,
    env: { ...process.env, WRANGLER_SEND_METRICS: "false", CI: "true" },
  });
  if (options.prepare) {
    if (!options.output) throw Error("Missing release config output");
    const before = captureApplication(target, run);
    const expected = localRelease(process.cwd(), execFileSync).fingerprint;
    if (!STAMP.test(expected ?? "")) throw Error("Could not fingerprint the release");
    writeFileSync(options.output, JSON.stringify(releaseConfig(target.main), null, 2) + "\n");
    writeFileSync(options.state, JSON.stringify({ before, expected }));
    return;
  }
  const { before, expected } = JSON.parse(readFileSync(options.state, "utf8"));
  await verifyRollout({ before, expected, waitSeconds: Number(options.wait),
    readApplication: async () => parseJson(run(["containers", "info", before.id, "--json", "--config", target.mainConfig])),
    probe: async () => {
      const response = await fetch(new URL("/ready", target.origin), { redirect: "error", signal: AbortSignal.timeout(30000),
        headers: { "Cache-Control": "no-cache" } });
      await response.body?.cancel();
      return { ok: response.ok, worker: response.headers.get("X-MultiLLM-Worker-Build"),
        container: response.headers.get("X-MultiLLM-Container-Build") };
    } });
  console.log("Container version/image advanced; responding Worker and Container source fingerprints match.");
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { await main(process.argv.slice(2)); }
  catch { console.error("Container deployment verification failed. Check the selected application detail, rollout and release fingerprints; do not enable restrictions."); process.exitCode = 1; }
}
