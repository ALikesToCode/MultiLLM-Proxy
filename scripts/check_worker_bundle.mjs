#!/usr/bin/env node
/** Bundle validation without remote release admission. This command cannot deploy. */
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, unlinkSync } from "node:fs";
import { resolve } from "node:path";
import { randomUUID } from "node:crypto";
import { parseArgs } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = new URL("../", import.meta.url);
export function bundleConfig(config) {
  const result = structuredClone(config);
  delete result.build;
  return result;
}
export function bundleArguments(config, outdir, main) {
  return ["exec", "wrangler", "deploy", "--config", resolve(config), "--dry-run",
    ...(main ? ["--containers-rollout=none"] : []), "--outdir", resolve(outdir)];
}
function main() {
  const { values } = parseArgs({ options: { config: { type: "string" }, outdir: { type: "string" } } });
  if (!["wrangler.jsonc", "wrangler.knowledge.jsonc"].includes(values.config) || !values.outdir) {
    throw new Error("Pass --config wrangler.jsonc|wrangler.knowledge.jsonc and --outdir");
  }
  const source = JSON.parse(readFileSync(new URL(values.config, ROOT)));
  // Keep relative paths rooted beside the real configuration. Never change the
  // committed release config or provide a general build-admission bypass flag.
  const temporary = new URL(`.wrangler-bundle-${randomUUID()}.jsonc`, ROOT);
  writeFileSync(temporary, JSON.stringify(bundleConfig(source)), { flag: "wx", mode: 0o600 });
  try {
    execFileSync("pnpm", bundleArguments(fileURLToPath(temporary), values.outdir, values.config === "wrangler.jsonc"),
      { cwd: ROOT, stdio: "inherit", env: { ...process.env, WRANGLER_SEND_METRICS: "false" } });
  } finally { unlinkSync(temporary); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
