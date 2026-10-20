import { execFileSync } from "node:child_process";
import { build } from "esbuild";

export const OLD = "544bf49ba3b3d03d185ec5b5a71b2b1877dda786";

/** Compile the actual pinned source tree, without replacing protocol handlers. */
export async function runtimeBundle(contents, revision = "", platform = "node") {
  const root = process.cwd();
  const output = await build({ stdin: { resolveDir: root, contents }, bundle: true,
    format: "esm", platform, external: ["node:*"], write: false,
    plugins: [{ name: "runtime-version", setup(b) {
      b.onResolve({ filter: /^cloudflare:workers$/ }, () => ({ path: "runtime", namespace: "stub" }));
      b.onLoad({ filter: /.*/, namespace: "stub" }, () => ({ contents:
        "export class DurableObject {constructor(ctx,env){this.ctx=ctx;this.env=env}}; export class WorkflowEntrypoint {}" }));
      if (platform === "node") b.onResolve({ filter: /dispatch-network\.mjs$/ }, () => ({
        path: new URL("../../worker/dispatch-network.mjs", import.meta.url).href, external: true,
      }));
      if (revision) b.onLoad({ filter: /\/worker\/.*\.(mjs|json)$/ }, args => ({
        contents: execFileSync("git", ["show", `${revision}:${args.path.slice(root.length + 1)}`], { encoding: "utf8" }),
        loader: args.path.endsWith(".json") ? "json" : "js",
      }));
    } }] });
  return output.outputFiles[0].text;
}

export async function runtimeModule(contents, revision) {
  const source = await runtimeBundle(contents, revision);
  return import(`data:text/javascript;base64,${Buffer.from(source).toString("base64")}`);
}

export class MemoryStorage {
  constructor() { this.rows = new Map(); this.pending = Promise.resolve(); }
  async get(k) { return structuredClone(this.rows.get(k)); }
  async put(k, v) {
    if (typeof k === "string") this.rows.set(k, structuredClone(v));
    else for (const [name, value] of Object.entries(k)) this.rows.set(name, structuredClone(value));
  }
  async delete(keys) { for (const key of Array.isArray(keys) ? keys : [keys]) this.rows.delete(key); }
  async list({ prefix = "", limit = Infinity, startAfter } = {}) {
    return new Map([...this.rows].filter(([k]) => k.startsWith(prefix) && (!startAfter || k > startAfter))
      .sort().slice(0, limit).map(([k, v]) => [k, structuredClone(v)]));
  }
  transaction(fn) { const result = this.pending.then(() => fn(this)); this.pending = result.catch(() => {}); return result; }
}
