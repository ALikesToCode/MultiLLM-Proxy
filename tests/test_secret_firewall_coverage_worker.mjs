import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync, readdirSync } from "node:fs";
const coverage = JSON.parse(readFileSync(new URL("./fixtures/secret_firewall_coverage.json", import.meta.url)));
const inventory = coverage.edge_dispatches;
test("new edge dispatches require a firewall coverage review", () => {
  for (const [file, expected] of Object.entries(inventory)) {
    const source = readFileSync(new URL("../" + file, import.meta.url), "utf8");
    assert.deepEqual({ dispatches: [...source.matchAll(/\b(?:fetch|firewallFetch|dispatchKnowledge|dispatch)\(/g)].length,
      guards: [...source.matchAll(/\b(?:firewallFetch|protectPayload)\(/g)].length }, expected, file);
  }
  const source = readFileSync(new URL("../cloudflare-worker.mjs", import.meta.url), "utf8");
  assert.equal([...source.matchAll(/await firewallFetch\(upstreamRequest/g)].length, 3);
  assert.ok(!/await fetch\(upstreamRequest/.test(source));
  const roleplay = readFileSync(new URL("../worker/roleplay/transport.mjs", import.meta.url), "utf8");
  assert.ok(roleplay.includes("await firewallFetch(new Request"));
  assert.ok(roleplay.includes("await containerNamespace.getByName"));
});

test("new edge routes and modules require reviewing the dispatch inventory", () => {
  const root = new URL("../", import.meta.url);
  const modules = readdirSync(new URL("worker", root), { recursive: true }).filter(name => name.endsWith(".mjs")).map(name => "worker/" + name).sort();
  assert.deepEqual(modules, coverage.edge_modules);
  for (const [file, paths] of Object.entries(coverage.edge_route_literals)) {
    const source = readFileSync(new URL(file, root), "utf8");
    assert.deepEqual([...new Set([...source.matchAll(/["'](\/[^"'\n]*)["']/g)].map(match => match[1]))].sort(), paths, file);
  }
});
