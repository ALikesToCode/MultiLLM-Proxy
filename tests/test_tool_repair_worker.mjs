import assert from "node:assert/strict";
import test from "node:test";
import { collectContainerEnv } from "../worker/container-env.mjs";
import { CORS_DEFAULT_HEADERS, CORS_EXPOSE_HEADERS } from "../worker/cors-policy.mjs";
import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";

test("tool repair default reaches the container", () => {
  assert.equal(collectContainerEnv({ TOOL_CALL_REPAIR_DEFAULT: "full" }).TOOL_CALL_REPAIR_DEFAULT, "full");
});

test("browser clients can select repair and read its counts", () => {
  assert.ok(CORS_DEFAULT_HEADERS.split(", ").includes("X-MultiLLM-Tool-Repair"));
  assert.ok(CORS_EXPOSE_HEADERS.split(", ").includes("X-MultiLLM-Tool-Repair"));
});

for (const [label, summary, contentType] of [
  ["response counts", "checked=1 repaired=1 extracted=0 invalid=0 reasked=0", "application/json"],
  ["streaming status", "mode=full; streaming=1", "text/event-stream"],
]) {
  test(`unified requests retain the mode and ${label} through the edge`, async () => {
    const worker = (await loadWorkerModule()).default;
    const counts = summary;
    let forwarded;
    const stub = {
      async startAndWaitForPorts() {},
      async containerFetch(input, init) {
        const resolved = typeof input === "string" && input.startsWith("/") ? "http://container" + input : input;
        forwarded = resolved instanceof Request ? resolved : new Request(resolved, { ...init, ...(init?.body !== undefined ? { duplex: "half" } : {}) });
        return new Response(contentType === "text/event-stream" ? "data: [DONE]\n\n" : "{}", { headers: { "Content-Type": contentType, "X-MultiLLM-Tool-Repair": counts } });
      },
      async fetch(request) { return this.containerFetch(request); },
    };
    const response = await worker.fetch(new Request("https://gateway.example/v1/chat/completions", {
      method: "POST", headers: { "Content-Type": "application/json", "X-MultiLLM-Tool-Repair": "full", Origin: "https://client.example" },
      body: JSON.stringify({ model: "openai:synthetic", messages: [], tools: [] }),
    }), { MULTILLM_PROXY_CONTAINER: { getByName: () => stub } });
    assert.equal(response.status, 200);
    assert.equal(forwarded.headers.get("X-MultiLLM-Tool-Repair"), "full");
    assert.equal(response.headers.get("X-MultiLLM-Tool-Repair"), counts);
    assert.match(response.headers.get("Access-Control-Expose-Headers"), /X-MultiLLM-Tool-Repair/);
  });
}
