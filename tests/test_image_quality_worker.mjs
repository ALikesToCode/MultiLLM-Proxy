import assert from "node:assert/strict";
import test from "node:test";
import { collectContainerEnv } from "../worker/container-env.mjs";
import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";

test("image QA judge model reaches the container without changing the default", () => {
  assert.equal(collectContainerEnv({}).IMAGE_QA_JUDGE_MODEL, undefined);
  assert.equal(collectContainerEnv({ IMAGE_QA_JUDGE_MODEL: "free:vision" }).IMAGE_QA_JUDGE_MODEL, "free:vision");
  assert.equal(collectContainerEnv({ IMAGE_QA_JUDGE_MODEL: "opencode:synthetic-vision" }).IMAGE_QA_JUDGE_MODEL,
    "opencode:synthetic-vision");
});

test("image QA header is allowed and exposed at the edge", async () => {
  const { default: worker } = await loadWorkerModule();
  const response = await worker.fetch(new Request("https://gateway.invalid/v1/images/generations", {
    method: "OPTIONS", headers: { Origin: "https://client.invalid" },
  }), {}, {});
  assert.equal(response.status, 204);
  assert.match(response.headers.get("Access-Control-Allow-Headers"), /X-MultiLLM-Image-QA/i);
  assert.match(response.headers.get("Access-Control-Expose-Headers"), /X-MultiLLM-Image-QA/i);
});
