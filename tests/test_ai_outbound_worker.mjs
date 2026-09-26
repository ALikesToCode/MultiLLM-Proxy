import assert from "node:assert/strict";
import test from "node:test";

import { handleAiOutbound, imageInput } from "../worker/ai-outbound.mjs";
import { collectContainerEnv } from "../worker/container-env.mjs";

function ai(result) {
  const calls = [];
  return { calls, async run(model, input, options) {
    calls.push({ model, input, options });
    if (result instanceof Error) throw result;
    return typeof result === "function" ? result(model, input) : result;
  } };
}

const post = (path, body, env) => handleAiOutbound(new Request(`http://ai.internal${path}`, {
  method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }), env);

test("third-party GPT Image models run through AI Gateway with OpenAI parameters", async () => {
  const env = { AI: ai({ result: { image: "https://images.example/out.png" } }), AI_GATEWAY_ID: "media" };
  const response = await post("/v1/images/generations", { model: "openai/gpt-image-2.5-sunburst", prompt: "A lighthouse",
    size: "3840x2160", quality: "max", background: "opaque", output_format: "png", response_format: "url", user: "ignored" }, env);
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.deepEqual(body.data, [{ url: "https://images.example/out.png" }]);
  assert.deepEqual(env.AI.calls[0], { model: "openai/gpt-image-2.5-sunburst",
    input: { prompt: "A lighthouse", size: "3840x2160", quality: "max", background: "opaque", output_format: "png" },
    options: { gateway: { id: "media" } } });
});

test("an image URL is downloaded when the caller asks for base64", async () => {
  const original = globalThis.fetch;
  globalThis.fetch = async url => { assert.equal(url, "https://images.example/out.png"); return new Response(new Uint8Array([1, 2, 3])); };
  try {
    const env = { AI: ai({ image: "https://images.example/out.png" }) };
    const body = await (await post("/v1/images/generations", { model: "openai/gpt-image-2", prompt: "x" }, env)).json();
    assert.deepEqual(body.data, [{ b64_json: "AQID" }]);
    assert.deepEqual(env.AI.calls[0].options, { gateway: { id: "default" } });
  } finally { globalThis.fetch = original; }
});

test("Workers AI image models receive their own dimensions and step budget", async () => {
  assert.deepEqual(imageInput({ model: "@cf/leonardo/lucid-origin", prompt: "x", size: "3840x2160", quality: "max" }),
    { prompt: "x", width: 2496, height: 1400, steps: 40 });
  assert.deepEqual(imageInput({ model: "@cf/black-forest-labs/flux-1-schnell", prompt: "x", size: "1024x1024", quality: "high" }),
    { prompt: "x", steps: 6 });
  const env = { AI: ai({ image: "data:image/jpeg;base64,/9j/AA==" }) };
  const body = await (await post("/v1/images/generations", { model: "@cf/leonardo/lucid-origin", prompt: "x" }, env)).json();
  assert.deepEqual(body.data, [{ b64_json: "/9j/AA==" }]);
});

test("unsupported requests and AI Gateway refusals keep their meaning", async () => {
  const env = { AI: ai({ image: "abc" }) };
  assert.equal((await post("/v1/images/generations", { model: "@cf/unknown/model", prompt: "x" }, env)).status, 404);
  assert.equal((await post("/v1/images/generations", { model: "openai/gpt-image-2", prompt: "x", n: 2 }, env)).status, 400);
  assert.equal((await post("/v1/images/generations", { model: "openai/gpt-image-2", prompt: " " }, env)).status, 400);
  assert.equal((await post("/v1/images/generations", { model: "openai/gpt-image-2", prompt: "x" }, {})).status, 503);
  assert.equal((await handleAiOutbound(new Request("http://other.internal/v1/images/generations", { method: "POST" }), env)).status, 404);
  for (const [message, status] of [["AiError: 5006: input is invalid", 400], ["Unified Billing: insufficient credits", 402],
    ["AiError: 3040: rate limit exceeded (429)", 429], ["socket hang up", 502]]) {
    const response = await post("/v1/images/generations", { model: "openai/gpt-image-2", prompt: "x" }, { AI: ai(new Error(message)) });
    assert.equal(response.status, status, message);
    assert.equal(JSON.stringify(await response.json()).includes(message), false, "provider detail stays in the log");
  }
});

test("Veo runs through Cloudflare AI and returns the finished clip", async () => {
  const env = { AI: ai({ video: "https://videos.example/clip.mp4" }) };
  const response = await post("/v1/videos/generations", { model: "google/veo-3.1", prompt: "An eagle", aspect_ratio: "16:9",
    resolution: "1080p", duration: 8 }, env);
  assert.deepEqual(await response.json(), { status: "completed", video_url: "https://videos.example/clip.mp4", model: "google/veo-3.1" });
  assert.deepEqual(env.AI.calls[0].input, { prompt: "An eagle", generate_audio: true, aspect_ratio: "16:9", resolution: "1080p", duration: "8s" });
  assert.equal((await post("/v1/videos/generations", { model: "openai/sora-2", prompt: "x" }, env)).status, 404);
});

test("GPT Image edits send the source images to AI Gateway and nothing else accepts them", async () => {
  const env = { AI: ai({ image: "https://images.example/edit.png" }) };
  const source = "data:image/png;base64,iVBORw0KGgo=";
  const response = await post("/v1/images/edits", { model: "openai/gpt-image-2.5-flare", prompt: "Clay", images: [source],
    quality: "max", response_format: "url" }, env);
  assert.equal(response.status, 200);
  assert.deepEqual((await response.json()).data, [{ url: "https://images.example/edit.png" }]);
  assert.deepEqual(env.AI.calls[0].input, { prompt: "Clay", quality: "max", images: [source] });
  for (const body of [{ model: "@cf/leonardo/lucid-origin", prompt: "x", images: [source] },
    { model: "openai/gpt-image-2", prompt: "x", images: [] },
    { model: "openai/gpt-image-2", prompt: "x", images: ["https://images.example/a.png"] }]) {
    assert.notEqual((await post("/v1/images/edits", body, env)).status, 200, JSON.stringify(body));
  }
  assert.equal((await post("/v1/images/generations", { model: "openai/gpt-image-2", prompt: "x", images: [source] }, env)).status, 400);
  assert.equal(env.AI.calls.length, 1);
});

test("Workers AI embeddings, Aura speech and Whisper transcription answer in OpenAI shapes", async () => {
  const embed = { AI: ai({ shape: [2, 2], data: [[0.1, 0.2], [0.3, 0.4]] }) };
  const vectors = await (await post("/v1/embeddings", { model: "@cf/baai/bge-m3", input: ["a", "b"] }, embed)).json();
  assert.deepEqual(vectors.data, [{ object: "embedding", index: 0, embedding: [0.1, 0.2] }, { object: "embedding", index: 1, embedding: [0.3, 0.4] }]);
  assert.deepEqual(embed.AI.calls[0].input, { text: ["a", "b"] });
  assert.equal((await post("/v1/embeddings", { model: "@cf/baai/bge-m3", input: [1, 2] }, embed)).status, 400);
  assert.equal((await post("/v1/embeddings", { model: "@cf/unknown/embed", input: "a" }, embed)).status, 404);

  const speak = { AI: ai(() => new ReadableStream({ start(controller) { controller.enqueue(new Uint8Array([7, 8])); controller.close(); } })) };
  const audio = await post("/v1/audio/speech", { model: "@cf/deepgram/aura-2-en", input: "Hello", voice: "orion", response_format: "wav" }, speak);
  assert.equal(audio.headers.get("content-type"), "audio/wav");
  assert.deepEqual(new Uint8Array(await audio.arrayBuffer()), new Uint8Array([7, 8]));
  assert.deepEqual(speak.AI.calls[0].input, { text: "Hello", speaker: "orion", encoding: "linear16", container: "wav" });
  await post("/v1/audio/speech", { model: "@cf/deepgram/aura-2-en", input: "Hello", voice: "alloy" }, speak);
  assert.deepEqual(speak.AI.calls[1].input, { text: "Hello", speaker: "luna", encoding: "mp3" });

  const hear = { AI: ai({ text: "hello world", word_count: 2 }) };
  const text = await (await post("/v1/audio/transcriptions", { model: "@cf/openai/whisper-large-v3-turbo", audio: "AAAA",
    language: "en", prompt: "names" }, hear)).json();
  assert.deepEqual(text, { text: "hello world" });
  assert.deepEqual(hear.AI.calls[0].input, { audio: "AAAA", language: "en", initial_prompt: "names" });
  assert.equal((await post("/v1/audio/transcriptions", { model: "@cf/openai/whisper-large-v3-turbo", audio: "not base64!" }, hear)).status, 400);
});

test("the Container learns about Cloudflare AI only when the binding exists", () => {
  assert.equal(collectContainerEnv({ AI: {} }).CLOUDFLARE_AI_ENABLED, "true");
  assert.equal(collectContainerEnv({}).CLOUDFLARE_AI_ENABLED, undefined);
});
