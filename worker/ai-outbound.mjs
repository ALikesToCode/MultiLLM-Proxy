/**
 * Cloudflare AI for the Container, reachable only through its private outbound handler
 * (`http://ai.internal`). Third-party models (OpenAI GPT Image, Google Veo) run through
 * AI Gateway with Cloudflare billing and zero data retention; `@cf/` models run on
 * Workers AI. Replies use OpenAI shapes so the Container treats this like any provider.
 */
import { Buffer } from "node:buffer";
import { logFailure } from "./log.mjs";

const MAX_BODY_BYTES = 64 * 1024;
// Edits carry up to 16 source images as base64 data URLs.
const MAX_EDIT_BODY_BYTES = 24 * 1024 * 1024;
const DATA_IMAGE = /^data:image\/(?:png|jpeg|webp);base64,[A-Za-z0-9+/=]+$/;
const MAX_FETCHED_IMAGE_BYTES = 40 * 1024 * 1024;
const THIRD_PARTY_IMAGE = /^openai\/gpt-image-[a-z0-9.-]{1,40}$/;
const THIRD_PARTY_VIDEO = new Set(["google/veo-3.1"]);
const IMAGE_FIELDS = ["size", "quality", "background", "output_format", "output_compression", "moderation"];
// Diffusion steps per requested quality; `max` asks for each model's ceiling.
const STEPS = { low: 0.25, medium: 0.5, high: 0.75, xhigh: 1, max: 1 };
const WORKERS_AI_IMAGE = {
  "@cf/leonardo/lucid-origin": { maxEdge: 2500, maxSteps: 40, dimensions: true },
  "@cf/leonardo/phoenix-1.0": { maxEdge: 2048, maxSteps: 50, dimensions: true },
  "@cf/black-forest-labs/flux-1-schnell": { maxEdge: 0, maxSteps: 8, dimensions: false },
};

const failure = (code, message, status) => Response.json({ error: { code, message } },
  { status, headers: { "cache-control": "no-store" } });
const isRecord = value => value !== null && typeof value === "object" && !Array.isArray(value);

async function boundedJson(request, maxBytes = MAX_BODY_BYTES) {
  const length = request.headers.get("content-length");
  if (length !== null && Number(length) > maxBytes) return null;
  const text = await request.text();
  if (text.length > maxBytes) return null;
  try {
    const body = JSON.parse(text);
    return isRecord(body) ? body : null;
  } catch { return null; }
}

// AI Gateway reports quota, credit and validation refusals as error messages.
function refusal(error) {
  const message = String(error?.message ?? error ?? "");
  if (/\b429\b|rate.?limit|too many requests/i.test(message)) return ["rate_limited", 429];
  if (/credit|insufficient|billing|payment|balance/i.test(message)) return ["payment_required", 402];
  if (/not found|no such model|unknown model|5007/i.test(message)) return ["model_not_found", 404];
  if (/invalid|schema|required|must be|bad input|5006/i.test(message)) return ["invalid_request", 400];
  if (/moderat|safety|policy/i.test(message)) return ["content_policy", 400];
  return ["upstream_error", 502];
}

function dimensions(size, maxEdge) {
  const match = /^(\d{2,5})x(\d{2,5})$/.exec(String(size ?? ""));
  if (!match) return {};
  const [width, height] = [Number(match[1]), Number(match[2])];
  const scale = Math.min(1, maxEdge / Math.max(width, height));
  // Workers AI image models expect multiples of 8.
  return { width: Math.floor((width * scale) / 8) * 8, height: Math.floor((height * scale) / 8) * 8 };
}

export function imageInput(body) {
  const input = { prompt: body.prompt };
  if (THIRD_PARTY_IMAGE.test(body.model)) {
    for (const field of IMAGE_FIELDS) if (body[field] !== undefined) input[field] = body[field];
    // AI Gateway sends a request with `images` to OpenAI's edit endpoint.
    if (Array.isArray(body.images)) input.images = body.images;
    return input;
  }
  const spec = WORKERS_AI_IMAGE[body.model];
  if (spec.dimensions) Object.assign(input, dimensions(body.size, spec.maxEdge));
  const share = STEPS[body.quality];
  if (share) input.steps = Math.max(1, Math.round(spec.maxSteps * share));
  return input;
}

async function imageData(image, responseFormat) {
  if (typeof image !== "string" || !image) return null;
  if (/^https:\/\//i.test(image)) {
    if (responseFormat === "url") return { url: image };
    const response = await fetch(image, { signal: AbortSignal.timeout(30000) });
    const length = Number(response.headers.get("content-length") ?? 0);
    if (!response.ok || length > MAX_FETCHED_IMAGE_BYTES) throw new Error(`Image download failed with HTTP ${response.status}`);
    const bytes = await response.arrayBuffer();
    if (bytes.byteLength > MAX_FETCHED_IMAGE_BYTES) throw new Error("Generated image is too large");
    return { b64_json: Buffer.from(bytes).toString("base64") };
  }
  // A base64 result has no URL to share; the caller receives the bytes instead.
  return { b64_json: image.replace(/^data:image\/[a-z]+;base64,/i, "") };
}

async function run(env, model, input) {
  const response = await env.AI.run(model, input, { gateway: { id: env.AI_GATEWAY_ID || "default" } });
  return isRecord(response?.result) ? response.result : response;
}

async function generateImage(env, body) {
  if (typeof body.prompt !== "string" || !body.prompt.trim() || body.prompt.length > 32000) {
    return failure("invalid_request", "A prompt is required.", 400);
  }
  if (!THIRD_PARTY_IMAGE.test(body.model ?? "") && !Object.hasOwn(WORKERS_AI_IMAGE, body.model ?? "")) {
    return failure("model_not_found", "This model is not served through Cloudflare AI here.", 404);
  }
  if (body.n !== undefined && body.n !== 1) return failure("invalid_request", "Cloudflare AI generates one image per request.", 400);
  const result = await run(env, body.model, imageInput(body));
  const data = await imageData(result?.image, body.response_format);
  if (!data) throw new Error("Cloudflare AI returned no image");
  return Response.json({ created: Math.floor(Date.now() / 1000), data: [data], model: body.model },
    { headers: { "cache-control": "no-store" } });
}

async function editImage(env, body) {
  if (!THIRD_PARTY_IMAGE.test(body.model ?? "")) {
    return failure("model_not_found", "Only OpenAI GPT Image models edit images through Cloudflare AI here.", 404);
  }
  if (!Array.isArray(body.images) || !body.images.length || body.images.length > 16
    || !body.images.every(image => typeof image === "string" && DATA_IMAGE.test(image))) {
    return failure("invalid_request", "images must hold 1 to 16 PNG, JPEG or WebP data URLs.", 400);
  }
  return generateImage(env, body);
}

async function generateVideo(env, body) {
  if (!THIRD_PARTY_VIDEO.has(body.model)) return failure("model_not_found", "This video model is not served through Cloudflare AI here.", 404);
  if (typeof body.prompt !== "string" || !body.prompt.trim()) return failure("invalid_request", "A prompt is required.", 400);
  const input = { prompt: body.prompt, generate_audio: body.generate_audio !== false };
  if (body.aspect_ratio) input.aspect_ratio = String(body.aspect_ratio);
  if (body.resolution) input.resolution = String(body.resolution);
  if (body.duration) input.duration = `${Number(body.duration)}s`;
  if (body.image_url) input.image = String(body.image_url);
  // The binding waits for the finished clip, so the reply is already complete.
  const result = await run(env, body.model, input);
  if (typeof result?.video !== "string" || !/^https:\/\//i.test(result.video)) throw new Error("Cloudflare AI returned no video");
  return Response.json({ status: "completed", video_url: result.video, model: body.model }, { headers: { "cache-control": "no-store" } });
}

export async function handleAiOutbound(request, env) {
  const url = new URL(request.url);
  if (url.origin !== "http://ai.internal" || url.search || url.hash || url.username || url.password || request.method !== "POST") {
    return failure("not_found", "Unknown Cloudflare AI operation.", 404);
  }
  if (!env.AI) return failure("ai_not_configured", "The Worker has no Cloudflare AI binding.", 503);
  if (request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase() !== "application/json") {
    return failure("invalid_request", "Use application/json.", 415);
  }
  const edit = url.pathname === "/v1/images/edits";
  const body = await boundedJson(request, edit ? MAX_EDIT_BODY_BYTES : MAX_BODY_BYTES);
  if (!body) {
    return failure("invalid_request", `The request body must be a JSON object of at most ${edit ? "24 MiB" : "64 KiB"}.`, 400);
  }
  try {
    if (url.pathname === "/v1/images/generations") {
      if (body.images !== undefined) return failure("invalid_request", "Send source images to /v1/images/edits.", 400);
      return await generateImage(env, body);
    }
    if (edit) return await editImage(env, body);
    if (url.pathname === "/v1/videos/generations") return await generateVideo(env, body);
    return failure("not_found", "Unknown Cloudflare AI operation.", 404);
  } catch (error) {
    const [code, status] = refusal(error);
    logFailure("cloudflare_ai_failed", error, { model: typeof body.model === "string" ? body.model.slice(0, 80) : "unknown", code });
    return failure(code, "Cloudflare AI could not complete the generation.", status);
  }
}
