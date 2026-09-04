import assert from "node:assert/strict";
import test from "node:test";

import {
  resolveSseHeartbeatMs,
  withSseHeartbeat,
} from "../worker/sse-heartbeat.mjs";
import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";

const encoder = new TextEncoder();

function delayedEventStream(delayMs = 20) {
  let cancelledWith;
  let timer;
  const body = new ReadableStream({
    start(controller) {
      controller.enqueue(encoder.encode('data: {"chunk":1}\n\n'));
      timer = setTimeout(() => {
        controller.enqueue(encoder.encode('data: {"chunk":2}\n\n'));
        controller.close();
      }, delayMs);
    },
    cancel(reason) {
      clearTimeout(timer);
      cancelledWith = reason;
    },
  });
  return {
    body,
    cancelledWith() {
      return cancelledWith;
    },
  };
}

function gatedEventStream() {
  let controller;
  let cancelledWith;
  const body = new ReadableStream({
    start(streamController) {
      controller = streamController;
      controller.enqueue(encoder.encode('data: {"chunk":1}\n\n'));
    },
    cancel(reason) {
      cancelledWith = reason;
    },
  });
  return {
    body,
    release() {
      controller.enqueue(encoder.encode('data: {"chunk":2}\n\n'));
      controller.close();
    },
    cancelledWith() {
      return cancelledWith;
    },
  };
}

test("SSE heartbeat preserves chunks and fills an idle interval", async () => {
  const upstream = gatedEventStream();
  const response = withSseHeartbeat(
    new Response(upstream.body, {
      headers: {
        "Content-Type": "text/event-stream; charset=utf-8",
        "Content-Length": "42",
      },
    }),
    { heartbeatMs: 5 },
  );

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  const first = decoder.decode((await reader.read()).value);
  const heartbeat = decoder.decode((await reader.read()).value);
  upstream.release();
  const second = decoder.decode((await reader.read()).value);
  assert.equal((await reader.read()).done, true);
  const body = first + heartbeat + second;
  assert.match(body, /data: \{"chunk":1\}\n\n/);
  assert.match(body, /: multillm-keepalive\n\n/);
  assert.match(body, /data: \{"chunk":2\}\n\n/);
  assert.ok(
    body.indexOf('data: {"chunk":1}') <
      body.indexOf(": multillm-keepalive"),
  );
  assert.ok(
    body.indexOf(": multillm-keepalive") <
      body.indexOf('data: {"chunk":2}'),
  );
  assert.equal(response.headers.get("Content-Length"), null);
  assert.equal(response.headers.get("Cache-Control"), "no-cache, no-transform");
  assert.equal(response.headers.get("X-Accel-Buffering"), "no");
});

test("SSE heartbeat propagates downstream cancellation", async () => {
  const upstream = delayedEventStream(1_000);
  const response = withSseHeartbeat(
    new Response(upstream.body, {
      headers: { "Content-Type": "text/event-stream" },
    }),
    { heartbeatMs: 10 },
  );
  const reader = response.body.getReader();

  await reader.read();
  await reader.cancel("browser disconnected");

  assert.equal(upstream.cancelledWith(), "browser disconnected");
});

test("SSE heartbeat leaves non-event responses untouched", () => {
  const response = new Response('{"ok":true}', {
    headers: { "Content-Type": "application/json" },
  });

  assert.equal(withSseHeartbeat(response), response);
});

test("SSE heartbeat configuration is bounded and can be disabled", () => {
  assert.equal(resolveSseHeartbeatMs(undefined), 10_000);
  assert.equal(resolveSseHeartbeatMs("invalid"), 10_000);
  assert.equal(resolveSseHeartbeatMs("0"), 0);
  assert.equal(resolveSseHeartbeatMs("1"), 1_000);
  assert.equal(resolveSseHeartbeatMs("120000"), 60_000);
});

test("generic Container route applies heartbeat and CORS to SSE", async () => {
  const worker = (await loadWorkerModule()).default;
  const origin = "https://janitorai.com";
  const upstream = delayedEventStream();
  const env = {
    SSE_STREAM_HEARTBEAT_MS: "1",
    MULTILLM_PROXY_CONTAINER: {
      getByName(name) {
        assert.equal(name, "primary");
        return {
          async fetch() {
            return new Response(upstream.body, {
              headers: { "Content-Type": "text/event-stream" },
            });
          },
        };
      },
    },
  };

  const response = await worker.fetch(
    new Request("https://proxy.example/v1/chat/completions", {
      method: "POST",
      headers: {
        Origin: origin,
        "Content-Type": "application/json",
      },
      body: '{"stream":true}',
    }),
    env,
  );

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), origin);
  assert.equal(response.headers.get("X-Accel-Buffering"), "no");
  assert.match(await response.text(), /data: \{"chunk":2\}\n\n/);
});
