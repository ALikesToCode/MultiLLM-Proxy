/**
 * Public /status and /status.json served by the Worker from the D1 snapshot the Container
 * stores, so a visit never wakes a sleeping Container or extends its sleepAfter window.
 * Responses carry no keys, usage, URLs or hostnames and are cached for 30 to 60 seconds:
 * in the edge cache on a custom domain, and per isolate everywhere (the Cache API does
 * nothing on workers.dev). The markup matches templates/public_status.html.
 */
import { readStatusSnapshot } from "./route-health-d1.mjs";

export const STATUS_PATHS = new Set(["/status", "/status.json"]);
export const STATUS_CACHE_CONTROL = "public, max-age=30, s-maxage=60";
const MEMO_MS = 30000;
const STATUSES = new Set(["up", "degraded", "down", "unknown"]);
const LABELS = { up: "Up", degraded: "Degraded", down: "Down", unknown: "Unknown" };
const OVERALL_TEXT = {
  up: "All automatic routes are up",
  degraded: "Some automatic routes are degraded",
  down: "Automatic routes are down",
  unknown: "No recent health data",
};
const HTML_SECURITY_HEADERS = {
  "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
};
const STYLE = `body{margin:0;font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;color:#10202e;background:#f6f8fa}
main{max-width:60rem;margin:0 auto;padding:2rem 1rem}
h1{font-size:1.75rem;margin:0 0 .5rem}
h2{font-size:1.25rem;margin:2rem 0 .75rem}
h3{font-size:1rem;margin:0 0 .5rem;display:flex;gap:.5rem;align-items:center;flex-wrap:wrap}
.overall{font-size:1.125rem;font-weight:600;margin:0}
.meta{color:#4a5a68;margin:.25rem 0 0}
.route{background:#fff;border:1px solid #d5dde5;border-radius:.5rem;padding:1rem;margin:0 0 1rem;overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:.9375rem}
th,td{text-align:left;padding:.375rem .5rem;border-top:1px solid #e3e9ef;white-space:nowrap}
thead th{border-top:0;color:#4a5a68;font-weight:600}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.9em}
.badge{display:inline-block;border-radius:1rem;padding:0 .625rem;font-size:.8125rem;font-weight:600;border:1px solid}
.badge--up{color:#0b5d2a;background:#e3f6ea;border-color:#9fd8b3}
.badge--degraded{color:#7a4a00;background:#fff3d6;border-color:#f0cf7c}
.badge--down{color:#8f1d1d;background:#fde7e7;border-color:#f1a9a9}
.badge--unknown{color:#3d4b57;background:#eef2f5;border-color:#c9d3dc}
.visually-hidden{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
footer{margin-top:2rem;color:#4a5a68;font-size:.875rem}
@media (prefers-color-scheme:dark){body{color:#e4ebf1;background:#0d1720}.route{background:#13212d;border-color:#26394a}th,td{border-color:#26394a}.meta,thead th,footer{color:#a7b6c3}}`;

let memo = null;

export function resetStatusMemo() {
  memo = null;
}

const escapeHtml = value => String(value ?? "").replace(/[&<>"']/g, character =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]);
const status = value => (STATUSES.has(value) ? value : "unknown");
const list = value => (Array.isArray(value) ? value : []);
const isTime = value => typeof value === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(value);
const number = value => (typeof value === "number" && Number.isFinite(value) ? value : null);

export function formatRate(value) {
  const rate = number(value);
  return rate === null ? "–" : `${(rate * 100).toFixed(1)}%`;
}

export function formatLatency(value) {
  const latency = number(value);
  if (latency === null) return "–";
  return latency < 1000 ? `${Math.round(latency)} ms` : `${(latency / 1000).toFixed(1)} s`;
}

export function formatTime(value) {
  return isTime(value) ? `${value.slice(0, 10)} ${value.slice(11, 16)} UTC` : "–";
}

const badge = value => `<span class="badge badge--${status(value)}">${LABELS[status(value)]}</span>`;

/** The public page for a status document; every value is escaped or drawn from a fixed set. */
export function renderStatusHtml(snapshot, source) {
  const overall = status(snapshot.overall);
  const generated = isTime(snapshot.generated_at) ? snapshot.generated_at : "";
  const sourceText = source === "live" ? "Live figures from the gateway."
    : "Last figures the gateway stored; they refresh while it is awake.";
  const routes = list(snapshot.routes).map((route, index) => {
    const rows = list(route?.candidates).map(candidate => `<tr><td>${escapeHtml(number(candidate?.priority) ?? "")}</td>`
      + `<td><code>${escapeHtml(candidate?.model)}</code></td><td>${badge(candidate?.status)}</td>`
      + `<td>${formatRate(candidate?.success_rate)}</td><td>${formatLatency(candidate?.p50_latency_ms)}</td>`
      + `<td>${formatTime(candidate?.last_check_at)}</td></tr>`).join("\n");
    return `<article class="route" aria-labelledby="route-${index + 1}">
<h3 id="route-${index + 1}"><code>${escapeHtml(route?.id)}</code> ${badge(route?.status)}</h3>
<table>
<caption class="visually-hidden">Candidates for ${escapeHtml(route?.id)} in configured order</caption>
<thead><tr><th scope="col">Priority</th><th scope="col">Model</th><th scope="col">Status</th><th scope="col">Success rate</th><th scope="col">Median response</th><th scope="col">Last check</th></tr></thead>
<tbody>
${rows}
</tbody>
</table>
</article>`;
  }).join("\n");
  const providers = list(snapshot.providers).map(provider => `<tr><td>${escapeHtml(provider?.id)}</td>`
    + `<td>${badge(provider?.status)}</td><td>${formatRate(provider?.success_rate)}</td>`
    + `<td>${formatLatency(provider?.p50_latency_ms)}</td><td>${formatTime(provider?.last_check_at)}</td></tr>`).join("\n");
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>MultiLLM Proxy status</title>
<style>
${STYLE}
</style>
</head>
<body>
<main>
<header>
<h1>MultiLLM Proxy status</h1>
<p class="overall">${badge(overall)} ${OVERALL_TEXT[overall]}</p>
<p class="meta">Updated <time datetime="${escapeHtml(generated)}">${formatTime(generated)}</time>. ${sourceText} Success rate and median time to response cover the last hour of routed requests.</p>
</header>
<section aria-labelledby="routes-title">
<h2 id="routes-title">Automatic routes</h2>
${routes || "<p>No automatic routes are configured.</p>"}
</section>
<section aria-labelledby="providers-title">
<h2 id="providers-title">Providers</h2>
<div class="route">
<table>
<caption class="visually-hidden">Provider health</caption>
<thead><tr><th scope="col">Provider</th><th scope="col">Status</th><th scope="col">Success rate</th><th scope="col">Median response</th><th scope="col">Last check</th></tr></thead>
<tbody>
${providers}
</tbody>
</table>
</div>
</section>
<footer><p>Machine-readable: <a href="/status.json">/status.json</a>. Checks list each provider's models and never generate anything.</p></footer>
</main>
</body>
</html>
`;
}

function emptySnapshot(now) {
  return { version: 1, generated_at: new Date(now).toISOString(), window_seconds: 3600, overall: "unknown", routes: [], providers: [] };
}

/**
 * The status document without waking the Container: the D1 snapshot first, then a running
 * Container (reached without renewing its sleep timer), then an empty "unknown" document.
 */
async function loadSnapshot(env, container, now) {
  if (memo && now - memo.at < MEMO_MS) return memo.value;
  let value = null;
  const stored = await readStatusSnapshot(env.INTELLIGENCE_DB);
  if (stored) value = { snapshot: stored, source: "snapshot" };
  if (!value && container?.fetchIfRunning) {
    try {
      const live = await container.fetchIfRunning("/status.json", { headers: { Accept: "application/json" } });
      const parsed = live?.status === 200 ? JSON.parse(live.body) : null;
      if (parsed?.version === 1) value = { snapshot: parsed, source: "live" };
    } catch {
      value = null;
    }
  }
  value ??= { snapshot: emptySnapshot(now), source: "snapshot" };
  memo = { at: now, value };
  return value;
}

export async function handleStatusRequest(request, env, ctx, { container, now = Date.now() } = {}) {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return new Response("Method not allowed", { status: 405, headers: { Allow: "GET, HEAD" } });
  }
  const url = new URL(request.url);
  const cacheKey = new Request(`${url.origin}${url.pathname}`, { method: "GET" });
  const cache = globalThis.caches?.default;
  const cached = cache ? await cache.match(cacheKey).catch(() => undefined) : undefined;
  if (cached) return cached;

  const { snapshot, source } = await loadSnapshot(env, container, now);
  const headers = new Headers({ "Cache-Control": STATUS_CACHE_CONTROL });
  let body;
  if (url.pathname === "/status.json") {
    headers.set("Content-Type", "application/json");
    headers.set("Access-Control-Allow-Origin", "*");
    body = JSON.stringify({ ...snapshot, source });
  } else {
    headers.set("Content-Type", "text/html; charset=utf-8");
    for (const [name, value] of Object.entries(HTML_SECURITY_HEADERS)) headers.set(name, value);
    body = renderStatusHtml(snapshot, source);
  }
  const response = new Response(request.method === "HEAD" ? null : body, { status: 200, headers });
  if (cache && request.method === "GET") {
    const stored = cache.put(cacheKey, response.clone()).catch(() => undefined);
    if (ctx?.waitUntil) ctx.waitUntil(stored);
    else await stored;
  }
  return response;
}
