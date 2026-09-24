// Page served at / when the Flask container cannot answer. It must be self-contained:
// the container also serves /static, so no shared stylesheet is reachable here.

const ROOT_FALLBACK_HTML = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="light">
    <meta name="theme-color" content="#07131f">
    <title>MultiLLM Proxy · Starting up</title>
    <style>
      * { box-sizing: border-box; }
      body { display: grid; min-height: 100vh; margin: 0; padding: 1.25rem; place-items: center;
        background: #f3f7f9; color: #07131f; font: 1rem/1.5 Inter, ui-sans-serif, system-ui, sans-serif; }
      main { display: grid; width: min(100%, 38rem); padding: clamp(1.5rem, 5vw, 3rem); gap: 1rem;
        border: 1px solid #ccd7df; border-radius: 1rem; background: #fff; box-shadow: 0 12px 32px rgb(7 19 31 / 9%); }
      .eyebrow { margin: 0; color: #0a6b78; font: 700 0.75rem/1.4 ui-monospace, Menlo, monospace;
        letter-spacing: 0.1em; text-transform: uppercase; }
      h1 { margin: 0; font-size: clamp(1.9rem, 6vw, 2.5rem); letter-spacing: -0.04em; line-height: 1.08; }
      p { margin: 0; color: #476277; line-height: 1.65; }
      code { padding: 0.1rem 0.35rem; border-radius: 0.35rem; background: #f3f7f9; color: #173047; }
      a { display: inline-flex; justify-self: start; min-height: 2.75rem; padding: 0 1rem; align-items: center;
        border-radius: 0.45rem; background: #07131f; color: #fff; font-weight: 650; font-size: 0.875rem; text-decoration: none; }
      a:focus-visible { outline: 3px solid #0891a4; outline-offset: 2px; }
    </style>
  </head>
  <body>
    <main>
      <p class="eyebrow">MultiLLM Proxy</p>
      <h1>The console is starting or unavailable.</h1>
      <p>The dashboard container did not answer this request. If it is starting, try again in a few seconds; retrying this page is safe.</p>
      <p>Use <code>/health</code> for Worker liveness and <code>/ready</code> for application readiness.</p>
      <a href="/">Try again</a>
    </main>
  </body>
</html>`;

export function buildRootFallbackResponse() {
  return new Response(ROOT_FALLBACK_HTML, {
    status: 503,
    headers: {
      "Content-Type": "text/html; charset=UTF-8",
      "Retry-After": "5",
    },
  });
}
