export async function api(path, { method = "GET", body, signal } = {}) {
  const headers = new Headers({ Accept: "application/json" });
  if (method !== "GET") {
    headers.set("Content-Type", "application/json");
    headers.set("X-CSRFToken", document.querySelector('meta[name="csrf-token"]')?.content || "");
  }
  const response = await fetch(`/admin/knowledge/${path}`, {
    method, headers, signal, credentials: "same-origin", cache: "no-store",
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  let payload;
  try { payload = await response.json(); }
  catch { throw new Error(`The service returned an unreadable response (HTTP ${response.status}).`); }
  if (!response.ok) throw new Error(payload.error?.message || payload.message || `Operation failed (HTTP ${response.status}).`);
  return payload;
}

export function queryPayload(values) {
  const result = { query: String(values.get("query") || "").trim(), mode: values.get("mode"),
    token_budget: Number(values.get("token_budget")), freshness: values.get("freshness") };
  for (const name of ["product", "version", "repository"]) {
    const value = String(values.get(name) || "").trim();
    if (value) result[name] = value;
  }
  return result;
}

export function sourcePayload(values) {
  const result = { url: String(values.get("url") || "").trim(), product: String(values.get("product") || "").trim(),
    provider: values.get("provider"), refresh_hours: Number(values.get("refresh_hours")), pinned: values.get("pinned") === "on" };
  const version = String(values.get("version") || "").trim();
  if (version) result.version = version;
  return result;
}
