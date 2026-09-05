export const element = (id) => document.getElementById(id);
export function status(message) { element("workbench-status").textContent = message; }

export async function api(path, body, options = {}) {
  const headers = new Headers(options.headers);
  if (body !== undefined) {
    headers.set("Content-Type", "application/json");
    headers.set("X-CSRFToken", document.querySelector('meta[name="csrf-token"]')?.content || "");
  }
  const response = await fetch("/admin/workbench/" + path, { ...options, headers,
    method: body === undefined ? "GET" : "POST", credentials: "same-origin", cache: "no-store",
    ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  if (!response.ok) {
    let message = `Operation failed (HTTP ${response.status}).`;
    try { const data = await response.json(); message = data.message || data.error?.message || message; } catch {}
    throw new Error(message);
  }
  return options.stream ? response : response.json();
}

export function action(id, callback) {
  element(id).addEventListener("click", async () => {
    const button = element(id);
    button.disabled = true;
    try { await callback(); } catch (error) { status(error.message); }
    finally { button.disabled = false; }
  });
}

export function download(name, value) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: "application/json" }));
  const link = document.createElement("a");
  link.href = url; link.download = name; link.hidden = true;
  document.body.append(link); link.click(); link.remove();
  status(`Download requested: ${name}. No credentials are included.`);
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

export function sessionQuery() {
  const id = element("session-id").value.trim();
  if (!/^[A-Za-z0-9_-]{8,128}$/.test(id)) throw new Error("Enter the session ID returned by the proxy.");
  return new URLSearchParams({ session_id: id, scope: element("session-scope").value }).toString();
}
