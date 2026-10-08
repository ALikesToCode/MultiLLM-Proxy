/** Content-free Prometheus 0.0.4 gauges with bounded series and UTF-8 output. */
export const PROMETHEUS_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8";
const MAX_SERIES = 512;
const MAX_BYTES = 256 * 1024;
const MAX_NAME = 256;
const STATES = ["up", "degraded", "down", "unknown"];
const encoder = new TextEncoder();
const TRUNCATION_HELP = "# HELP multillm_prometheus_truncated Whether exposition was truncated.\n"
  + "# TYPE multillm_prometheus_truncated gauge\n";
const truncation = value => `${TRUNCATION_HELP}multillm_prometheus_truncated ${value}\n`;
const reservedBytes = encoder.encode(truncation(1)).byteLength;

export const prometheusEnabled = value => String(value ?? "").trim().toLowerCase() === "true";
export const escapeLabel = value => String(value).replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");

class Exposition {
  constructor() {
    this.parts = [];
    this.families = new Set();
    this.series = 0;
    this.bytes = 0;
    this.truncated = false;
  }

  add(name, help, samples) {
    if (samples.some(sample => !Number.isFinite(sample.value))) return false;
    const declaration = this.families.has(name) ? "" : `# HELP ${name} ${help}\n# TYPE ${name} gauge\n`;
    const body = declaration + samples.map(({ labels = {}, value }) => {
      const entries = Object.entries(labels).map(([key, label]) => `${key}="${escapeLabel(label)}"`);
      return `${name}${entries.length ? `{${entries.join(",")}}` : ""} ${value}\n`;
    }).join("");
    const bytes = encoder.encode(body).byteLength;
    if (this.series + samples.length > MAX_SERIES - 1 || this.bytes + bytes > MAX_BYTES - reservedBytes) {
      this.truncated = true;
      return false;
    }
    this.parts.push(body);
    this.families.add(name);
    this.series += samples.length;
    this.bytes += bytes;
    return true;
  }

  finish() {
    return this.parts.join("") + truncation(this.truncated ? 1 : 0);
  }
}

function addState(output, scope, name, state) {
  const normalized = STATES.includes(state) ? state : "unknown";
  return output.add("multillm_status_state", "Public route-health state; down does not imply an open circuit.",
    STATES.map(value => ({ labels: { scope, name, state: value }, value: Number(value === normalized) })));
}

function snapshotTime(timestamp) {
  if (typeof timestamp !== "string") return NaN;
  const match = /^(\d{4})-(\d{2})-(\d{2})T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.exec(timestamp);
  if (!match) return NaN;
  const [year, month, day] = match.slice(1).map(Number);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (month < 1 || month > 12 || day < 1 || day > days[month - 1]) return NaN;
  return Date.parse(timestamp);
}

/** Only fixed public status fields are selected; candidate models and other fields stay private. */
export function renderStatusMetrics({ snapshot, available }, now = Date.now()) {
  const output = new Exposition();
  output.add("multillm_status_snapshot_available", "Whether retained or live public status data is available.",
    [{ value: Number(available === true) }]);
  const generated = snapshotTime(snapshot?.generated_at);
  if (available === true && Number.isFinite(generated) && Number.isFinite(now)) {
    output.add("multillm_status_snapshot_age_seconds", "Age of retained or live public status data in seconds.",
      [{ value: Math.max(0, (now - generated) / 1000) }]);
  }
  addState(output, "overall", "overall", snapshot?.overall);
  for (const [scope, items] of [["route", snapshot?.routes], ["provider", snapshot?.providers]]) {
    const seen = new Set();
    if (!Array.isArray(items)) continue;
    // Bound traversal too, including malformed or duplicate snapshot entries.
    for (let index = 0; index < Math.min(items.length, MAX_SERIES); index += 1) {
      const item = items[index];
      if (typeof item?.id !== "string" || !item.id) continue;
      const name = item.id.slice(0, MAX_NAME);
      if (name.length !== item.id.length) output.truncated = true;
      if (seen.has(name)) continue;
      seen.add(name);
      if (!addState(output, scope, name, item.status)) break;
    }
    if (items.length > MAX_SERIES) output.truncated = true;
  }
  return output.finish();
}
