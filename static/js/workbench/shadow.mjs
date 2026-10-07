import { action, api, download, element } from "./api.mjs";
const tasks = ["coding", "extraction", "writing", "reasoning", "chat"];
const note = message => { element("shadow-status").textContent = message; };

export function renderLeague(container, rows) {
  container.replaceChildren();
  if (!rows.length) { container.textContent = "No judged comparisons yet."; return; }
  const table = document.createElement("table");
  table.className = "data-table";
  const caption = table.createCaption(); caption.textContent = "Model league by task";
  const columns = [["task_type", "Task"], ["model", "Model"], ["rating", "Elo"], ["sample_count", "Comparisons"],
    ["wins", "Wins"], ["losses", "Losses"], ["ties", "Ties"], ["median_latency_ms", "Median ms"], ["median_cost_usd", "Median USD"]];
  const header = table.createTHead().insertRow();
  for (const [, label] of columns) { const cell = document.createElement("th"); cell.scope = "col"; cell.textContent = label; header.append(cell); }
  const body = table.createTBody();
  for (const row of rows) {
    const tr = body.insertRow();
    for (const [name] of columns) { const cell = tr.insertCell(); cell.textContent = row[name] ?? "Unknown"; }
  }
  container.append(table);
}

export function renderCounts(container, counts, columns) {
  container.replaceChildren();
  const list = document.createElement("dl");
  for (const [name, label] of columns) {
    const term = document.createElement("dt"); term.textContent = label;
    const value = document.createElement("dd");
    value.textContent = Number.isSafeInteger(counts?.[name]) && counts[name] >= 0 ? String(counts[name]) : "0";
    list.append(term, value);
  }
  container.append(list);
}

const coverageColumns = [["eligible", "Eligible"], ["sampled", "Sampled"], ["skipped_rate", "Skipped: rate"],
  ["skipped_secret", "Skipped: secret"], ["skipped_oversize", "Skipped: size"], ["skipped_queue_full", "Skipped: queue full"],
  ["skipped_error", "Skipped: error"]];
const resultColumns = [["judged", "Judged"], ["failed", "Failed"], ["same_model", "Same model"], ["candidate_truncated", "Candidate truncated"]];

export function initShadow() {
  let config, rows = [], proposal, sampling_counts, result_counts;
  const invalidate = () => { proposal = undefined; element("shadow-apply").disabled = true; element("shadow-confirm-apply").checked = false; };
  action("shadow-load", async () => {
    [config, { league: rows, sampling_counts, result_counts }] = await Promise.all([api("shadow/config"), api("shadow/league")]);
    renderLeague(element("shadow-league"), rows);
    renderCounts(element("shadow-coverage"), sampling_counts, coverageColumns);
    renderCounts(element("shadow-results"), result_counts, resultColumns);
    element("shadow-export").disabled = false;
    element("shadow-config-form").hidden = false;
    element("shadow-enabled").checked = config.enabled;
    element("shadow-judge").value = config.judge_model;
    element("shadow-per-run").value = config.max_replays_per_run;
    element("shadow-daily").value = config.daily_cap;
    for (const task of tasks) element("shadow-" + task).value = config.candidate_models[task].join("\n");
    invalidate(); note("League and evaluation settings loaded.");
  });
  element("shadow-config-form").addEventListener("submit", async event => {
    event.preventDefault();
    const button = event.submitter; button.disabled = true;
    try {
      const next = { enabled: element("shadow-enabled").checked, judge_model: element("shadow-judge").value.trim(),
        max_replays_per_run: Number(element("shadow-per-run").value), daily_cap: Number(element("shadow-daily").value),
        candidate_models: Object.fromEntries(tasks.map(task => [task, element("shadow-" + task).value.split(/[\s,]+/).filter(Boolean)])) };
      config = await api("shadow/config", { config: next, expected: config });
      invalidate(); note("Evaluation settings saved.");
    } catch (error) { note(error.message); } finally { button.disabled = false; }
  });
  action("shadow-export", async () => download("model-league.json", { league: rows, sampling_counts, result_counts }));
  action("shadow-propose", async () => {
    invalidate(); proposal = await api("shadow/propose", {});
    element("shadow-proposal").textContent = JSON.stringify({ policy_diff: proposal.policy_diff,
      suggested_auto_route_orders: proposal.suggested_auto_route_orders }, null, 2);
    element("shadow-apply").disabled = !proposal.policy_diff.length;
    note("Review the diff and explicitly confirm before applying policy scores.");
  });
  element("shadow-apply").addEventListener("click", async () => {
    if (!proposal || !element("shadow-confirm-apply").checked) { note("Confirm the displayed policy proposal first."); return; }
    element("shadow-apply").disabled = true;
    try {
      await api("shadow/apply", { confirm: true, revision: proposal.revision });
      invalidate(); note("Policy scores applied with a guarded backup. Auto-route orders were not changed.");
    } catch (error) { element("shadow-apply").disabled = false; note(error.message); }
  });
  action("shadow-samples", async () => {
    const { samples } = await api("shadow/samples");
    const select = element("shadow-sample-id"); select.replaceChildren(new Option("Select a sample", ""));
    for (const sample of samples) select.append(new Option(`${sample.task_type} · ${sample.production_model} · ${new Date(sample.created_at * 1000).toISOString()}`, sample.id));
    element("shadow-sample-detail").textContent = "Text loads only on demand.";
  });
  action("shadow-sample-text", async () => {
    const id = element("shadow-sample-id").value;
    if (!/^[0-9a-f]{32}$/.test(id)) throw new Error("Select a retained sample first.");
    element("shadow-sample-detail").textContent = JSON.stringify(await api("shadow/samples/" + id), null, 2);
  });
  action("shadow-purge", async () => {
    if (!element("shadow-confirm-purge").checked) throw new Error("Confirm deletion of evaluation data first.");
    await api("shadow/purge", { confirm: true }); rows = []; result_counts = Object.fromEntries(resultColumns.map(([name]) => [name, 0])); invalidate();
    renderCounts(element("shadow-results"), result_counts, resultColumns);
    renderLeague(element("shadow-league"), rows);
    element("shadow-sample-detail").textContent = "Retained samples purged.";
    element("shadow-sample-id").replaceChildren(new Option("No samples", ""));
    element("shadow-confirm-purge").checked = false; note("Evaluation samples and results purged.");
  });
}
