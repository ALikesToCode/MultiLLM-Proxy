import { action, api, download, element, status } from "./api.mjs";
import { consumeStream } from "./stream.mjs";

function shuffled(values) {
  const result = [...values];
  for (let i = result.length - 1; i > 0; i--) {
    const random = crypto.getRandomValues(new Uint32Array(1))[0] / 2 ** 32;
    const j = Math.floor(random * (i + 1));
    [result[i], result[j]] = [result[j], result[i]];
  }
  return result;
}

export function initLab() {
  let controller = null, running = false, runs = [], report = null;
  element("lab-stop").addEventListener("click", () => controller?.abort());
  const card = (label) => {
    const article = document.createElement("article"); article.className = "wb-answer";
    const title = document.createElement("h3"); title.textContent = label;
    const output = document.createElement("pre"); output.textContent = "Waiting…";
    const note = document.createElement("p");
    const ratingLabel = document.createElement("label"); ratingLabel.textContent = "Quality · continuity, agency, plausibility, instruction following";
    const rating = document.createElement("select");
    rating.add(new Option("Rate before revealing provider", ""));
    for (let n = 1; n <= 5; n++) rating.add(new Option(`${n} / 5`, String(n)));
    ratingLabel.append(rating); article.append(title, output, note, ratingLabel); element("lab-results").append(article);
    return { title, output, note, rating };
  };
  action("lab-start", async () => {
    if (running) return;
    const candidates = [...element("lab-candidates").selectedOptions].map((option) => JSON.parse(option.value));
    if (candidates.length < 2 || candidates.length > 4) throw new Error("Select 2–4 routes.");
    if (!element("lab-confirm").checked) throw new Error("Confirm the potentially billed comparison first.");
    const repetitions = Number(element("lab-repeats").value);
    if (![1, 2, 3].includes(repetitions)) throw new Error("Choose 1–3 repeats.");
    const scene = element("lab-case").value, effort = element("lab-effort").value;
    controller = new AbortController(); running = true; runs = []; report = null;
    element("lab-results").replaceChildren(); element("lab-stop").disabled = false;
    element("lab-reveal").disabled = true; element("lab-export").disabled = true;
    const trial = shuffled(candidates.flatMap((candidate) => Array.from({ length: repetitions }, () => candidate)));
    try {
      for (const [index, candidate] of trial.entries()) {
        if (controller.signal.aborted) break;
        const view = card(`Answer ${String.fromCharCode(65 + index)}`);
        element("lab-status").textContent = `Running ${index + 1} of ${trial.length}. Provider identity stays hidden until rating.`;
        const startedAt = performance.now();
        let result;
        try {
          const response = await api("lab/run", { case: scene, ...candidate, effort, confirm_billable: true }, { signal: controller.signal, stream: true });
          const sessionId = response.headers.get("X-Roleplay-Session-ID");
          result = await consumeStream(response, { signal: controller.signal, startedAt, onText: (text) => { view.output.textContent = text; } });
          if (sessionId && result.status !== "completed") {
            const inspect = document.createElement("button"); inspect.type = "button"; inspect.className = "button button--quiet";
            inspect.textContent = "Inspect this interrupted session";
            inspect.addEventListener("click", () => {
              element("session-id").value = sessionId; element("session-scope").value = "admin";
              element("session-id").dispatchEvent(new Event("change")); element("session-panel").scrollIntoView({ behavior: "smooth" });
            });
            view.note.after(inspect);
          }
        } catch (error) {
          result = { status: controller.signal.aborted ? "cancelled" : "failed", message: error.message,
            ttft_ms: null, duration_ms: performance.now() - startedAt, output_tokens: null, tps: null };
        }
        view.note.textContent = result.message;
        if (!result.text) view.output.textContent = "No visible answer received.";
        runs.push({ candidate, scene, effort, result, view });
      }
    } finally {
      running = false; element("lab-stop").disabled = true; element("lab-confirm").checked = false;
      element("lab-reveal").disabled = runs.length < 2;
      element("lab-status").textContent = `${controller.signal.aborted ? "Comparison stopped" : "Comparison finished"}. Rate the received answers before revealing routes.`;
    }
  });
  action("lab-reveal", async () => {
    if (report) { status("This comparison is already saved. Export it or start a new comparison."); return; }
    if (running || runs.length < 2 || runs.some((run) => !run.view.rating.value)) throw new Error("Rate every received answer first.");
    const measurements = runs.map(({ candidate, scene, effort, result, view }) => ({
      provider: candidate.provider, model: candidate.model, case: scene, effort, status: result.status,
      rating: Number(view.rating.value), ttft_ms: result.ttft_ms, duration_ms: result.duration_ms,
      output_tokens: result.output_tokens, tps: result.tps,
    }));
    const saved = await api("lab/reports", { measurements });
    report = { id: saved.id, measurement_source: "Browser-observed latency; provider-reported output tokens (including reasoning). No invented TPS when usage is absent.", measurements };
    for (const { candidate, result, view } of runs) {
      view.rating.disabled = true;
      view.title.textContent += ` · ${candidate.provider} / ${candidate.model}`;
      view.note.textContent = `${result.status} · first visible ${result.ttft_ms === null ? "unknown" : (result.ttft_ms / 1000).toFixed(2) + "s"} · total ${(result.duration_ms / 1000).toFixed(2)}s · output TPS ${result.tps === null ? "unknown" : result.tps.toFixed(1)}`;
    }
    element("lab-export").disabled = false; status("Ratings and content-free measurements saved.");
  });
  action("lab-export", () => { if (report) download("comparison-report.json", report); });
  action("lab-history", async () => { element("lab-history-result").textContent = JSON.stringify(await api("lab/reports"), null, 2); });
}
