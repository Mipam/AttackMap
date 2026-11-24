/* Activity view (AR083/AC-404): the run's event stream and stage timeline.
 *
 * The UI server exposes no events.jsonl endpoint (server.py is outside this
 * change's scope), so this view reconstructs the stream client-side: every
 * state poll carries the scan child's latest NDJSON progress event
 * (begin/advance/stage/done), and observing each distinct event builds the
 * timeline. Once the run finishes, the published report supplies the
 * recorded skips with reasons (time-budget breaches surface as
 * time_budget_exceeded analyzer errors) and the run's limitations.
 *
 * AR065 export-signature adaptation: plain script → ES module. escapeHtml is
 * imported from util.js instead of relying on the app.js global; the
 * functions and their behavior are unchanged. The old app.js feature-detect
 * (`typeof renderActivity === "function`) existed only for the node-based
 * ui_freshness harness, which loads modules explicitly now.
 */

import { escapeHtml } from "./util.js";

let activityRunId = null;
let activityEvents = [];   // [{t: Date, event: object}] in observation order
let activityLastKey = "";

export function activityObserve(state) {
  if (!state) return;
  if (state.runId !== activityRunId) {
    // A new run (or a cleared run id) starts a fresh timeline.
    activityRunId = state.runId;
    activityEvents = [];
    activityLastKey = "";
  }
  const progress = state.progress;
  if (!progress) return;
  const key = JSON.stringify(progress);
  if (key === activityLastKey) return;
  activityLastKey = key;
  activityEvents.push({ t: new Date(), event: progress });
  if (activityEvents.length > 500) activityEvents.shift();
}

function _fmtClock(t) {
  try { return t.toLocaleTimeString(); } catch { return ""; }
}

function _fmtElapsed(seconds) {
  const s = Math.max(0, Math.round(Number(seconds) || 0));
  const m = Math.floor(s / 60);
  return m ? `${m}m${String(s % 60).padStart(2, "0")}s` : `${s}s`;
}

function _activityTimeline() {
  const rows = [];
  let lastAdvance = -1;
  for (let i = 0; i < activityEvents.length; i++) {
    const { t, event } = activityEvents[i];
    const kind = event.event || "";
    if (kind === "advance") { lastAdvance = i; continue; }
    if (kind === "begin") {
      rows.push({ t, text: `File scan started (${Number(event.total) || 0} files)` });
      continue;
    }
    if (kind === "stage") {
      rows.push({ t, text: String(event.label || "stage") });
      continue;
    }
    if (kind === "done") {
      const elapsed = event.elapsed_s != null ? ` — ${_fmtElapsed(event.elapsed_s)}` : "";
      const files = Number(event.done) || 0;
      rows.push({ t, text: `Scan stage finished (${files} files${elapsed})` });
    }
  }
  if (lastAdvance >= 0) {
    const { t, event } = activityEvents[lastAdvance];
    const done = Number(event.done) || 0;
    const total = Number(event.total) || 0;
    rows.push({ t, text: `Files scanned: ${done}/${total}` });
  }
  if (!rows.length) return "";
  return `<h3 style="padding:0 16px">Observed activity</h3>` + rows.map((row) =>
    `<div class="list-row"><div class="muted">${escapeHtml(_fmtClock(row.t))}</div>` +
    `<div>${escapeHtml(row.text)}</div></div>`).join("");
}

function _activitySkips(report) {
  if (!report) return { skips: "", errors: "", notes: "" };
  const errors = report.analyzerErrors || [];
  const budgetSkips = errors.filter((e) => String(e.error_type || "").includes("budget"));
  const otherErrors = errors.filter((e) => !String(e.error_type || "").includes("budget"));
  const skipRows = budgetSkips.map((e) =>
    `<div class="list-row"><div><span class="chip">skipped</span> ${escapeHtml(e.message || "")}</div></div>`);
  const errorRows = otherErrors.map((e) =>
    `<div class="list-row"><div>${escapeHtml(e.analyzer || "")}<div class="muted">${escapeHtml(e.message || "")}</div></div></div>`);
  const limits = (report.limitations || []).map((note) =>
    `<div class="list-row"><div class="muted">${escapeHtml(note)}</div></div>`);
  return {
    skips: skipRows.length ? `<h3 style="padding:0 16px">Skips</h3>${skipRows.join("")}` : "",
    errors: errorRows.length ? `<h3 style="padding:0 16px">Analyzer errors</h3>${errorRows.join("")}` : "",
    notes: limits.length ? `<h3 style="padding:0 16px">Limitations</h3>${limits.join("")}` : "",
  };
}

export function renderActivity(state, report) {
  const runId = state.runId || (report && report.generationId) || null;
  if (!runId && !activityEvents.length) {
    return `<div class="empty-state"><h3>No run activity yet</h3>
      <p>Run a scan to watch its live stage timeline here. While a scan runs,
      each progress event the engine emits appears as it happens; when the run
      finishes, its recorded skips (with reasons) and limitations are listed
      from the published generation.</p></div>`;
  }
  const header = runId
    ? `<div class="list-row"><div>Run <code>${escapeHtml(runId)}</code></div>` +
      `<span class="chip">${escapeHtml(state.status || "")}</span></div>`
    : "";
  const scan = (report && report.scan) || {};
  const filesScanned = scan.scanned_files || scan.files_scanned || null;
  const totals = report
    ? `<div class="cards">
        <div class="card"><div class="muted">Findings</div><div class="n">${Number(report.findingCount) || 0}</div></div>
        ${filesScanned != null ? `<div class="card"><div class="muted">Files scanned</div><div class="n">${Number(filesScanned) || 0}</div></div>` : ""}
      </div>`
    : "";
  const skips = _activitySkips(report);
  return header + totals + _activityTimeline()
    + skips.skips + skips.errors + skips.notes
    + (report ? "" : `<div class="empty">Run finished reports are unavailable for this generation.</div>`);
}
