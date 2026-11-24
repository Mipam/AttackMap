/* Status bar, view bar and main-pane painting (AR065).
 * These functions own the DOM chrome around the per-view HTML: the run
 * status/progress line, the view title + export buttons, and the decision of
 * when re-rendering the main pane is safe (focus retention in Settings and
 * the suppression reason box).
 */

import { renderMain } from "./views/index.js";
import { escapeHtml } from "./util.js";

const VIEW_TITLES = {
  overview: "Overview",
  activity: "Activity",
  findings: "Findings",
  exploitability: "Exploitability",
  paths: "Attack paths",
  surface: "Attack surface",
  diagrams: "Diagrams",
  review: "Review",
  "ai-review": "AI Review",
  diff: "Diff",
  fleet: "Fleet",
  deps: "Dependencies",
  secrets: "Secrets",
  ci: "CI workflows",
  flows: "Data flows",
  analyzers: "Analyzers",
  recents: "Recent scans",
};

/**
 * @param {any} ui shared client state (state.js)
 * @param {import("./api-types.js").StateResponse} state
 */
export function paintStatus(ui, state) {
  const status = document.getElementById("status-text");
  const delta = document.getElementById("delta");
  const watching = document.getElementById("watching");
  const run = document.getElementById("run");
  const dot = document.getElementById("dot");
  const barWrap = document.getElementById("bar-wrap");
  const bar = document.getElementById("bar");
  const eta = document.getElementById("eta");
  const reveal = document.getElementById("reveal");
  const p = state.progress || {};
  dot.className = "dot " + (state.status || "");
  if (state.status === "running") {
    status.textContent = `Scanning… ${p.current || p.label || ""}`;
    run.textContent = "Cancel";
    const total = Number(p.total) || 0;
    const done = Number(p.done) || 0;
    if (p.event === "begin") ui.progressStarted = Date.now();
    barWrap.hidden = !total;
    const pct = total ? Math.min(100, Math.round((done / total) * 100)) : 0;
    bar.style.width = pct + "%";
    if (total && done > 0 && ui.progressStarted) {
      const elapsed = (Date.now() - ui.progressStarted) / 1000;
      const remain = Math.max(0, Math.round((elapsed / done) * (total - done)));
      eta.textContent = remain ? `ETA ${remain}s` : "";
    } else eta.textContent = "";
  } else if (state.status === "failed") {
    status.textContent = "Failed";
    run.textContent = "Run scan";
    barWrap.hidden = true;
    eta.textContent = "";
  } else if (state.status === "idle") {
    status.textContent = "Pick a repository and run a scan.";
    run.textContent = "Run scan";
    barWrap.hidden = true;
  } else {
    status.textContent = `Done — ${state.findingCount || 0} findings`;
    run.textContent = "Run scan";
    barWrap.hidden = true;
    eta.textContent = "";
  }
  if (state.newCount || state.resolvedCount) {
    delta.innerHTML = `<span class="new">+${state.newCount} new</span> · <span class="resolved">${state.resolvedCount} resolved</span>`;
  } else delta.textContent = "";
  watching.hidden = !state.watch;
  watching.textContent = state.watchNotice ? `Watching — ${state.watchNotice}` : "Watching";
  reveal.hidden = !state.output;
  const label = document.getElementById("repo-label");
  if (document.activeElement !== label) {
    if (state.repos && state.repos.length) label.value = state.repos.join(" · ");
    else if (state.repo) label.value = state.repo;
  }
  const analyzers = document.getElementById("analyzers");
  if (state.availableModules && analyzers.options.length <= 1) {
    state.availableModules.forEach((m) => analyzers.add(new Option(m.display_name || m.name, m.name)));
  }
}

/** Recommended-analyzers banner; "" when everything recommended is installed. */
export function showMissing(state) {
  if (!state.missingAnalyzers || !state.missingAnalyzers.length) return "";
  const names = state.missingAnalyzers.map((m) => m.plugin).join(", ");
  return `<div class="banner">Recommended analyzers are not installed: ${escapeHtml(names)}. Install them, then re-run — a heuristic-only pass may miss language-specific sinks.</div>`;
}

/**
 * Export is allowed only on a settled run, outside Settings, with a cached
 * report for the current view.
 */
export function canExport(ui, state) {
  return ["idle", "done"].includes(state.status) && ui.currentView !== "settings" && !!ui.reportCache;
}

export function paintViewbar(ui, state) {
  const bar = document.getElementById("viewbar");
  const title = document.getElementById("view-title");
  const mdBtn = document.getElementById("export-md");
  const pdfBtn = document.getElementById("export-pdf");
  title.textContent = VIEW_TITLES[ui.currentView] || "";
  const ok = canExport(ui, state);
  mdBtn.disabled = !ok;
  pdfBtn.disabled = !ok;
  bar.hidden = false;
}

let renderObserver = null;

/**
 * Test seam (AR065 node freshness harness): observe every main-pane render
 * with the (state, report, view) triple. Pass null to detach. The observer
 * must not throw and must not mutate the payload.
 */
export function setRenderObserver(fn) {
  renderObserver = fn;
}

/**
 * Paint the main pane unless the user is mid-edit in a field that re-rendering
 * would clobber (Settings key inputs, the suppression reason for the already
 * rendered report/view).
 */
export function paintMain(ui, state, report) {
  paintViewbar(ui, state);
  const focused = document.activeElement && document.activeElement.id;
  if (ui.currentView === "settings" && ["anth-key", "oai-key"].includes(focused)) return;
  if (focused === "suppress-reason" && report && ui.renderedReport === report && ui.renderedView === ui.currentView) return;
  if (renderObserver) renderObserver({ state, report, view: ui.currentView });
  document.getElementById("view").innerHTML = showMissing(state) + renderMain(ui, state, report);
  ui.renderedReport = report;
  ui.renderedView = ui.currentView;
}
