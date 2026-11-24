/* View router (AR065): maps the selected nav view to its renderer.
 * Dispatch order matters and is preserved from the monolithic app.js:
 * settings first, then the live Activity view, then the running/failed
 * overlays, then recents, then the report-backed views.
 */

import { renderActivity } from "../activity.js";
import { renderSettings } from "./settings.js";
import { renderRecents } from "./recents.js";
import { renderOverview } from "./overview.js";
import { renderFindings } from "./findings.js";
import { renderExploitability } from "./exploitability.js";
import { renderPaths } from "./paths.js";
import { renderSurface } from "./surface.js";
import { renderDiagrams } from "./diagrams.js";
import { renderReview, renderAiReview, renderDiff } from "./review.js";
import { renderFleet } from "./fleet.js";
import { renderDependencies } from "./deps.js";
import { renderInventory, renderAnalyzers } from "./inventory.js";
import { escapeHtml } from "../util.js";

/**
 * @param {any} ui shared client state (state.js)
 * @param {import("../api-types.js").StateResponse} state server state snapshot
 * @param {import("../api-types.js").ReportResponse|null} report
 * @returns {string}
 */
export function renderMain(ui, state, report) {
  if (ui.currentView === "settings") return renderSettings(state);
  // The Activity view stays live during a run — it renders before the
  // running/failed early returns below (AR083).
  if (ui.currentView === "activity") return renderActivity(state, report);
  if (state.status === "running") {
    const p = state.progress || {};
    return `<div class="running">Scanning… ${escapeHtml(p.label || p.event || "")} ${escapeHtml(p.current || "")}</div>`;
  }
  if (state.status === "failed") {
    return `<div class="failed">${escapeHtml(state.error || "Scan failed.")}${state.stderrTail && state.stderrTail !== state.error ? "\n\n" + escapeHtml(state.stderrTail) : ""}</div>`;
  }
  if (ui.currentView === "recents") return renderRecents(state);
  if (!report) return `<div class="empty">${state.hasReport ? "Loading current report…" : "Pick a repository and run a scan."}</div>`;
  if (ui.currentView === "overview") return renderOverview(report);
  if (ui.currentView === "findings") return renderFindings(report, ui.selectedFinding);
  if (ui.currentView === "exploitability") return renderExploitability(report.exploitability, report, ui.openRow);
  if (ui.currentView === "paths") return renderPaths(report.attackPaths || []);
  if (ui.currentView === "surface") return renderSurface(report.attackSurfaces || []);
  if (ui.currentView === "diagrams") return renderDiagrams(report);
  if (ui.currentView === "review") return renderReview(report);
  if (ui.currentView === "ai-review") return renderAiReview(report);
  if (ui.currentView === "diff") return renderDiff(report);
  if (ui.currentView === "fleet") return renderFleet(report.fleet);
  if (ui.currentView === "deps") return renderDependencies(report);
  if (ui.currentView === "secrets") return renderInventory(report.secrets || [], "No secrets.");
  if (ui.currentView === "ci") return renderInventory(report.workflows || [], "No CI workflow issues.");
  if (ui.currentView === "flows") return renderInventory(report.dataFlows || [], "No data-flow chains.");
  if (ui.currentView === "analyzers") return renderAnalyzers(report);
  return "";
}
