/* Client-side state and the refresh loop (AR065).
 *
 * `ui` holds every piece of mutable client state that used to be a top-level
 * variable in the monolithic app.js: the selected nav view, per-view selection
 * (open exploitability row, selected finding), the report cache and the
 * last-painted (report, view) pair used to skip redundant paints.
 *
 * The refresh loop serializes state polling: paintStatus fires first, then the
 * report is fetched concurrently with nothing else, and a fresh state read
 * revalidates the report identity before it may enter the cache. Any epoch or
 * revision drift re-queues the refresh instead of painting stale data.
 */

import { getState, getFreshState, getReport, stateEpoch } from "./api.js";
import { activityObserve } from "./activity.js";
import { paintStatus, paintMain } from "./paint.js";
import { escapeHtml } from "./util.js";

/** @typedef {import("./api-types.js").StateResponse} ServerState */
/** @typedef {import("./api-types.js").ReportResponse} Report */

/**
 * Mutable GUI state (was: top-level `let` globals in app.js).
 * @type {{
 *   currentView: string,
 *   openRow: number,
 *   selectedFinding: number,
 *   reportCache: Report|null,
 *   renderedReport: Report|null,
 *   renderedView: string|null,
 *   progressStarted: number,
 * }}
 */
export const ui = {
  currentView: "overview",
  openRow: -1,
  selectedFinding: 0,
  reportCache: null,
  renderedReport: null,
  renderedView: null,
  progressStarted: 0,
};

let refreshPromise = null;
let refreshRequested = false;
let refreshRevision = 0;

/** Queue a refresh; concurrent calls share the in-flight poll. */
export function refresh() {
  refreshRequested = true;
  refreshRevision += 1;
  if (!refreshPromise) {
    refreshPromise = refreshPending().finally(() => { refreshPromise = null; });
  }
  return refreshPromise;
}

/**
 * Test seam (AR065 node freshness harness): the in-flight refresh promise,
 * or null when the poll loop is idle. Lets the harness await the initial
 * poll exactly like the pre-module build exposed `refreshPromise`.
 */
export function pendingRefresh() {
  return refreshPromise;
}

async function refreshPending() {
  let state = null;
  while (refreshRequested) {
    refreshRequested = false;
    const revision = refreshRevision;
    const epoch = stateEpoch;
    const isCurrent = () => revision === refreshRevision && epoch === stateEpoch;
    try {
      state = await getState();
      if (!isCurrent()) { refreshRequested = true; continue; }
      paintStatus(ui, state);
      activityObserve(state);
      const pendingReport = loadReportIfNeeded(state, isCurrent);
      // Clear the old view while the new generation is still in flight.
      if (!ui.reportCache) paintMain(ui, state, null);
      const report = await pendingReport;
      if (!isCurrent()) { refreshRequested = true; continue; }
      paintMain(ui, state, report);
    } catch (err) {
      if (!isCurrent()) { refreshRequested = true; continue; }
      ui.reportCache = null;
      document.getElementById("view").innerHTML = `<div class="failed">${escapeHtml(err.message || String(err))}</div>`;
      document.getElementById("export-md").disabled = true;
      document.getElementById("export-pdf").disabled = true;
      state = null;
    }
  }
  return state;
}

/**
 * Load (and validate) the report for a state snapshot, or null when no
 * current report exists. The cache is keyed on (repositoryKey,
 * reportGeneration); a stale identity triggers a revalidation read and,
 * unless the server still agrees, a re-queue.
 * @param {ServerState} state
 * @param {() => boolean} [isCurrent]
 * @returns {Promise<Report|null>}
 */
export function loadReportIfNeeded(state, isCurrent = () => true) {
  if (!["idle", "done"].includes(state.status) || !state.hasReport
      || !state.reportGeneration || state.reportRepositoryKey !== state.repositoryKey) {
    ui.reportCache = null;
    return Promise.resolve(null);
  }
  if (ui.reportCache && ui.reportCache.generationId === state.reportGeneration
      && ui.reportCache.repositoryKey === state.repositoryKey) return Promise.resolve(ui.reportCache);
  ui.reportCache = null;
  ui.selectedFinding = 0;
  ui.openRow = -1;
  return (async () => {
    try {
      const report = await getReport(state);
      if (!isCurrent()) return null;
      // Watch scans and native folder selection can change the server without
      // a local refresh/post. Revalidate after the report body has arrived so
      // an old response cannot become the current view.
      const latest = await getFreshState();
      if (!isCurrent()) return null;
      if (!["idle", "done"].includes(latest.status) || !latest.hasReport
          || latest.reportGeneration !== state.reportGeneration
          || latest.repositoryKey !== state.repositoryKey
          || latest.reportRepositoryKey !== state.repositoryKey) {
        refreshRequested = true;
        return null;
      }
      if (report.generationId === state.reportGeneration && report.repositoryKey === state.repositoryKey) {
        ui.reportCache = report;
      }
    } catch {
      // The generation may have changed between the state and report requests.
      if (isCurrent()) ui.reportCache = null;
    }
    return ui.reportCache;
  })();
}
