/* Inventory-style nav views (AR065): Secrets, CI workflows, Data flows, Analyzers. */

import { escapeHtml } from "../util.js";

/**
 * Generic row renderer for report inventories (secrets, CI workflow issues,
 * data-flow chains). Title prefers name/id/kind/rule/label/package and falls
 * back to a route→sink composite; the location column prefers file:line,
 * then sink file/line, then a freeform location.
 * @param {Array<any>} rows
 * @param {string} empty message shown when there is nothing to list
 * @returns {string}
 */
export function renderInventory(rows, empty) {
  if (!rows || !rows.length) return `<div class="empty">${empty}</div>`;
  return rows.map((item) => {
    const title = item.name || item.id || item.kind || item.rule || item.label || item.package
      || ((item.route_method || item.route_path || item.sink_kind)
        ? `${item.route_method || ""} ${item.route_path || ""} → ${item.sink_kind || ""}`.trim()
        : "item");
    const loc = item.file ? `${item.file}${item.line ? ":" + item.line : ""}`
      : (item.sink_file ? `${item.sink_file}${item.sink_line ? ":" + item.sink_line : ""}` : (item.location || ""));
    return `<div class="list-row"><div>${escapeHtml(title)}<div class="muted">${escapeHtml(item.summary || item.message || item.ecosystem || "")}</div></div>
      <code>${escapeHtml(loc)}</code></div>`;
  }).join("");
}

/**
 * @param {import("../api-types.js").ReportResponse} report
 * @returns {string}
 */
export function renderAnalyzers(report) {
  const errors = report.analyzerErrors || [];
  const limits = report.limitations || [];
  return `${errors.map((e) => `<div class="list-row"><div>${escapeHtml(e.analyzer || "")}<div class="muted">${escapeHtml(e.message || "")}</div></div></div>`).join("")}
    ${limits.map((l) => `<div class="list-row"><div>${escapeHtml(l)}</div></div>`).join("")}
    ${!errors.length && !limits.length ? `<div class="empty">Analyzers completed without recorded errors.</div>` : ""}`;
}
