/* Overview nav view (AR065): finding counts, top static risk, architecture diagram. */

import { escapeHtml } from "../util.js";
import { renderMarkdown } from "../markdown.js";

/**
 * @param {import("../api-types.js").ReportResponse} r
 * @returns {string}
 */
export function renderOverview(r) {
  const sev = r.severityCounts || {};
  const top = r.topPath;
  return `<div class="cards">
    <div class="card"><div class="muted">Findings</div><div class="n">${r.findingCount}</div></div>
    <div class="card"><div class="muted">High</div><div class="n">${sev.high || 0}</div></div>
    <div class="card"><div class="muted">Medium</div><div class="n">${sev.medium || 0}</div></div>
    <div class="card"><div class="muted">Low</div><div class="n">${sev.low || 0}</div></div>
  </div>
  ${top ? `<div class="card" style="margin:0 16px 16px"><div class="muted">Highest static route-to-sink risk score</div>
    <div>${escapeHtml(top.method || "")} ${escapeHtml(top.route || top.subject)} · score ${escapeHtml(top.score)}</div><div class="muted">Heuristic static analysis; runtime reachability and exploitability are not verified.</div></div>` : ""}
  ${renderMarkdown((r.diagrams && r.diagrams.architecture) || "")}`;
}
