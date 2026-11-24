/* Fleet nav view (AR065): multi-repo rollup, contract links, trust gaps. */

import { escapeHtml } from "../util.js";

/**
 * @param {any} fleet fleet summary object, or null when no fleet scan ran
 * @returns {string}
 */
export function renderFleet(fleet) {
  if (!fleet) return `<div class="empty">Select two or more folders with + Fleet, then run a scan.</div>`;
  const repos = (fleet.repos || []).map((r) => `<div class="list-row"><div>${escapeHtml(r.repo_id || r.root)}</div><span>${escapeHtml(r.findings)}</span></div>`).join("");
  const links = (fleet.cross_repo_links || []).map((l) => `<div class="list-row"><div>${escapeHtml(l.client_repo)} → ${escapeHtml(l.server_repo)}</div><code>${escapeHtml(l.method + " " + (l.path_template || ""))}</code></div>`).join("");
  const failed = (fleet.failed || []).map((f) => `<div class="list-row"><div>${escapeHtml(f.repo_id || "")}<div class="muted">${escapeHtml(f.error || "")}</div></div></div>`).join("");
  const gaps = (fleet.trust_gaps || []).concat(fleet.cross_boundary_flows || []).map((g) => `<div class="list-row"><div>${escapeHtml(g.client_repo || "")} → ${escapeHtml(g.server_repo || "")}<div class="muted">${escapeHtml(g.basis || g.kind || "")}</div></div></div>`).join("");
  return `<div class="cards"><div class="card"><div class="muted">Repos</div><div class="n">${Number(fleet.repo_count) || 0}</div></div>
    <div class="card"><div class="muted">Findings</div><div class="n">${Number(fleet.total_findings) || 0}</div></div></div>
    <h3 style="padding:0 16px">Per-repo rollup</h3>${repos || '<div class="empty">None</div>'}
    <h3 style="padding:0 16px">Contract links</h3>${links || '<div class="empty">None</div>'}
    <h3 style="padding:0 16px">Failed</h3>${failed || '<div class="empty">None</div>'}
    <h3 style="padding:0 16px">Trust gaps / cross-boundary</h3>${gaps || '<div class="empty">None</div>'}`;
}
