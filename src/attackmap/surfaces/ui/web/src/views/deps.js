/* Dependencies nav view (AR065): resolved packages and known advisories. */

import { escapeHtml } from "../util.js";

/**
 * @param {import("../api-types.js").ReportResponse} report
 * @returns {string}
 */
export function renderDependencies(report) {
  const deps = report.dependencies || [];
  const vulns = report.vulnerabilities || [];
  const depRows = deps.length
    ? `<table class="grid"><thead><tr><th>Package</th><th>Version</th><th>Ecosystem</th><th>Scope</th><th>Resolved via</th></tr></thead><tbody>
      ${deps.map((d) => `<tr>
        <td>${escapeHtml(d.name || "")}</td>
        <td>${escapeHtml(d.version || "")}</td>
        <td>${escapeHtml(d.ecosystem || "")}</td>
        <td>${d.direct ? "direct" : "transitive"}${d.dev ? " · dev" : ""}</td>
        <td>${escapeHtml(d.via || d.file || "")}</td>
      </tr>`).join("")}
    </tbody></table>`
    : `<div class="empty-state"><h3>No dependencies detected</h3>
       <p>No package manifests or lockfiles were resolved in this scan.</p>
       <p class="muted">Run with <strong>CVE</strong> enabled to cross-reference resolved
       dependencies against OSV.dev advisories.</p></div>`;
  const vulnRows = vulns.length
    ? `<h3 style="padding:12px 12px 0">Known advisories</h3>
       <table class="grid"><thead><tr><th>ID</th><th>Aliases</th><th>Summary</th><th>Affected</th></tr></thead><tbody>
       ${vulns.map((v) => `<tr>
         <td>${escapeHtml(v.id || v.osv_id || "")}</td>
         <td>${escapeHtml((v.aliases || []).join(", "))}</td>
         <td>${escapeHtml(v.summary || "")}</td>
         <td>${escapeHtml(v.affected || v.package || "")}</td>
       </tr>`).join("")}</tbody></table>`
    : "";
  return depRows + vulnRows;
}
