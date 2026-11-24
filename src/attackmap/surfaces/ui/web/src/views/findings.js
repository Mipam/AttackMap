/* Findings nav view (AR065): master/detail list with suppression. */

import { escapeHtml } from "../util.js";

/**
 * @param {import("../api-types.js").ReportResponse} r
 * @param {number} selectedFinding index into r.findings
 * @returns {string}
 */
export function renderFindings(r, selectedFinding) {
  const findings = r.findings || [];
  const suppressed = r.suppressed || [];
  const f = findings[selectedFinding] || findings[0];
  const list = findings.map((item, i) => {
    const loc = (item.locations && item.locations[0]) || {};
    return `<div class="split-row${i === selectedFinding ? " open" : ""}" data-fi="${i}">
      <div>${escapeHtml(item.title || "")}<div class="muted">${escapeHtml((loc.file || "") + (loc.line ? ":" + loc.line : ""))}</div></div>
      <span class="sev ${escapeHtml(item.severity || "")}">${escapeHtml(item.severity || "")}</span>
    </div>`;
  }).join("");
  const techniques = ((f && f.attack_techniques) || []).map((t) => (typeof t === "string" ? t : (t.technique_id || t.id || ""))).filter(Boolean).join(", ");
  const detail = f ? `<div class="detail">
      <h2>${escapeHtml(f.title || "")}</h2>
      <span class="sev ${escapeHtml(f.severity || "")}">${escapeHtml(f.severity || "")}</span>
      <p>${(f.evidence || []).map((e) => `<div class="muted">${escapeHtml(e)}</div>`).join("")}</p>
      <p><strong>Remediation</strong><br/>${escapeHtml(f.mitigation || "")}</p>
      ${techniques ? `<p>ATT&CK: ${escapeHtml(techniques)}</p>` : ""}
      <p><input id="suppress-reason" placeholder="Suppression reason" />
      <button type="button" class="ghost" id="suppress-btn">Suppress…</button></p>
    </div>` : `<div class="empty">No findings.</div>`;
  const hidden = suppressed.length ? `<details style="padding:12px"><summary>Suppressed (${suppressed.length})</summary>
    ${suppressed.map((s) => `<div class="list-row"><div>${escapeHtml(s.title || s.id || "")}<div class="muted">${escapeHtml(s.reason || "")}</div></div></div>`).join("")}
  </details>` : "";
  return `<div class="master"><div>${list}${hidden}</div>${detail}</div>`;
}
