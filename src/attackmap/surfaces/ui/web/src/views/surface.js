/* Attack surface nav view (AR065): routes/endpoints table. */

import { escapeHtml } from "../util.js";

/**
 * @param {Array<any>} surfaces attack surface rows
 * @returns {string}
 */
export function renderSurface(surfaces) {
  if (!surfaces.length) return `<div class="empty">No attack surface.</div>`;
  return `<table class="grid"><thead><tr><th>Method</th><th>Path</th><th>Category</th><th>Exposure</th><th>File</th></tr></thead><tbody>
    ${surfaces.map((s) => `<tr><td>${escapeHtml(s.method || "")}</td><td>${escapeHtml(s.route || s.path || "")}</td>
      <td>${escapeHtml(s.category || "")}</td><td>${escapeHtml(s.exposure || "")}</td>
      <td>${escapeHtml(s.file || "")}</td></tr>`).join("")}
  </tbody></table>`;
}
