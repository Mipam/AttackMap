/* Attack paths nav view (AR065): entry→asset trust chains. */

import { escapeHtml } from "../util.js";

/**
 * @param {Array<any>} paths attack path cards
 * @returns {string}
 */
export function renderPaths(paths) {
  if (!paths.length) {
    return `<div class="empty-state"><h3>No attack paths</h3>
      <p>No entry→asset trust chains were inferred in this scan.</p></div>`;
  }
  return paths.map((p) => {
    const steps = (p.steps || []).map((s) => (typeof s === "string" ? s : ((s.stage || "") + (s.detail || s.action || s.label ? ": " + (s.detail || s.action || s.label) : "")))).filter(Boolean);
    return `<div class="path-card">
      <div class="path-name">${escapeHtml(p.name || "")}</div>
      <div class="m-row">${steps.map((s, i) =>
        `<span class="m-node">${escapeHtml(s)}</span>${i < steps.length - 1 ? '<span class="m-arrow">→</span>' : ""}`
      ).join("")}</div>
      ${p.impact ? `<div class="path-impact">Impact: ${escapeHtml(p.impact)}</div>` : ""}
    </div>`;
  }).join("");
}
