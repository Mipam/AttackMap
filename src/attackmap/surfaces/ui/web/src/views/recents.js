/* Recent scans nav view (AR065): clickable recent scan list. */

import { escapeHtml } from "../util.js";

/**
 * @param {import("../api-types.js").StateResponse} state
 * @returns {string}
 */
export function renderRecents(state) {
  const items = (state.recents || []).map((r) => `<div class="list-row recent" data-path="${escapeHtml(r.path)}"><div>${escapeHtml(r.name)}<div class="muted">${escapeHtml(r.path)}</div></div></div>`).join("");
  return items || `<div class="empty">No recent scans.</div>`;
}
