/* Markdown-backed nav views (AR065): Review, AI Review, Diff. */

import { renderMarkdown } from "../markdown.js";

/**
 * @param {import("../api-types.js").ReportResponse} report
 * @returns {string}
 */
export function renderReview(report) {
  return renderMarkdown(report.reviewMd || "");
}

/**
 * @param {import("../api-types.js").ReportResponse} report
 * @returns {string}
 */
export function renderAiReview(report) {
  if (report.aiReviewMd) {
    return renderMarkdown(report.aiReviewMd);
  }
  if (report.aiReviewRequested) {
    return `<div class="empty">AI Review was requested but produced no output. Check the *.meta.json files in the report folder for backend details.</div>`;
  }
  return `<div class="empty">Enable an AI mode to generate a review. Optional AI and CVE features have separate network and data disclosures in Settings.</div>`;
}

/**
 * @param {import("../api-types.js").ReportResponse} report
 * @returns {string}
 */
export function renderDiff(report) {
  return renderMarkdown(report.diffMd || "No baseline diff. Re-run the same repo to compare.");
}
