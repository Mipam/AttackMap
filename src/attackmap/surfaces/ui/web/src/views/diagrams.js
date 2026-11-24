/* Diagrams nav view (AR065): mermaid path/topology diagrams. */

import { renderMermaidDocument } from "../mermaid-lite.js";

/**
 * @param {import("../api-types.js").ReportResponse} report
 * @returns {string}
 */
export function renderDiagrams(report) {
  return renderMermaidDocument((report.diagrams && (report.diagrams.paths || report.diagrams.topology)) || "")
    + (report.diagrams && report.diagrams.topology && report.diagrams.paths ? renderMermaidDocument(report.diagrams.topology) : "");
}
