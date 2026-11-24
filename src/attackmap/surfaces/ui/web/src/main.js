/* Entry point (AR065): wires the GUI together after the ES-module split.
 * Everything here used to live at the bottom of the monolithic app.js:
 * nav/view switching, the run/pick/watch/export command handlers, the print
 * preview bridge, and the poll loop that drives the shared refresh cycle.
 */

import { getState, post, getToken } from "./api.js";
import { ui, refresh } from "./state.js";
import { renderMarkdown } from "./markdown.js";

/** Switch nav view and repaint. */
function showView(view) {
  ui.currentView = view;
  document.querySelectorAll(".sidebar button").forEach((b) => b.classList.toggle("active", b.dataset.view === view));
  refresh();
}

function suggestedExportName(suffix) {
  const repo = (ui.reportCache && ui.reportCache.repoName) || "report";
  const safe = String(repo).replace(/[^a-zA-Z0-9-_]+/g, "-").replace(/^-+|-+$/g, "").toLowerCase() || "report";
  return `attackmap-${safe}-${ui.currentView}${suffix}`;
}

async function pickSavePath(suggestedName, extension) {
  try {
    if (window.pywebview && window.pywebview.api && window.pywebview.api.pick_save) {
      const chosen = await window.pywebview.api.pick_save(suggestedName, extension);
      if (chosen) return chosen;
    }
  } catch {}
  const res = await post("/api/pick-save", { suggestedName });
  return res.path || "";
}

async function doExport(suffix) {
  const path = await pickSavePath(suggestedExportName(suffix), suffix);
  if (!path) return;
  const result = await post("/api/export", { view: ui.currentView, path });
  if (!result.ok) {
    alert(result.error || "Export failed.");
    return;
  }
  if (suffix.toLowerCase() === ".pdf") {
    // Optionally open a preview/print dialog after the PDF has been written.
    try {
      // AR065: the state snapshot carries no token (AR063 schemas are the
      // source of truth), so the preview fetch must use the centralized
      // client token — previously this header was `state.token`, i.e. the
      // string "undefined", and the preview silently 403'd.
      const md = await (await fetch(`/api/export-source?view=${encodeURIComponent(ui.currentView)}`, {
        headers: { "X-AttackMap-Token": getToken() },
      })).text();
      openPdfFromMarkdown(md);
    } catch {
      // Preview is optional; the PDF file is already saved.
    }
  } else {
    alert(`Saved to ${result.path}`);
  }
}

async function pickFolder(multi) {
  let paths = [];
  try {
    if (window.pywebview && window.pywebview.api && window.pywebview.api.pick_folder) {
      paths = await window.pywebview.api.pick_folder(multi);
    }
  } catch {
    paths = [];
  }
  if (!paths || !paths.length) {
    const res = await post("/api/pick", { multi: !!multi });
    paths = res.picked || [];
  }
  if (multi && paths.length) {
    const state = await getState();
    const merged = [...new Set([...(state.repos || []), ...paths])];
    await post("/api/config", { repos: merged });
  } else if (paths.length) {
    await post("/api/config", { repos: paths });
  }
  refresh();
}

document.getElementById("sidebar").addEventListener("click", (ev) => {
  const btn = ev.target.closest("button");
  if (!btn) return;
  showView(btn.dataset.view);
});

document.getElementById("main").addEventListener("click", async (ev) => {
  const row = ev.target.closest(".exploit-row");
  if (row) {
    const i = Number(row.dataset.i);
    ui.openRow = ui.openRow === i ? -1 : i;
    refresh();
    return;
  }
  const find = ev.target.closest(".split-row");
  if (find) {
    ui.selectedFinding = Number(find.dataset.fi);
    refresh();
    return;
  }
  if (ev.target.id === "save-keys") {
    await post("/api/settings", {
      anthropicKey: document.getElementById("anth-key").value,
      openAIKey: document.getElementById("oai-key").value,
    });
    refresh();
    return;
  }
  if (ev.target.id === "suppress-btn" && ui.reportCache) {
    const box = document.getElementById("suppress-reason");
    const reason = box ? box.value.trim() : "";
    const f = ui.reportCache.findings[ui.selectedFinding];
    if (!reason || !f) return;
    await post("/api/suppress", { id: f.id, reason });
    ui.reportCache = null;
    await refresh();
    return;
  }
  const recent = ev.target.closest(".recent");
  if (recent) {
    await post("/api/config", { repo: recent.dataset.path });
    refresh();
  }
});

document.getElementById("run").addEventListener("click", async () => {
  const state = await getState();
  if (state.running) await post("/api/cancel", {});
  else {
    const typed = document.getElementById("repo-label").value.trim();
    if (typed && !state.repo) {
      await post("/api/config", { repo: typed.split(" · ")[0] });
    }
    if (!state.repo && !state.repos?.length && !typed) {
      await pickFolder(false);
    }
    const next = await getState();
    const repos = next.repos && next.repos.length ? next.repos : (typed ? typed.split(" · ") : []);
    if (!repos.length) return;
    const providerSel = document.getElementById("provider").value;
    const isLmStudio = providerSel === "openai-lmstudio";
    await post("/api/run", {
      repos,
      cve: document.getElementById("cve").checked,
      recall: document.getElementById("recall").checked,
      llmMode: document.getElementById("llm-menu").value,
      provider: isLmStudio ? "openai" : providerSel,
      model: document.getElementById("model").value.trim() || null,
      baseUrl: isLmStudio
        ? (document.getElementById("base-url").value.trim() || "http://127.0.0.1:1234/v1")
        : "",
      modules: document.getElementById("analyzers").value,
    });
  }
  refresh();
});

document.getElementById("pick").addEventListener("click", () => pickFolder(false));
document.getElementById("add-folder").addEventListener("click", () => pickFolder(true));
document.getElementById("settings-btn").addEventListener("click", () => showView("settings"));
document.getElementById("reveal").addEventListener("click", () => post("/api/reveal", {}));
document.getElementById("export-md").addEventListener("click", () => doExport(".md"));
document.getElementById("export-pdf").addEventListener("click", () => doExport(".pdf"));

function openPdfFromMarkdown(md) {
  const w = window.open("about:blank", "_blank");
  if (!w) return;
  const html = `
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AttackMap – Export</title>
<link rel="stylesheet" href="/src/app.css">
<link rel="stylesheet" href="/src/exploitability.css">
<style>
@media print {
  body { background: #fff; color: #111; }
  .md code { background: #eee; color: #111; }
}
</style>
</head>
<body>
${renderMarkdown(md)}
<script>window.print();<\/script>
</body>
</html>`;
  w.document.open();
  w.document.write(html);
  w.document.close();
}
// Kept on window for parity with the pre-module build (the native bridge and
// any external caller reach it there); doExport uses the local binding.
window.openPdfFromMarkdown = openPdfFromMarkdown;

document.getElementById("watch").addEventListener("change", (ev) => {
  post("/api/watch", { enabled: ev.target.checked }).then(() => refresh());
});
document.getElementById("provider").addEventListener("change", (ev) => {
  document.getElementById("base-url-label").hidden = ev.target.value !== "openai-lmstudio";
});
document.getElementById("llm-menu").addEventListener("change", (ev) => {
  if (ev.target.value !== "none") {
    window.alert("Enabling an LLM provider can send an evidence pack off this machine.");
  }
  post("/api/config", { llmMode: ev.target.value, provider: document.getElementById("provider").value });
});

async function pollState() {
  await refresh();
  const boot = document.getElementById("boot");
  if (boot) boot.remove();
  setTimeout(pollState, 800);
}
pollState();
