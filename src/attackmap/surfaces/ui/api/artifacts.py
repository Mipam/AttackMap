"""Report-artifact API handlers and their export/save-dialog helpers (AR063).

Handlers (all registered with ``@route``):

- ``GET  /api/report``        — current report snapshot (404/409 when stale)
- ``GET  /api/export-source`` — raw Markdown for a report view
- ``POST /api/export``        — write a report view to a .md/.pdf path
- ``POST /api/pick-save``     — ask for an export destination path
- ``POST /api/reveal``        — open the report folder in the system shell

The export/save helpers were extracted verbatim from ``surfaces/ui/server.py``
during AR063; behavior is unchanged.
"""

from __future__ import annotations

import logging
import os
import subprocess
import threading
import uuid
from pathlib import Path
from typing import Any

from attackmap.surfaces.ui.api.routes import ApiResponse, route, state_response
from attackmap.surfaces.ui.api.schemas import (
    ExportRequest,
    ExportResponse,
    ExportSourceResponse,
    PickSaveRequest,
    PickSaveResponse,
    ReportResponse,
    RevealRequest,
    RevealResponse,
)
from attackmap.surfaces.ui.export_md import (
    SUPPORTED_SUFFIXES,
    render_view_markdown,
    suggested_export_name,
)
from attackmap.surfaces.ui.output import current_generation

# Handlers take ``app: Any`` (the adapter's ``LoopbackApp`` at runtime); see
# api/scans.py for why the concrete type is not imported here.
logger = logging.getLogger(__name__)


@route("GET", "/api/report", response=ReportResponse, summary="Current report snapshot")
def report_snapshot(app: Any, body: dict[str, Any], query: dict[str, list[str]]) -> ApiResponse:
    snapshot = app.report_snapshot()
    if snapshot is None:
        return ApiResponse(404, {"error": "no report"})
    stale = any(
        query.get(key, [snapshot[key]])[0] != snapshot[key]
        for key in ("repositoryKey", "generationId")
    )
    if stale:
        return ApiResponse(409, {"error": "report generation changed"})
    ReportResponse.model_validate(snapshot)
    return ApiResponse(200, snapshot)


@route("GET", "/api/export-source", response=ExportSourceResponse,
       summary="Raw Markdown for a report view")
def export_source(app: Any, body: dict[str, Any], query: dict[str, list[str]]) -> ApiResponse:
    view = str(query.get("view", [""])[0])
    if not app.report or view == "settings":
        return ApiResponse(409, {"error": "not available"})
    repo = app.report.repo_name or (app.repo.name if app.repo else "report")
    markdown = render_view_markdown(view, app.report.as_json(), repo_name=repo, recents=app.recents)
    ExportSourceResponse.model_validate({"markdown": markdown})
    return ApiResponse(200, markdown.encode("utf-8"), "text/markdown; charset=utf-8")


@route("POST", "/api/export", request=ExportRequest, response=ExportResponse,
       summary="Write a report view to a .md/.pdf path")
def export_view(app: Any, body: dict[str, Any], query: dict[str, list[str]]) -> ApiResponse:
    ExportRequest.model_validate(body)
    result = _handle_export(app, body)
    return ApiResponse(result["code"], result["body"])


@route("POST", "/api/pick-save", request=PickSaveRequest, response=PickSaveResponse,
       summary="Ask for an export destination path")
def pick_save(app: Any, body: dict[str, Any], query: dict[str, list[str]]) -> ApiResponse:
    request = PickSaveRequest.model_validate(body)
    payload = {"path": _pick_save_path(request.suggestedName or "") or ""}
    PickSaveResponse.model_validate(payload)
    return ApiResponse(200, payload)


@route("POST", "/api/reveal", request=RevealRequest, response=RevealResponse,
       summary="Open the report folder in the system shell")
def reveal_output(app: Any, body: dict[str, Any], query: dict[str, list[str]]) -> ApiResponse:
    RevealRequest.model_validate(body)
    if app.output and app.output.exists() and hasattr(os, "startfile"):
        target = current_generation(app.output) or app.output
        os.startfile(target)
    return state_response(app, RevealResponse)


# --------------------------------------------------------------------------
# Export / save-dialog helpers (extracted from server.py, behavior unchanged)
# --------------------------------------------------------------------------


def _handle_export(app: Any, body: dict[str, Any]) -> dict[str, Any]:
    view = str(body.get("view", ""))
    path_str = str(body.get("path", "")).strip('"').strip("'")
    if not app.report:
        return {"code": 409, "body": {"error": "no report"}}
    if view == "settings" or view not in {
        "overview", "findings", "exploitability", "paths", "surface", "diagrams",
        "review", "ai-review", "diff", "fleet", "deps", "secrets", "ci", "flows",
        "analyzers", "recents",
    }:
        return {"code": 400, "body": {"error": "invalid view"}}
    target = Path(path_str)
    suffix = target.suffix.lower()
    if suffix == ".":
        # tkinter asksaveasfilename may return a trailing dot when the user
        # typed a name without extension and the dialog appended defaultextension.
        # Re-derive the suffix from the requested filename or the view default.
        suggested = suggested_export_name(
            app.report.repo_name or (app.repo.name if app.repo else "report"), view, ".md"
        )
        target = target.with_suffix(Path(suggested).suffix)
        suffix = target.suffix.lower()
    if suffix not in SUPPORTED_SUFFIXES:
        return {"code": 400, "body": {"error": f"unsupported suffix {suffix}"}}
    try:
        from attackmap.foundation.safe_fs import safe_write_text

        out_dir = target.parent
        repo = app.report.repo_name or (app.repo.name if app.repo else "report")
        markdown = render_view_markdown(
            view,
            app.report.as_json(),
            repo_name=repo,
            recents=app.recents,
        )
        if suffix == ".md":
            safe_write_text(out_dir, target, markdown)
            return {"code": 200, "body": {"ok": True, "path": str(target)}}
        html = _markdown_to_pdf_html(markdown, repo, view)
        tmp_html = out_dir / f"._attackmap_export_{uuid.uuid4().hex}.html"
        tmp_html.write_text(html, encoding="utf-8")
        try:
            browser = _find_chrome_or_edge()
            if not browser:
                raise RuntimeError("Chrome or Edge not found")
            subprocess.run(
                [
                    str(browser),
                    "--headless",
                    "--disable-gpu",
                    "--no-pdf-header-footer",
                    f"--print-to-pdf={target}",
                    str(tmp_html),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=60,
            )
        finally:
            try:
                tmp_html.unlink()
            except OSError:
                pass
        return {"code": 200, "body": {"ok": True, "path": str(target)}}
    except Exception as exc:
        return {"code": 400, "body": {"error": str(exc)}}


def _markdown_to_pdf_html(markdown: str, repo: str, view: str) -> str:
    """Wrap rendered Markdown in print-friendly HTML with dark-to-light colors."""
    from html import escape

    title = f"AttackMap – {repo} – {view}"
    body = "\n".join(
        f"<p>{escape(line)}</p>" if line and not line.startswith("<") else line
        for line in markdown.splitlines()
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{escape(title)}</title>
<style>
  body {{ font-family: "Segoe UI", sans-serif; margin: 24px; color: #1a1a1a; background: #fff; line-height: 1.5; }}
  h1 {{ font-size: 22px; margin-bottom: 8px; }}
  h2 {{ font-size: 16px; margin-top: 24px; margin-bottom: 8px; }}
  p {{ margin: 8px 0; }}
  pre {{ background: #f4f4f4; padding: 10px; border-radius: 6px; overflow-x: auto; }}
  table {{ border-collapse: collapse; width: 100%; margin: 12px 0; }}
  th, td {{ border: 1px solid #ccc; padding: 6px 8px; text-align: left; vertical-align: top; word-break: break-word; }}
  th {{ background: #f0f0f0; }}
</style>
</head>
<body>
{body}
</body>
</html>"""


def _find_chrome_or_edge() -> Path | None:
    candidates = [
        Path(os.environ.get("PROGRAMFILES(x86)", "")) / "Microsoft" / "Edge" / "Application" / "msedge.exe",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "Edge" / "Application" / "msedge.exe",
        Path(os.environ.get("PROGRAMFILES", "")) / "Microsoft" / "Edge" / "Application" / "msedge.exe",
        Path(os.environ.get("PROGRAMFILES(x86)", "")) / "Google" / "Chrome" / "Application" / "chrome.exe",
        Path(os.environ.get("PROGRAMFILES", "")) / "Google" / "Chrome" / "Application" / "chrome.exe",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Google" / "Chrome" / "Application" / "chrome.exe",
    ]
    for candidate in candidates:
        if candidate and candidate.is_file():
            return candidate
    return None


def _pick_save_path(suggested_name: str) -> str | None:
    if threading.current_thread() is not threading.main_thread():
        return None
    try:
        import tkinter as tk
        from tkinter import filedialog
    except ImportError:
        logger.debug("tkinter is unavailable; save dialog disabled.", exc_info=True)
        return None
    try:
        root = tk.Tk()
        root.withdraw()
        root.wm_attributes("-topmost", 1)
        chosen = filedialog.asksaveasfilename(
            title="Save report",
            defaultextension=".md",
            initialfile=suggested_name or "attackmap-report.md",
            filetypes=[("Markdown files", "*.md"), ("PDF files", "*.pdf"), ("All files", "*.*")],
        )
        root.destroy()
        return chosen if chosen else None
    except tk.TclError:
        # Recorded, not swallowed (AC-012): headless/no-display hosts fail here.
        logger.debug("tkinter save dialog failed.", exc_info=True)
        return None
