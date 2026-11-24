"""Scan-lifecycle API handlers and the scan orchestration they build on (AR063).

Handlers (all registered with ``@route``):

- ``GET  /api/state``  — app + run state snapshot
- ``POST /api/config`` — apply scan configuration
- ``POST /api/pick``   — pick repository folders via the native dialog
- ``POST /api/run``    — start a scan
- ``POST /api/cancel`` — request cancellation of the active run
- ``POST /api/watch``  — toggle filesystem watching

The orchestration helpers below were extracted verbatim from
``surfaces/ui/server.py`` during AR063; behavior is unchanged. ``server.py``
re-exports them so existing callers and tests keep working.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import uuid
from pathlib import Path
from typing import Any

from attackmap.foundation.secrets import (
    child_llm_env,
    has_llm_key,
    is_loopback_endpoint,
)
from attackmap.orchestration.analyzers import TRUSTED_ONLY_ENV
from attackmap.surfaces.ui.api.routes import ApiResponse, route, state_response
from attackmap.surfaces.ui.api.schemas import (
    CancelRequest,
    CancelResponse,
    ConfigRequest,
    ConfigResponse,
    PickRequest,
    PickResponse,
    RunRequest,
    RunResponse,
    StateResponse,
    WatchRequest,
    WatchResponse,
)
from attackmap.surfaces.ui.config import ScanConfig
from attackmap.surfaces.ui.output import (
    fleet_dir,
    generation_dir,
    promote_generation,
    reports_dir,
    rotate_previous,
)
from attackmap.surfaces.ui.report import load_current_report
from attackmap.surfaces.ui.run_state import GuiRunState
from attackmap.surfaces.ui.spawn import frozen_aware_argv, is_frozen_build
from attackmap.surfaces.ui.watch import Watcher

logger = logging.getLogger(__name__)

_RECENTS_LIMIT = 12


# Handlers take ``app: Any`` (the adapter's ``LoopbackApp`` at runtime): the
# arch_report cycle gate counts type-only imports, so this package must not
# import ``surfaces.ui.server`` even under ``TYPE_CHECKING``.
# --------------------------------------------------------------------------
# Handlers
# --------------------------------------------------------------------------


@route("GET", "/api/state", response=StateResponse, summary="App + run state snapshot")
def state(app: Any, body: dict[str, Any], query: dict[str, list[str]]) -> ApiResponse:
    payload = app.state()
    StateResponse.model_validate(payload)
    return ApiResponse(200, payload)


@route("POST", "/api/config", request=ConfigRequest, response=ConfigResponse,
       summary="Apply scan configuration")
def apply_config(app: Any, body: dict[str, Any], query: dict[str, list[str]]) -> ApiResponse:
    ConfigRequest.model_validate(body)
    _apply_config(app, body)
    return state_response(app, ConfigResponse)


@route("POST", "/api/pick", request=PickRequest, response=PickResponse,
       summary="Pick repository folders via the native dialog")
def pick_repositories(app: Any, body: dict[str, Any], query: dict[str, list[str]]) -> ApiResponse:
    PickRequest.model_validate(body)
    chosen = _pick_folders(multi=bool(body.get("multi")))
    if chosen:
        app.repos = [Path(p).resolve() for p in chosen]
        _refresh_missing(app)
    payload = {**app.state(), "picked": [str(p) for p in app.repos]}
    PickResponse.model_validate(payload)
    return ApiResponse(200, payload)


@route("POST", "/api/run", request=RunRequest, response=RunResponse, summary="Start a scan")
def run_scan(app: Any, body: dict[str, Any], query: dict[str, list[str]]) -> ApiResponse:
    RunRequest.model_validate(body)
    _start_scan(app, body)
    return state_response(app, RunResponse)


@route("POST", "/api/cancel", request=CancelRequest, response=CancelResponse,
       summary="Request cancellation of the active run")
def cancel_scan(app: Any, body: dict[str, Any], query: dict[str, list[str]]) -> ApiResponse:
    CancelRequest.model_validate(body)
    _request_scan_cancel(app)
    return state_response(app, CancelResponse)


@route("POST", "/api/watch", request=WatchRequest, response=WatchResponse,
       summary="Toggle filesystem watching")
def toggle_watch(app: Any, body: dict[str, Any], query: dict[str, list[str]]) -> ApiResponse:
    request = WatchRequest.model_validate(body)
    app.watch = bool(request.enabled)
    _sync_watch(app)
    return state_response(app, WatchResponse)


# --------------------------------------------------------------------------
# Scan orchestration (extracted from server.py, behavior unchanged)
# --------------------------------------------------------------------------


def _request_scan_cancel(app: Any) -> None:
    """Acknowledge cancellation without waiting for process-tree cleanup."""
    with app._lock:
        if app._run_state != GuiRunState.RUNNING:
            return
        app._run_state = GuiRunState.CANCELLING
        run_id, runner = app.run_id, app.runner

    def cleanup() -> None:
        try:
            verified = runner.cancel()
        except Exception:
            verified = False
        if verified is False:
            with app._lock:
                if app.run_id == run_id and app.runner is runner and app._run_state == GuiRunState.CANCELLING:
                    app.error = "Cancellation could not verify process-tree exit; restart remains blocked."

    threading.Thread(target=cleanup, daemon=True).start()


def _apply_config(app: Any, body: dict[str, Any]) -> None:
    with app._lock:
        _apply_config_locked(app, body)


def _apply_config_locked(app: Any, body: dict[str, Any]) -> None:
    if body.get("repo"):
        app.repos = [Path(body["repo"]).resolve()]
    if body.get("repos"):
        app.repos = [Path(p).resolve() for p in body["repos"]]
    app.cve = bool(body.get("cve", app.cve))
    app.recall = bool(body.get("recall", app.recall))
    app.llm_mode = str(body.get("llmMode") or body.get("llm") or app.llm_mode)
    app.provider = str(body.get("provider") or app.provider)
    if "model" in body:
        app.model = str(body["model"]).strip() or None
    if "baseUrl" in body:
        app.base_url = str(body["baseUrl"]).strip()
    if "modules" in body:
        raw = body["modules"]
        app.modules = [raw] if isinstance(raw, str) else list(raw)
    app.no_suppress = bool(body.get("noSuppress", app.no_suppress))
    app.use_baseline = bool(body.get("useBaseline", app.use_baseline))
    app.fail_on_new_high = bool(body.get("failOnNewHigh", app.fail_on_new_high))
    if app.repos:
        _refresh_missing(app)


def _start_scan(app: Any, body: dict[str, Any]) -> None:
    with app._lock:
        _start_scan_locked(app, body)


def _start_scan_locked(app: Any, body: dict[str, Any]) -> None:
    if app._run_state in {GuiRunState.RUNNING, GuiRunState.CANCELLING}:
        return
    _apply_config(app, body)
    if not app.repos or not app.repos[0].exists():
        app._run_state = GuiRunState.FAILED
        app.error = "Pick a repository folder first."
        return
    llm_active = app.llm_mode not in {"none", "None (heuristic only)", ""}
    is_local_openai = app.provider.lower().startswith("openai") and is_loopback_endpoint(app.base_url)
    if llm_active and not is_local_openai and not has_llm_key(app.provider):
        app._run_state = GuiRunState.FAILED
        app.error = f"No API key stored for {app.provider}. Open Settings and save a key, or keep heuristic-only mode."
        return
    _refresh_missing(app)
    fleet = len(app.repos) > 1
    report_base = fleet_dir(app.repos) if fleet else reports_dir(app.repos[0])
    app.output = report_base
    baseline = None
    if not fleet and app.use_baseline:
        baseline = rotate_previous(app.repos[0], report_base)

    run_id = uuid.uuid4().hex
    run_repos = list(app.repos)
    workspace_revision = app.workspace_revision
    repository_key = app.repository_key
    app.run_id = run_id
    app._contract_repository_key = app.repository_key
    app._run_state = GuiRunState.RUNNING
    app.error = None
    app.exit_code = None
    app.stderr_tail = ""
    app.progress = {"event": "begin", "label": "Starting scan"}
    output = generation_dir(report_base, run_id)
    cfg = ScanConfig(
        repos=run_repos,
        output=output,
        run_id=app.run_id,
        run_cve=app.cve,
        modules=[m for m in app.modules if m and m.lower() != "auto"],
        llm_mode=app.llm_mode,
        provider=app.provider,
        model=app.model,
        recall=app.recall,
        no_suppress=app.no_suppress,
        baseline=baseline if app.use_baseline else None,
        fail_on_new_high=app.fail_on_new_high,
        capabilities=app.capabilities if app._caps_loaded else None,
    )
    argv = frozen_aware_argv(cfg)

    def on_progress(event: dict) -> None:
        with app._lock:
            if app.run_id == run_id and app.workspace_revision == workspace_revision:
                app.progress = event

    def on_done(code: int, report: Path | None, tail: str = "") -> None:
        with app._lock:
            finish(code, report, tail)
            # Changes observed during the run are processed by exactly one
            # follow-up scan once the run has completed.
            _drain_watch_pending_locked(app)

    def finish(code: int, report: Path | None, tail: str) -> None:
        if app.run_id != run_id:
            return
        if app.workspace_revision != workspace_revision:
            app._run_state = GuiRunState.IDLE
            app.run_id = None
            app.progress = {}
            return
        app.exit_code = code
        app.stderr_tail = tail
        if app._run_state == GuiRunState.CANCELLING:
            app._run_state = GuiRunState.CANCELLED
            app.error = tail.strip() or "Scan cancelled."
            return
        if report is not None and report.is_file() and (
            code == 0 or "failing per --fail-on-new-high" in tail
        ):
            try:
                promote_generation(report_base, run_id)
                name = run_repos[0].name
                app.report = load_current_report(report_base, name)
                app.report_generation = run_id
                app.report_repository = repository_key
                app._run_state = GuiRunState.SUCCEEDED
                app.error = None
                _remember(app)
            except (OSError, FileNotFoundError) as exc:
                app._run_state = GuiRunState.FAILED
                app.error = f"Report generated but could not be promoted: {exc}"
        else:
            app._run_state = GuiRunState.FAILED
            detail = tail.strip() or f"Scan exited with code {code} and no report."
            app.error = detail
            if app.missing:
                names = ", ".join(
                    item.get("plugin") or item.get("analyzer_name") or "?"
                    for item in app.missing
                )
                app.error = f"{detail}\nMissing recommended analyzers: {names}"

    env_overlay = child_llm_env(
        app.provider if app.llm_mode not in {"none", ""} else "none",
        app.base_url if app.provider.lower().startswith("openai") else None,
    )
    if is_frozen_build():
        env_overlay[TRUSTED_ONLY_ENV] = "1"

    argv.append("--direct-generation-output")

    report_path = output / ("fleet-summary.json" if fleet else "attackmap-report.json")
    started = app.runner.start(
        run_repos[0],
        output,
        on_progress=on_progress,
        on_done=lambda code, report, tail="": on_done(code, report, tail),
        argv=argv,
        env=env_overlay,
        report_path=report_path,
    )
    if not started:
        app._run_state = GuiRunState.FAILED
        app.error = "Scan could not start because a previous run is still finishing."


def _sync_watch(app: Any) -> None:
    if app.watcher is not None:
        app.watcher.stop()
        app.watcher = None
    if not app.watch or not app.repos:
        return
    out = app.output or reports_dir(app.repos[0])

    watcher = Watcher(
        app.repos[0], out, lambda: None,
        is_running=lambda: app.runner.running,
    )

    def on_quiet() -> None:
        if app.runner.running:
            # A scan is active; remember the burst for exactly one
            # follow-up drained when the run completes.
            watcher.mark_pending()
            return
        _start_scan(app, {})

    watcher.on_quiet = on_quiet
    app.watcher = watcher
    watcher.start()


def _drain_watch_pending(app: Any) -> None:
    with app._lock:
        _drain_watch_pending_locked(app)


def _drain_watch_pending_locked(app: Any) -> None:
    """Start exactly one follow-up scan for changes seen during the last run."""
    watcher = app.watcher
    if not app.watch or watcher is None:
        return
    if app._run_state in {GuiRunState.RUNNING, GuiRunState.CANCELLING}:
        # The active run already reads the changed files; recheck when it ends.
        return
    if app._run_state == GuiRunState.CANCELLED:
        # The user stopped the scan on purpose; do not auto-rescan.
        watcher.take_pending()
        return
    if watcher.take_pending():
        _start_scan_locked(app, {})


def _watch_notice(app: Any, platform: str | None = None) -> str | None:
    """Honest watch-coverage limitation surfaced to the UI; never silent."""
    if not app.watch:
        return None
    if (platform or os.name) != "nt":
        return "Live watching is only implemented on Windows; changes are not detected automatically."
    if app.watcher is not None and app.watcher.limitation:
        return app.watcher.limitation
    if len(app.repos) > 1:
        return f"Watching covers only the first selected repository (1 of {len(app.repos)})."
    return None


def _refresh_missing(app: Any) -> None:
    if not app.repos:
        app.missing = []
        return
    try:
        from attackmap.surfaces.suggest import detect_ecosystems

        app.missing = [
            {"plugin": s.plugin, "analyzer_name": s.analyzer_name, "pip_install": s.pip_install, "signals": list(s.matched_signals)}
            for s in detect_ecosystems(app.repos[0])
            if not s.installed
        ]
    except Exception:
        # Recorded, not swallowed (AC-012): plugin suggestions are advisory,
        # but a persistent failure here should leave a trace in the log.
        logger.warning("Missing-analyzer suggestions failed; continuing without them.",
                       exc_info=True)
        app.missing = []


def _remember(app: Any) -> None:
    if not app.repos or not app.output:
        return
    entry = {"name": app.repos[0].name, "path": str(app.repos[0]), "output": str(app.output)}
    recents = [item for item in _load_recents() if item.get("path") != entry["path"]]
    recents.insert(0, entry)
    app.recents = recents[:_RECENTS_LIMIT]
    path = _recents_path()
    path.write_text(json.dumps(app.recents, indent=2), encoding="utf-8")


def _recents_path() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / ".attackmap")
    folder = Path(base) / "AttackMap"
    folder.mkdir(parents=True, exist_ok=True)
    return folder / "recents.json"


def _load_recents() -> list[dict]:
    path = _recents_path()
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return data if isinstance(data, list) else []


def _pick_folders(multi: bool = False) -> list[str]:
    if threading.current_thread() is not threading.main_thread():
        return []
    try:
        import tkinter as tk
        from tkinter import filedialog
    except ImportError:
        logger.debug("tkinter is unavailable; folder picker disabled.", exc_info=True)
        return []
    try:
        root = tk.Tk()
        root.withdraw()
        root.wm_attributes("-topmost", 1)
        chosen: list[str] = []
        first = filedialog.askdirectory(title="Select a repository")
        if first:
            chosen.append(first)
        while multi:
            nxt = filedialog.askdirectory(title="Add another repository (cancel to finish)")
            if not nxt:
                break
            chosen.append(nxt)
        root.destroy()
        return chosen
    except tk.TclError:
        # Recorded, not swallowed (AC-012): headless/no-display hosts fail here.
        logger.debug("tkinter folder picker failed.", exc_info=True)
        return []
