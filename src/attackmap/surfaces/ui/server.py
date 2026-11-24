"""Loopback HTTP server for the Windows GUI (127.0.0.1 only).

AR063 thin adapter: this module keeps the app state (``LoopbackApp``), static
file serving (``/``, ``/index.html``, ``/src/*``), and the HTTP handler shell.
All ``/api/*`` endpoints are declared, schema-gated, and dispatched from the
``attackmap.surfaces.ui.api`` package; the single auth-token check lives in
``api.routes.token_ok`` and is applied by the dispatcher.

The scan orchestration helpers that used to live here are re-exported from
``api.scans`` so existing callers and tests keep their import paths; the module
remains a runnable rollback point — a partial extraction still runs because the
adapter only needs ``api.routes.dispatch``.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import subprocess
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from attackmap.foundation.secrets import has_llm_key

# Imported for their @route registration side effect (AR063): the api.route
# registry is populated when these handler modules load.
from attackmap.surfaces.ui.api import artifacts as _api_artifacts  # noqa: F401
from attackmap.surfaces.ui.api import settings as _api_settings  # noqa: F401
from attackmap.surfaces.ui.api.routes import dispatch
from attackmap.surfaces.ui.api.scans import (
    _apply_config,
    _drain_watch_pending,
    _load_recents,
    _pick_folders,
    _refresh_missing,
    _request_scan_cancel,
    _start_scan,
    _sync_watch,
    _watch_notice,
)
from attackmap.surfaces.ui.contract_adapter import LegacyRunContractAdapter
from attackmap.surfaces.ui.report import (
    GuiReport,
    decode_report,
    fixture_report_path,
    web_root,
)
from attackmap.surfaces.ui.run_state import GuiRunState
from attackmap.surfaces.ui.runner import ScanRunner, child_python_env
from attackmap.surfaces.ui.spawn import discovery_argv
from attackmap.surfaces.ui.watch import Watcher

__all__ = [
    "WEBVIEW2_INSTALL",
    "LoopbackApp",
    "_apply_config",
    "_drain_watch_pending",
    "_handler",
    "_load_recents",
    "_pick_folders",
    "_refresh_missing",
    "_request_scan_cancel",
    "_start_scan",
    "_sync_watch",
    "_watch_notice",
    "load_fixture_app",
    "make_server",
]

WEBVIEW2_INSTALL = "https://go.microsoft.com/fwlink/p/?LinkId=2124703"

logger = logging.getLogger(__name__)


class LoopbackApp:
    def __init__(self, report: GuiReport | None = None) -> None:
        self._lock = threading.RLock()
        self._contract_adapter = LegacyRunContractAdapter()
        self._contract_repository_key = None
        self._repos: list[Path] = []
        self.workspace_revision = 0
        self.token = secrets.token_urlsafe(24)
        self.report = report
        self.report_generation = uuid.uuid4().hex if report else None
        self.report_repository = self.repository_key if report else None
        self.output: Path | None = None
        self._run_state = GuiRunState.IDLE
        self.run_id: str | None = None
        self.progress: dict = {}
        self.exit_code: int | None = None
        self.error: str | None = None
        self.stderr_tail = ""
        self.cve = False
        self.recall = False
        self.llm_mode = "none"
        self.provider = "claude"
        self.model: str | None = None
        self.effort: str | None = None
        self.fast = False
        self.base_url: str = ""
        self.modules: list[str] = []
        self.watch = False
        self.no_suppress = False
        self.use_baseline = True
        self.fail_on_new_high = False
        self.runner = ScanRunner()
        self.watcher: Watcher | None = None
        self.capabilities: set[str] | None = None
        self.available_modules: list[dict] = []
        self._caps_loaded = False
        self.missing: list[dict] = []
        self.recents: list[dict] = _load_recents()

    @property
    def repos(self) -> list[Path]:
        return self._repos

    @repos.setter
    def repos(self, values: list[Path]) -> None:
        with self._lock:
            repos = [p.resolve() for p in values]
            if repos == self._repos:
                return
            self._repos = repos
            self.workspace_revision += 1
            self.report = None
            self.report_generation = None
            self.report_repository = None
            self.output = None
            self.error = None
            self.stderr_tail = ""
            if self._run_state not in {GuiRunState.RUNNING, GuiRunState.CANCELLING}:
                self._run_state = GuiRunState.IDLE
                self.run_id = None
            # Switching workspace/repository must stop the previous watcher
            # (its callback closes over this app and would scan stale state).
            _sync_watch(self)

    @property
    def repository_key(self) -> str:
        return json.dumps([os.path.normcase(str(p)) for p in self._repos])

    def report_snapshot(self) -> dict | None:
        with self._lock:
            if (self.report is None or self.status not in {"idle", "done"}
                    or self.report_repository != self.repository_key):
                return None
            return {
                **self.report.as_json(),
                "repositoryKey": self.report_repository,
                "generationId": self.report_generation,
            }

    @property
    def status(self) -> str:
        """Frontend-compatible status label derived from the run state."""
        status_map = {
            GuiRunState.IDLE: "idle",
            GuiRunState.RUNNING: "running",
            GuiRunState.CANCELLING: "running",
            GuiRunState.SUCCEEDED: "done",
            GuiRunState.FAILED: "failed",
            GuiRunState.CANCELLED: "failed",
        }
        return status_map.get(self._run_state, self._run_state.value)

    def _ensure_caps(self) -> set[str]:
        if self._caps_loaded:
            return self.capabilities or set()
        threading.Thread(target=self._load_caps_bg, daemon=True).start()
        return set()

    def _load_caps_bg(self) -> None:
        if self._caps_loaded:
            return
        caps = _load_capabilities()
        modules = _load_modules()
        self.capabilities = caps
        self.available_modules = modules
        self._caps_loaded = True

    @property
    def repo(self) -> Path | None:
        return self.repos[0] if self.repos else None

    @repo.setter
    def repo(self, value: Path | None) -> None:
        if value is None:
            self.repos = []
        else:
            self.repos = [value]

    def state(self) -> dict:
        with self._lock:
            current_report = (
                self.report if self.status in {"idle", "done"}
                and self.report_repository == self.repository_key else None
            )
            snapshot = {
                "status": self.status,
                "progress": self.progress,
                "exitCode": self.exit_code,
                "error": self.error,
                "stderrTail": self.stderr_tail,
                "repo": str(self.repo) if self.repo else None,
                "repos": [str(p) for p in self.repos],
                "repositoryKey": self.repository_key,
                "runId": self.run_id,
                "reportGeneration": self.report_generation,
                "reportRepositoryKey": self.report_repository,
                "output": str(self.output) if self.output else None,
                "cve": self.cve,
                "recall": self.recall,
                "llm": self.llm_mode,
                "llmMode": self.llm_mode,
                "provider": self.provider,
                "model": self.model,
                "baseUrl": self.base_url,
                "modules": self.modules or ["auto"],
                "watch": self.watch,
                "watchNotice": _watch_notice(self),
                "running": self.runner.running,
                "hasReport": current_report is not None,
                "findingCount": current_report.finding_count if current_report else 0,
                "newCount": current_report.new_count if current_report else 0,
                "resolvedCount": current_report.resolved_count if current_report else 0,
                "capabilities": sorted(self.capabilities) if self.capabilities else [],
                "availableModules": self.available_modules,
                "missingAnalyzers": self.missing,
                "recents": self.recents,
                "hasAnthropicKey": has_llm_key("claude"),
                "hasOpenAIKey": has_llm_key("openai"),
                "llmOffBoxWarning": (
                    "AI sends structured evidence and may include source excerpts to the selected "
                    "provider or endpoint. Local endpoints stay local; remote providers receive the data."
                    if self.llm_mode not in {"none", "None (heuristic only)"}
                    else None
                ),
            }
            contract_snapshot = {**snapshot, "repositoryKey": self._contract_repository_key or self.repository_key}
            snapshot["runContract"] = self._contract_adapter.snapshot(
                contract_snapshot, run_state=self._run_state.value,
            )
            return snapshot


def _handler(app: LoopbackApp):
    root = web_root()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            return

        def _send(self, code: int, body: bytes, content_type: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, payload: object) -> None:
            self._send(code, json.dumps(payload).encode("utf-8"), "application/json; charset=utf-8")

        def _body(self) -> dict:
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            if length < 0 or length > 1_000_000:
                self._json(400, {"error": "invalid body"})
                return {}
            raw = self.rfile.read(length) if length else b"{}"
            try:
                data = json.loads(raw.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                return {}
            return data if isinstance(data, dict) else {}

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path in {"/", "/index.html"}:
                html = (root / "index.html").read_bytes()
                self._send(200, html, "text/html; charset=utf-8")
                return
            if parsed.path.startswith("/src/"):
                rel = parsed.path.lstrip("/")
                path = (root / rel).resolve()
                try:
                    ok = path.is_relative_to(root.resolve())
                except (OSError, ValueError):
                    ok = False
                if not ok or not path.is_file():
                    self._send(404, b"not found", "text/plain")
                    return
                ctype = {
                    ".css": "text/css",
                    ".js": "text/javascript",
                    ".json": "application/json",
                }.get(path.suffix, "application/octet-stream")
                self._send(200, path.read_bytes(), ctype)
                return
            if dispatch(app, self, "GET", parsed):
                return
            self._json(404, {"error": "not found"})

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            if dispatch(app, self, "POST", parsed):
                return
            self._json(404, {"error": "not found"})

    return Handler


def _load_capabilities() -> set[str] | None:
    try:
        raw = subprocess.check_output(
            discovery_argv("capabilities"),
            text=True,
            timeout=20,
            stderr=subprocess.DEVNULL,
            env=child_python_env(),
        )
        payload = json.loads(raw)
        options = set(payload.get("analyze", {}).get("options") or [])
        return options or None
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return None


def _load_modules() -> list[dict]:
    try:
        raw = subprocess.check_output(
            discovery_argv("modules") + ["--json"],
            text=True,
            timeout=20,
            stderr=subprocess.DEVNULL,
            env=child_python_env(),
        )
        data = json.loads(raw)
        return data if isinstance(data, list) else []
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return []


def make_server(app: LoopbackApp, start: bool = True) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _handler(app))
    if start:
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def load_fixture_app() -> LoopbackApp:
    path = fixture_report_path()
    report = decode_report(json.loads(path.read_text(encoding="utf-8")), "juice-shop")
    return LoopbackApp(report)
