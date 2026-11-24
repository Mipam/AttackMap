"""AC-306: no cross-thread UI calls — the GUI API never touches tkinter off
the process main thread.

The HTTP server is a ``ThreadingHTTPServer``, so every ``/api/*`` handler
executes on a worker thread. AR064 routes all native dialog work through
``surfaces.ui.dialogs.MainThreadDispatcher``; this suite proves, at three
levels, that the dialog backend therefore only ever executes on the main
thread:

1. static — no tkinter call site exists outside ``dialogs.py``;
2. unit-dispatch — a fake backend records the thread of every dialog call
   while requests originate on worker threads;
3. end-to-end — real HTTP POSTs to ``/api/pick``, ``/api/pick-save`` and
   ``/api/reveal`` on a live loopback server, with the main-thread pump
   running on the test thread.

Run: ``pytest tests/integration/test_ui_threading.py -v``
"""

from __future__ import annotations

import json
import re
import threading
import time
from collections.abc import Callable
from pathlib import Path
from urllib.request import Request, urlopen

import pytest

from attackmap.surfaces.ui import dialogs
from attackmap.surfaces.ui.server import LoopbackApp, make_server

SRC_UI = Path(__file__).resolve().parents[2] / "src" / "attackmap" / "surfaces" / "ui"

TK_CALL_SITE = re.compile(
    r"import tkinter|from tkinter|filedialog\.|askdirectory\(|asksaveasfilename\(|"
    r"askopenfilename\(|tk\.Tk\(|TclError"
)


class _Pump:
    """Stand-in for the Tk/WebView main loop: thunks run only when the main
    thread drains them — exactly the guarantee AC-306 requires."""

    def __init__(self) -> None:
        self._pending: list[Callable[[], None]] = []
        self._lock = threading.Lock()

    def hook(self, thunk: Callable[[], None]) -> None:
        with self._lock:
            self._pending.append(thunk)

    def drain(self) -> None:
        while True:
            with self._lock:
                if not self._pending:
                    return
                thunk = self._pending.pop(0)
            thunk()

    def run_until(self, done: threading.Event, timeout: float = 10.0) -> None:
        deadline = time.monotonic() + timeout
        while not done.is_set() and time.monotonic() < deadline:
            self.drain()
            time.sleep(0.005)
        self.drain()
        assert done.is_set(), "main-thread pump was never collected"


class _RecordingDialogs:
    """PlatformDialogs stand-in recording the thread each operation ran on."""

    def __init__(self) -> None:
        self.threads: dict[str, threading.Thread] = {}
        self.calls: list[tuple[str, tuple[object, ...]]] = []

    def _record(self, name: str, *args: object) -> None:
        self.threads[name] = threading.current_thread()
        self.calls.append((name, args))

    def pick_dir(self, multi: bool = False) -> list[str]:
        self._record("pick_dir", multi)
        return [r"C:\picked\repo"]

    def pick_file(self, title: str = "Select a file") -> str | None:
        self._record("pick_file", title)
        return None

    def save_file(self, suggested_name: str = "") -> str | None:
        self._record("save_file", suggested_name)
        return r"C:\picked\report.md"

    def reveal(self, path: str) -> bool:
        self._record("reveal", path)
        return True


@pytest.fixture
def wired_dialogs(monkeypatch: pytest.MonkeyPatch):
    pump = _Pump()
    dispatcher = dialogs.MainThreadDispatcher(timeout=10.0)
    dispatcher.install_hook(pump.hook)
    fake = _RecordingDialogs()
    monkeypatch.setattr(dialogs, "_default_dispatcher", dispatcher)
    monkeypatch.setattr(dialogs, "_default_dialogs", fake)
    return pump, fake


def test_no_tkinter_call_site_outside_dialogs_module() -> None:
    """Static assertion: handlers/adapter never call tkinter directly."""
    offenders = []
    for path in SRC_UI.rglob("*.py"):
        if path.name == "dialogs.py":
            continue
        if TK_CALL_SITE.search(path.read_text(encoding="utf-8")):
            offenders.append(str(path.relative_to(SRC_UI)))
    assert offenders == [], f"tkinter call sites outside dialogs.py: {offenders}"


def test_dialogs_module_asserts_main_thread() -> None:
    """dialogs.py must guard every tkinter entry with a main-thread check."""
    source = (SRC_UI / "dialogs.py").read_text(encoding="utf-8")
    assert source.count("_require_main_thread()") >= 3
    assert "threading.current_thread() is not threading.main_thread()" in source


def test_worker_thread_dialog_requests_execute_on_main_thread(wired_dialogs) -> None:
    """Dispatch-level proof: requests from worker threads run the backend on
    the main thread (the pump only drains there)."""
    pump, fake = wired_dialogs
    done = threading.Event()

    def worker() -> None:
        assert dialogs.pick_folders(multi=True) == [r"C:\picked\repo"]
        assert dialogs.save_path("report.md") == r"C:\picked\report.md"
        assert dialogs.reveal_path(r"C:\out") is True
        done.set()

    thread = threading.Thread(target=worker)
    thread.start()
    pump.run_until(done)
    thread.join(10)
    assert not thread.is_alive()
    assert set(fake.threads) == {"pick_dir", "save_file", "reveal"}
    for name, thread_run in fake.threads.items():
        assert thread_run is threading.main_thread(), (
            f"AC-306 violation: {name} executed on {thread_run.name}"
        )


def test_http_dialog_endpoints_run_backend_on_main_thread(
    wired_dialogs, tmp_path: Path
) -> None:
    """End-to-end proof over a live ThreadingHTTPServer: the dialog backend
    executes on the main thread while responses keep their wire shape."""
    pump, fake = wired_dialogs
    app = LoopbackApp()
    output = tmp_path / "reports"
    output.mkdir()
    app.output = output
    httpd = make_server(app, start=True)
    done = threading.Event()
    results: dict[str, object] = {}

    def client() -> None:
        base = f"http://127.0.0.1:{httpd.server_address[1]}"
        headers = {
            "Content-Type": "application/json",
            "X-AttackMap-Token": app.token,
        }

        def post(path: str, body: dict) -> tuple[int, dict]:
            req = Request(
                base + path,
                data=json.dumps(body).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            with urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))

        try:
            results["pick"] = post("/api/pick", {"multi": True})
            results["pick_save"] = post("/api/pick-save", {"suggestedName": "r.md"})
            results["reveal"] = post("/api/reveal", {})
        finally:
            done.set()

    thread = threading.Thread(target=client)
    thread.start()
    try:
        pump.run_until(done)
    finally:
        thread.join(10)
        httpd.shutdown()
        httpd.server_close()

    code, body = results["pick"]
    assert code == 200
    assert body["picked"] == [r"C:\picked\repo"]
    code, body = results["pick_save"]
    assert code == 200
    assert body["path"] == r"C:\picked\report.md"
    code, body = results["reveal"]
    assert code == 200
    assert body["status"] == app.status
    # The decisive AC-306 assertion: every backend call ran on the main thread,
    # even though the HTTP handlers themselves ran on server worker threads.
    for name, thread_run in fake.threads.items():
        assert thread_run is threading.main_thread(), (
            f"AC-306 violation: {name} executed on {thread_run.name}"
        )


def test_http_pick_without_pump_keeps_pre_ar064_deferred_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No main-loop hook installed (browser fallback): /api/pick still returns
    200 with an empty selection, exactly as the pre-AR064 off-thread guard did."""
    monkeypatch.setattr(dialogs, "_default_dispatcher", dialogs.MainThreadDispatcher())
    app = LoopbackApp()
    httpd = make_server(app, start=True)
    try:
        req = Request(
            f"http://127.0.0.1:{httpd.server_address[1]}/api/pick",
            data=json.dumps({"multi": False}).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-AttackMap-Token": app.token},
            method="POST",
        )
        with urlopen(req, timeout=10) as resp:
            assert resp.status == 200
            body = json.loads(resp.read().decode("utf-8"))
        assert body["picked"] == []
        assert "status" in body
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_tk_hook_delivers_to_a_real_tk_mainloop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Smoke the real Tk vehicle (root.after) when a display is available;
    skipped on headless hosts, where the dispatcher tests above still prove
    the threading contract."""
    tk = pytest.importorskip("tkinter")
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("no display available for a real Tk mainloop")
    fake = _RecordingDialogs()
    monkeypatch.setattr(dialogs, "_default_dialogs", fake)
    dispatcher = dialogs.MainThreadDispatcher(timeout=10.0)
    dispatcher.install_tk_hook(root)
    monkeypatch.setattr(dialogs, "_default_dispatcher", dispatcher)
    root.withdraw()
    done = threading.Event()

    def worker() -> None:
        dialogs.pick_folders(multi=False)
        done.set()

    thread = threading.Thread(target=worker)
    thread.start()
    deadline = time.monotonic() + 10
    try:
        while not done.is_set() and time.monotonic() < deadline:
            root.update()
            time.sleep(0.005)
        assert done.is_set(), "Tk mainloop never collected the dialog"
        assert fake.threads["pick_dir"] is threading.main_thread()
    finally:
        thread.join(10)
        root.destroy()
