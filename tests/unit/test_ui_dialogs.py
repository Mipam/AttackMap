"""Unit tests for the AR064 main-thread dialog dispatcher (AC-306 support).

The integration proof lives in tests/integration/test_ui_threading.py; these
tests cover the dispatcher mechanics and the handler seams directly.
"""

from __future__ import annotations

import builtins
import re
import threading
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from attackmap.surfaces.ui import dialogs
from attackmap.surfaces.ui.api import artifacts, scans


class _Pump:
    """Test main loop: collects thunks via the hook, runs them on demand."""

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

    def run_until_idle(self, done: threading.Event, timeout: float = 5.0) -> None:
        deadline = time.monotonic() + timeout
        while not done.is_set() and time.monotonic() < deadline:
            self.drain()
            time.sleep(0.005)
        self.drain()


class _RecordingDialogs:
    """Fake PlatformDialogs recording the thread each call runs on."""

    def __init__(self) -> None:
        self.threads: dict[str, threading.Thread] = {}
        self.values = {"pick_dir": [r"C:\repos\one"], "save_file": r"C:\out.md",
                       "pick_file": r"C:\in.txt", "reveal": True}

    def _record(self, name: str) -> None:
        self.threads[name] = threading.current_thread()

    def pick_dir(self, multi: bool = False) -> list[str]:
        self._record("pick_dir")
        assert multi is True or multi is False
        return list(self.values["pick_dir"])

    def pick_file(self, title: str = "Select a file") -> str | None:
        self._record("pick_file")
        return str(self.values["pick_file"])

    def save_file(self, suggested_name: str = "") -> str | None:
        self._record("save_file")
        return str(self.values["save_file"])

    def reveal(self, path: str) -> bool:
        self._record("reveal")
        return bool(self.values["reveal"])


@pytest.fixture
def wired(monkeypatch: pytest.MonkeyPatch):
    """Replace the process-wide dispatcher/dialogs with pump + fake backend."""
    pump = _Pump()
    dispatcher = dialogs.MainThreadDispatcher(timeout=5.0)
    dispatcher.install_hook(pump.hook)
    fake = _RecordingDialogs()
    monkeypatch.setattr(dialogs, "_default_dispatcher", dispatcher)
    monkeypatch.setattr(dialogs, "_default_dialogs", fake)
    return pump, dispatcher, fake


def _run_worker(fn: Callable[[], object]) -> tuple[object, threading.Thread]:
    box: dict[str, object] = {}

    def target() -> None:
        box["result"] = fn()

    worker = threading.Thread(target=target)
    worker.start()
    return box, worker


def test_dispatcher_runs_inline_on_main_thread() -> None:
    dispatcher = dialogs.MainThreadDispatcher()
    assert dispatcher.run_on_main(lambda: threading.current_thread()) is threading.main_thread()


def test_dispatcher_off_thread_without_hook_raises_no_main_loop() -> None:
    dispatcher = dialogs.MainThreadDispatcher()
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            dispatcher.run_on_main(lambda: None)
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join(5)
    assert any(isinstance(e, dialogs.NoMainLoopError) for e in errors)


def test_dispatcher_delivers_work_to_main_thread(wired) -> None:
    pump, _, fake = wired
    done = threading.Event()

    def request() -> None:
        result = dialogs.pick_folders(multi=False)
        assert result == [r"C:\repos\one"]
        done.set()

    worker = threading.Thread(target=request)
    worker.start()
    pump.run_until_idle(done)
    worker.join(5)
    assert not worker.is_alive()
    assert done.is_set()
    assert fake.threads["pick_dir"] is threading.main_thread()


def test_all_dialog_ops_execute_on_main_thread(wired) -> None:
    pump, _, fake = wired
    done = threading.Event()
    calls = {
        "pick_dir": lambda: dialogs.pick_folders(multi=True),
        "pick_file": None,
        "save_file": lambda: dialogs.save_path("report.md"),
        "reveal": lambda: dialogs.reveal_path(r"C:\out"),
    }

    def request() -> None:
        calls["pick_dir"]()
        calls["save_file"]()
        calls["reveal"]()
        done.set()

    worker = threading.Thread(target=request)
    worker.start()
    pump.run_until_idle(done)
    worker.join(5)
    assert done.is_set()
    for name, thread in fake.threads.items():
        assert thread is threading.main_thread(), f"{name} ran off the main thread"


def test_tk_dialogs_refuse_off_main_thread_before_importing_tkinter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The main-thread assertion must fire before tkinter is even imported."""
    real_import = builtins.__import__
    tk_touched: list[str] = []

    def _spy(name: str, *args: object, **kwargs: object) -> object:
        if name == "tkinter" or name.startswith("tkinter."):
            tk_touched.append(name)
        return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(builtins, "__import__", _spy)
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            dialogs.TkDialogs().pick_dir()
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join(5)
    assert any(isinstance(e, RuntimeError) for e in errors)
    assert tk_touched == []


def test_handler_pick_folders_records_unavailable(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """scans._pick_folders keeps the AR012 record when tkinter is missing."""
    import logging

    real_import = builtins.__import__

    def _no_tk(name: str, *args: object, **kwargs: object) -> object:
        if name == "tkinter" or name.startswith("tkinter."):
            raise ImportError("No module named 'tkinter'")
        return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(builtins, "__import__", _no_tk)
    with caplog.at_level(logging.DEBUG, logger="attackmap.surfaces.ui.api.scans"):
        assert scans._pick_folders() == []
    assert any("tkinter is unavailable" in r.message for r in caplog.records)


def test_handler_pick_save_defers_without_hook(caplog: pytest.LogCaptureFixture) -> None:
    """Off-thread save request without a pump yields the pre-AR064 None."""
    import logging

    monkey_free = dialogs.get_dispatcher()  # process-wide; no hook installed
    assert monkey_free.has_hook() is False
    import threading as _t

    box: dict[str, object] = {}

    def worker() -> None:
        box["value"] = artifacts._pick_save_path("report.md")

    caplog.clear()
    with caplog.at_level(logging.DEBUG, logger="attackmap.surfaces.ui.api.artifacts"):
        thread = _t.Thread(target=worker)
        thread.start()
        thread.join(5)
    assert box["value"] is None
    assert any("save dialog" in r.message for r in caplog.records)


def test_reveal_uses_backend_directly_when_no_hook(monkeypatch: pytest.MonkeyPatch) -> None:
    """Browser-fallback (no pump): reveal runs inline off-thread, no tkinter."""
    fake = _RecordingDialogs()
    monkeypatch.setattr(dialogs, "_default_dispatcher", dialogs.MainThreadDispatcher())
    monkeypatch.setattr(dialogs, "_default_dialogs", fake)
    assert dialogs.reveal_path(r"C:\out") is True


def test_reveal_dispatched_when_hook_installed(wired) -> None:
    pump, _, fake = wired
    done = threading.Event()

    def worker() -> None:
        dialogs.reveal_path(r"C:\out")
        done.set()

    thread = threading.Thread(target=worker)
    thread.start()
    pump.run_until_idle(done)
    thread.join(5)
    assert fake.threads["reveal"] is threading.main_thread()


def test_source_of_truth_dialogs_is_only_tkinter_user() -> None:
    """Static tripwire: no tkinter *call* outside dialogs.py (log strings and
    the PDF-lane comment in artifacts.py may still mention the word)."""
    ui_root = Path(__file__).resolve().parents[2] / "src" / "attackmap" / "surfaces" / "ui"
    call_sites = re.compile(
        r"import tkinter|from tkinter|filedialog\.|askdirectory\(|asksaveasfilename\(|"
        r"askopenfilename\(|tk\.Tk\(|TclError"
    )
    offenders = []
    for path in ui_root.rglob("*.py"):
        if path.name == "dialogs.py":
            continue
        if call_sites.search(path.read_text(encoding="utf-8")):
            offenders.append(path.name)
    assert offenders == [], f"tkinter call sites outside dialogs.py: {offenders}"
