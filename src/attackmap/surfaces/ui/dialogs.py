"""Main-thread dialog dispatch for the GUI API (AR064 / AC-306).

HTTP handlers run on ``ThreadingHTTPServer`` worker threads, but every
tkinter call must execute on the thread that owns the GUI toolkit — on this
host that is the process main thread (Tk roots are created transiently per
dialog, and under WebView2 ``webview.start()`` also blocks on the main
thread; the no-WebView2 browser fallback parks the main thread in
``threading.Event().wait()``, see ``surfaces/ui/launch.py``).

This module is the only place the GUI API may touch tkinter:

- :class:`PlatformDialogs` — the native-dialog operations the API needs
  (``pick_dir``, ``pick_file``, ``save_file``, ``reveal``).
- :class:`TkDialogs` — the default tkinter-backed implementation; every
  method hard-asserts the main thread *before* importing tkinter, so an
  off-thread call can never reach the toolkit.
- :class:`MainThreadDispatcher` — routes callables to the main thread. When
  the caller already is the main thread the callable runs inline; otherwise
  it is handed to an installed main-loop hook (Tk ``root.after``, a WebView
  pump, or a test pump) and awaited. With no hook installed the request is
  rejected with :class:`NoMainLoopError`, and callers fall back to the
  pre-AR064 deferred behavior (empty result plus a debug record).

Wire format: none of this changes any HTTP response shape; the handlers
still return ``200`` with the same payloads, where an undeliverable dialog
request produces the same empty selection the pre-AR064 off-thread code did.
"""

from __future__ import annotations

import logging
import os
import threading
from collections.abc import Callable
from typing import Any, Protocol

logger = logging.getLogger(__name__)


class DialogError(Exception):
    """Base class for dialog dispatch failures."""


class DialogBackendUnavailable(DialogError):
    """The native dialog backend (tkinter/display) is not usable."""


class NoMainLoopError(DialogError):
    """Off-thread dialog request while no main-thread pump hook is installed."""


class DialogDispatchTimeout(DialogError):
    """The main thread did not collect a dispatched dialog in time."""


class PlatformDialogs(Protocol):
    """Native dialog operations used by the GUI API handlers."""

    def pick_dir(self, multi: bool = False) -> list[str]: ...

    def pick_file(self, title: str = "Select a file") -> str | None: ...

    def save_file(self, suggested_name: str = "") -> str | None: ...

    def reveal(self, path: str) -> bool: ...


MainHook = Callable[[Callable[[], None]], None]
"""Schedules a thunk to run on the GUI main thread (e.g. Tk ``root.after``)."""


class MainThreadDispatcher:
    """Posts work to the thread that owns the GUI toolkit (AC-306).

    The HTTP server is a ``ThreadingHTTPServer``, so handlers run on worker
    threads; dialog work submitted from there is wrapped, handed to the
    installed :data:`MainHook`, and awaited with a timeout. Known dialog
    failures (:class:`DialogBackendUnavailable`, :class:`RuntimeError` from
    the main-thread assertion) are transported back to the waiting thread so
    handlers can record them exactly where the pre-AR064 code did.
    """

    def __init__(self, timeout: float = 30.0) -> None:
        self._hook: MainHook | None = None
        self._timeout = timeout

    def install_hook(self, hook: MainHook | None) -> None:
        """Register (or clear, with ``None``) the main-thread pump hook."""
        self._hook = hook

    def has_hook(self) -> bool:
        return self._hook is not None

    @staticmethod
    def is_main_thread() -> bool:
        return threading.current_thread() is threading.main_thread()

    def run_on_main(self, fn: Callable[[], Any]) -> Any:
        """Run ``fn`` on the main thread, blocking until it completes.

        Main-thread callers run inline (preserving the pre-AR064 behavior
        for direct calls). Off-thread callers require an installed hook;
        without one :class:`NoMainLoopError` is raised so the caller can
        degrade to the documented deferred response.
        """
        if self.is_main_thread():
            return fn()
        hook = self._hook
        if hook is None:
            raise NoMainLoopError(
                "dialog requested off the main thread with no main-loop hook installed"
            )
        done = threading.Event()
        box: dict[str, Any] = {}

        def wrapped() -> None:
            try:
                box["value"] = fn()
            except (DialogBackendUnavailable, RuntimeError) as exc:
                box["error"] = exc
            finally:
                done.set()

        hook(wrapped)
        if not done.wait(self._timeout):
            raise DialogDispatchTimeout("main thread did not collect the dialog in time")
        if "error" in box:
            raise box["error"]
        return box.get("value")

    def install_tk_hook(self, root: Any, poll_ms: int = 50) -> None:
        """Pump dispatched work through a persistent Tk root's ``after`` queue.

        ``root.after`` is only safe from the thread that owns the Tk
        interpreter, so worker threads never call it: they enqueue onto a
        thread-safe queue, and a repeating ``after`` chain installed from the
        main thread drains it. Call while the Tk mainloop is (or will be)
        running on the main thread.
        """
        import queue
        import tkinter as tk
        from contextlib import suppress

        pending: queue.Queue[Callable[[], None]] = queue.Queue()

        def pump() -> None:
            try:
                while True:
                    try:
                        pending.get_nowait()()
                    except queue.Empty:
                        break
            finally:
                with suppress(tk.TclError):
                    root.after(poll_ms, pump)  # root destroyed ends the chain.

        self.install_hook(pending.put)
        root.after(poll_ms, pump)


class TkDialogs:
    """tkinter-backed :class:`PlatformDialogs`; main-thread only (AC-306)."""

    @staticmethod
    def _require_main_thread() -> None:
        if threading.current_thread() is not threading.main_thread():
            raise RuntimeError("tkinter dialogs must run on the process main thread")

    @staticmethod
    def _tk() -> tuple[Any, Any]:
        try:
            import tkinter as tk
            from tkinter import filedialog
        except ImportError as exc:
            raise DialogBackendUnavailable("tkinter is unavailable") from exc
        return tk, filedialog

    def pick_dir(self, multi: bool = False) -> list[str]:
        self._require_main_thread()
        tk, filedialog = self._tk()
        try:
            root = tk.Tk()
        except tk.TclError as exc:
            raise DialogBackendUnavailable("tkinter display unavailable") from exc
        try:
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
            return chosen
        except tk.TclError as exc:
            raise DialogBackendUnavailable("tkinter folder picker failed") from exc
        finally:
            root.destroy()

    def pick_file(self, title: str = "Select a file") -> str | None:
        self._require_main_thread()
        tk, filedialog = self._tk()
        try:
            root = tk.Tk()
        except tk.TclError as exc:
            raise DialogBackendUnavailable("tkinter display unavailable") from exc
        try:
            root.withdraw()
            root.wm_attributes("-topmost", 1)
            return filedialog.askopenfilename(title=title) or None
        except tk.TclError as exc:
            raise DialogBackendUnavailable("tkinter file picker failed") from exc
        finally:
            root.destroy()

    def save_file(self, suggested_name: str = "") -> str | None:
        self._require_main_thread()
        tk, filedialog = self._tk()
        try:
            root = tk.Tk()
        except tk.TclError as exc:
            raise DialogBackendUnavailable("tkinter display unavailable") from exc
        try:
            root.withdraw()
            root.wm_attributes("-topmost", 1)
            chosen = filedialog.asksaveasfilename(
                title="Save report",
                defaultextension=".md",
                initialfile=suggested_name or "attackmap-report.md",
                filetypes=[("Markdown files", "*.md"), ("PDF files", "*.pdf"), ("All files", "*.*")],
            )
            return chosen if chosen else None
        except tk.TclError as exc:
            raise DialogBackendUnavailable("tkinter save dialog failed") from exc
        finally:
            root.destroy()

    def reveal(self, path: str) -> bool:
        """Open ``path`` in the system shell; never raises for a bad target."""
        if not hasattr(os, "startfile"):
            return False
        try:
            os.startfile(path)
        except OSError:
            logger.debug("reveal failed for %s", path, exc_info=True)
            return False
        return True


_default_dispatcher = MainThreadDispatcher()
_default_dialogs: PlatformDialogs = TkDialogs()


def get_dispatcher() -> MainThreadDispatcher:
    """The process-wide dispatcher used by the API handlers (test seam)."""
    return _default_dispatcher


def set_dispatcher(dispatcher: MainThreadDispatcher) -> None:
    global _default_dispatcher
    _default_dispatcher = dispatcher


def get_dialogs() -> PlatformDialogs:
    """The process-wide dialog backend (test seam)."""
    return _default_dialogs


def set_dialogs(dialogs: PlatformDialogs) -> None:
    global _default_dialogs
    _default_dialogs = dialogs


def pick_folders(multi: bool = False) -> list[str]:
    """Folder picker, dispatched to the main thread (empty list = none)."""
    return get_dispatcher().run_on_main(lambda: get_dialogs().pick_dir(multi=multi))


def save_path(suggested_name: str) -> str | None:
    """Save dialog, dispatched to the main thread (None = cancelled)."""
    return get_dispatcher().run_on_main(lambda: get_dialogs().save_file(suggested_name))


def reveal_path(path: str) -> bool:
    """Reveal a path in the system shell.

    Dispatched when a main-thread pump exists; with no pump installed (the
    browser-fallback launch parks the main thread in ``Event().wait()``) it
    runs inline even off-thread, because ``os.startfile`` touches no GUI
    toolkit and is safe to call from worker threads.
    """
    dispatcher = get_dispatcher()
    if dispatcher.has_hook() or dispatcher.is_main_thread():
        return dispatcher.run_on_main(lambda: get_dialogs().reveal(path))
    return get_dialogs().reveal(path)
