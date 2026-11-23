"""Live scan progress with ETA (#36).

A repo scan can run for many minutes on a large tree, and a silent terminal
reads as "hung." This renders a single, self-updating status line to stderr:
a bar + percentage + count + ETA during the per-file pass, and an animated
spinner with elapsed time during the indeterminate tail analyzers (taint,
SBOM, authorization, anomalies) — the phase where a big monorepo spends most
of its time.

Zero third-party deps. TTY-aware: when stderr isn't a terminal (CI, piped to
a file) it stays silent so logs aren't polluted with carriage returns. The
scanner drives it through the small hook surface (`begin`/`advance`/`stage`/
`done`); when no progress object is passed, the scan runs exactly as before.
"""

from __future__ import annotations

import json
import sys
import threading
import time
from collections.abc import Callable, Mapping
from datetime import UTC
from typing import Any, TextIO

# NDJSON progress protocol version (consumed by the macOS GUI and other
# non-TTY front-ends). Bump only on a breaking change to the event shape.
PROGRESS_PROTOCOL_VERSION = 1

_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
_BAR_WIDTH = 24
_MIN_REDRAW_INTERVAL = 0.08  # seconds — cap redraws so we don't thrash the TTY


def _fmt_duration(seconds: float) -> str:
    seconds = int(max(0, seconds))
    if seconds >= 3600:
        return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m"
    return f"{seconds // 60:02d}:{seconds % 60:02d}"


class ScanProgress:
    """Render scan progress to a TTY. All methods are no-ops when disabled.

    AR028: every shared-state mutation (counters, label, spinner swap) is
    lock-guarded so concurrent stage/advance callers (parallel scheduler,
    fleet workers) cannot corrupt the counter or leak a spinner thread; the
    stream write itself was already serialized through ``_lock``.
    """

    def __init__(self, *, enabled: bool = True, stream: TextIO | None = None) -> None:
        stream = stream if stream is not None else sys.stderr
        self._stream = stream
        self._enabled = enabled and hasattr(stream, "isatty") and stream.isatty()
        self._total = 0
        self._done = 0
        self._start = 0.0
        self._last_draw = 0.0
        self._last_len = 0
        self._label = ""
        # Spinner thread state for indeterminate stages.
        self._spin_stop: threading.Event | None = None
        self._spin_thread: threading.Thread | None = None
        self._lock = threading.Lock()

    # --- per-file phase ---------------------------------------------------

    def begin(self, total: int, label: str = "Scanning files") -> None:
        if not self._enabled:
            return
        self._stop_spinner()
        with self._lock:
            self._total = max(0, total)
            self._done = 0
            self._label = label
            self._start = time.monotonic()
        self._draw(force=True)

    def advance(self, current: str = "") -> None:
        if not self._enabled:
            return
        with self._lock:
            self._done += 1
        self._draw(current=current)

    # --- indeterminate tail phases ---------------------------------------

    def stage(self, label: str) -> None:
        """Switch to an indeterminate phase with an animated spinner."""
        if not self._enabled:
            return
        self._stop_spinner()
        with self._lock:
            self._label = label
            stop = threading.Event()
            self._spin_stop = stop
            started = time.monotonic()

            def _spin() -> None:
                i = 0
                while not stop.is_set():
                    frame = _SPINNER[i % len(_SPINNER)]
                    with self._lock:
                        self._write(f"{frame} {label}… ({_fmt_duration(time.monotonic() - started)})")
                    i += 1
                    stop.wait(0.12)

            thread = threading.Thread(target=_spin, daemon=True)
            self._spin_thread = thread
            # Start under the lock so a concurrent stage()/done() can never
            # join a thread that has not been started yet.
            thread.start()

    def done(self, summary: str = "") -> None:
        if not self._enabled:
            return
        self._stop_spinner()
        with self._lock:
            self._clear_line()
            if summary:
                self._stream.write(summary + "\n")
            self._stream.flush()

    # --- internals --------------------------------------------------------

    def _stop_spinner(self) -> None:
        # Swap the spinner out under the lock, then stop and join outside it:
        # the spinner thread needs the lock for its final write, so joining
        # while holding the lock would deadlock.
        with self._lock:
            stop, thread = self._spin_stop, self._spin_thread
            self._spin_stop = None
            self._spin_thread = None
        if stop is not None:
            stop.set()
        if thread is not None:
            thread.join(timeout=0.5)

    def _draw(self, *, current: str = "", force: bool = False) -> None:
        now = time.monotonic()
        if not force and (now - self._last_draw) < _MIN_REDRAW_INTERVAL and self._done < self._total:
            return
        self._last_draw = now
        total = self._total or 1
        frac = min(1.0, self._done / total)
        filled = int(_BAR_WIDTH * frac)
        bar = "█" * filled + "░" * (_BAR_WIDTH - filled)
        elapsed = now - self._start
        eta = (elapsed / frac - elapsed) if frac > 0 else 0.0
        tail = f"  {_truncate(current, 32)}" if current else ""
        line = (
            f"{self._label}  [{bar}] {int(frac * 100):3d}%  "
            f"{self._done}/{self._total}  ETA {_fmt_duration(eta)}{tail}"
        )
        with self._lock:
            self._write(line)

    def _write(self, text: str) -> None:
        # Pad to erase any leftover from a previous longer line.
        pad = max(0, self._last_len - len(text))
        self._stream.write("\r" + text + " " * pad)
        self._stream.flush()
        self._last_len = len(text)

    def _clear_line(self) -> None:
        if self._last_len:
            self._stream.write("\r" + " " * self._last_len + "\r")
            self._last_len = 0


def _truncate(text: str, width: int) -> str:
    text = text.replace("\\", "/")
    if len(text) <= width:
        return text
    return "…" + text[-(width - 1):]


class JsonScanProgress:
    """Emit scan progress as newline-delimited JSON (one object per line).

    Same hook surface as ``ScanProgress`` (``begin``/``advance``/``stage``/
    ``done``) so the scanner drives either interchangeably. Unlike the TTY
    renderer this never gates on ``isatty`` — its whole purpose is to feed a
    non-terminal consumer (the macOS GUI) reading the child process's stderr.

    Event shapes (all carry ``"v": PROGRESS_PROTOCOL_VERSION``)::

        {"v":1,"event":"begin","total":1240,"label":"Scanning files"}
        {"v":1,"event":"advance","done":37,"total":1240,"current":"src/app.ts"}
        {"v":1,"event":"stage","label":"Taint analysis"}
        {"v":1,"event":"done","summary":"…","done":1240,"total":1240,"elapsed_s":92.4}

    ``advance`` events are throttled to at most one per ``min_interval`` seconds
    to keep the stream sane on large trees; ``done`` (per-file count) stays
    accurate because every advance still increments the internal counter and the
    latest count rides on each emitted event.

    AR028: counter mutations and stream writes are lock-guarded so concurrent
    callers (parallel scheduler, fleet workers) can never interleave two
    half-written NDJSON lines or tear the advance counter.
    """

    def __init__(self, *, stream: TextIO | None = None, min_interval: float = 0.1) -> None:
        self._stream = stream if stream is not None else sys.stderr
        self._min_interval = max(0.0, min_interval)
        self._total = 0
        self._done = 0
        self._start = 0.0
        self._last_emit = 0.0
        self._lock = threading.Lock()

    def begin(self, total: int, label: str = "Scanning files") -> None:
        with self._lock:
            self._total = max(0, total)
            self._done = 0
            self._start = time.monotonic()
            self._last_emit = self._start  # anchor throttle window to scan start
            self._emit("begin", total=self._total, label=label)

    def advance(self, current: str = "") -> None:
        with self._lock:
            self._done += 1
            now = time.monotonic()
            # Always emit the final file; throttle the rest.
            if self._done < self._total and (now - self._last_emit) < self._min_interval:
                return
            self._last_emit = now
            self._emit("advance", done=self._done, total=self._total, current=current)

    def stage(self, label: str) -> None:
        with self._lock:
            self._emit("stage", label=label)

    def done(self, summary: str = "") -> None:
        elapsed = round(time.monotonic() - self._start, 3) if self._start else 0.0
        with self._lock:
            self._emit(
                "done",
                summary=summary,
                done=self._done,
                total=self._total,
                elapsed_s=elapsed,
            )

    def _emit(self, event: str, **fields: object) -> None:
        payload = {"v": PROGRESS_PROTOCOL_VERSION, "event": event, **fields}
        try:
            self._stream.write(json.dumps(payload, ensure_ascii=False) + "\n")
            self._stream.flush()
        except (ValueError, OSError):
            # Never let a broken/closed pipe take down a scan.
            pass


def create_progress(
    fmt: str = "auto",
    *,
    no_progress: bool = False,
    stream: TextIO | None = None,
):
    """Build the right progress sink for ``--progress-format``.

    - ``none`` (or ``no_progress=True``) → a disabled ``ScanProgress`` no-op.
    - ``json`` → :class:`JsonScanProgress` (NDJSON, always emits).
    - ``auto`` / ``tty`` → :class:`ScanProgress` (TTY bar, self-silences when
      stderr isn't a terminal).
    """
    if no_progress or fmt == "none":
        return ScanProgress(enabled=False, stream=stream)
    if fmt == "json":
        return JsonScanProgress(stream=stream)
    return ScanProgress(enabled=True, stream=stream)


class EventLog:
    """In-memory JSONL run-event log (AR003).

    Records what ran, when, and how it ended, for every published generation
    (``events.jsonl``). Purely additive: stdout progress rendering is
    untouched, and logging failures never abort a scan. Every record carries
    ``ts, run_id, trace_id, stage, event, status``; ``ms`` and ``detail`` are
    attached when known. AR083: ``record(..., extra={...})`` merges additive
    metric fields (e.g. files/signals/budget_skips) without renaming anything.

    AR028 audit: appends, snapshots and flush are serialized through
    ``_lock`` — verified safe for the parallel scheduler's worker threads.
    """

    REQUIRED_FIELDS = ("ts", "run_id", "trace_id", "stage", "event", "status")

    def __init__(self, *, run_id: str, trace_id: str | None = None,
                 clock: Callable[[], str] | None = None) -> None:
        self.run_id = run_id
        self.trace_id = trace_id or run_id
        self._clock = clock or _utc_now_iso
        self._records: list[dict] = []
        self._lock = threading.Lock()

    def record(self, *, stage: str, event: str, status: str,
               ms: int | None = None, detail: str | None = None,
               extra: Mapping[str, Any] | None = None) -> None:
        entry: dict = {
            "ts": self._clock(),
            "run_id": self.run_id,
            "trace_id": self.trace_id,
            "stage": stage,
            "event": event,
            "status": status,
        }
        if ms is not None:
            entry["ms"] = int(ms)
        if detail is not None:
            entry["detail"] = str(detail)[:500]
        if extra:
            # AR083: additive metric payload (files/signals/budget_skips/…).
            # Existing field names are never overwritten — consumers of the
            # pre-AR083 shape keep seeing exactly their known fields.
            for key, value in extra.items():
                if key not in entry:
                    entry[key] = value
        with self._lock:
            self._records.append(entry)

    def stage(self, stage: str, status: str, *, ms: int | None = None,
              detail: str | None = None) -> None:
        self.record(stage=stage, event="stage", status=status, ms=ms, detail=detail)

    def analyzer(self, name: str, status: str, *, stage: str = "scan_and_merge",
                 ms: int | None = None, detail: str | None = None) -> None:
        text = name if detail is None else f"{name}: {str(detail)[:480]}"
        self.record(stage=stage, event="analyzer", status=status, ms=ms, detail=text)

    def records(self) -> list[dict]:
        with self._lock:
            return list(self._records)

    def flush(self, path) -> int:
        """Write every record as JSONL; returns the record count."""
        entries = self.records()
        payload = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in entries)
        with self._lock:
            path.write_text(payload, encoding="utf-8")
        return len(entries)


def _utc_now_iso() -> str:
    from datetime import datetime
    return datetime.now(UTC).isoformat()


__all__ = [
    "PROGRESS_PROTOCOL_VERSION",
    "EventLog",
    "JsonScanProgress",
    "ScanProgress",
    "create_progress",
]
