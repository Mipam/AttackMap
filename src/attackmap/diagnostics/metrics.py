"""Run-scoped metric accumulation and events.jsonl summarization (AR083, AC-404).

``RunMetrics`` is a thread-safe bag of counters/histograms the pipeline fills
while a scan runs (analyzer wall time, files, signals, budget skips, stage
timings) and flushes as ONE additive ``metrics`` record into the existing
``events.jsonl`` sink (``extraction.progress.EventLog``). The event format is
extended additively — existing record fields keep their names and meaning.

``summarize_run_events`` folds a generation's parsed ``events.jsonl`` records
into the payload behind ``attackmap explain-run``.

Leaf module: stdlib only, no ``attackmap`` imports.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping
from typing import Any


def _histogram(values: list[int]) -> dict[str, int]:
    """count/total/max over a list of non-negative millisecond samples."""
    if not values:
        return {"count": 0, "total_ms": 0, "max_ms": 0}
    return {"count": len(values), "total_ms": int(sum(values)), "max_ms": int(max(values))}


class RunMetrics:
    """Counters and histograms for exactly one scan run.

    Every mutator is lock-guarded: the AR027 scheduler pool records analyzer
    timings from worker-adjacent threads, so concurrent recorders must not
    tear a counter. ``snapshot`` returns copies — callers may serialize the
    result without holding the lock.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._analyzer_ms: dict[str, list[int]] = {}
        self._stage_ms: dict[str, list[int]] = {}
        self._files = 0
        self._signals = 0
        self._budget_skips: list[dict[str, str]] = []
        self._emitted = False

    # --- recorders ---------------------------------------------------------

    def record_analyzer(self, name: str, ms: int | float) -> None:
        with self._lock:
            self._analyzer_ms.setdefault(str(name), []).append(max(0, int(ms)))

    def record_stage(self, stage: str, ms: int | float) -> None:
        with self._lock:
            self._stage_ms.setdefault(str(stage), []).append(max(0, int(ms)))

    def add_files(self, count: int) -> None:
        with self._lock:
            self._files += max(0, int(count))

    def add_signals(self, count: int) -> None:
        with self._lock:
            self._signals += max(0, int(count))

    def record_budget_skip(self, stage: str, reason: str) -> None:
        entry = {"stage": str(stage), "reason": str(reason)[:200]}
        with self._lock:
            if entry not in self._budget_skips:
                self._budget_skips.append(entry)

    # --- snapshot / emit ---------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        """A JSON-serializable copy of everything accumulated so far."""
        with self._lock:
            return {
                "files": self._files,
                "signals": self._signals,
                "budget_skips": [dict(item) for item in self._budget_skips],
                "analyzer_ms": {name: _histogram(values)
                                for name, values in sorted(self._analyzer_ms.items())},
                "stage_ms": {stage: _histogram(values)
                             for stage, values in sorted(self._stage_ms.items())},
            }

    def emit_events(self, events: Any, *, stage: str = "run_summary") -> bool:
        """Record one additive ``metrics`` event into an ``EventLog``-like sink.

        The sink only needs ``record(stage=..., event=..., status=...,
        extra=...)`` (duck-typed so this leaf keeps zero attackmap imports).
        Idempotent per instance: a best-effort second flush (e.g. after a
        failed publication) must not duplicate the summary.
        """
        with self._lock:
            if self._emitted:
                return False
            self._emitted = True
        events.record(stage=stage, event="metrics", status="ok", extra=self.snapshot())
        return True


def summarize_run_events(
    records: list[Mapping[str, Any]],
    *,
    generation: str = "",
) -> dict[str, Any]:
    """Fold parsed ``events.jsonl`` records into the ``explain-run`` payload.

    Pure and deterministic: same records in, same dict out. Never raises on
    odd shapes — unknown records are counted, not crashed on.
    """
    run_ids = sorted({str(row["run_id"]) for row in records if row.get("run_id")})
    trace_ids = sorted({str(row["trace_id"]) for row in records if row.get("trace_id")})

    stages: list[dict[str, Any]] = []
    analyzers: list[dict[str, Any]] = []
    skips: list[dict[str, Any]] = []
    metrics_record: dict[str, Any] | None = None
    for row in records:
        event = row.get("event")
        status = str(row.get("status") or "")
        stage = str(row.get("stage") or "")
        if event == "metrics":
            metrics_record = dict(row)
            continue
        if event == "stage":
            stages.append({"stage": stage, "status": status,
                           "ms": row.get("ms"), "detail": row.get("detail")})
            if status == "skip":
                skips.append({"stage": stage, "reason": row.get("detail") or "skipped"})
        elif event == "analyzer":
            name = str(row.get("detail") or "").split(":", 1)[0]
            analyzers.append({"analyzer": name, "status": status, "ms": row.get("ms")})

    analyzer_ms_total = sum(int(row["ms"]) for row in analyzers
                            if isinstance(row.get("ms"), int | float))
    metrics = metrics_record or {}
    return {
        "generation": generation,
        "run_id": run_ids[0] if len(run_ids) == 1 else (run_ids or None),
        "trace_id": trace_ids[0] if len(trace_ids) == 1 else (trace_ids or None),
        "records": len(records),
        "stages": stages,
        "analyzers": analyzers,
        "skips": skips,
        "totals": {
            "events": len(records),
            "files": metrics.get("files"),
            "signals": metrics.get("signals"),
            "budget_skips": len(skips),
            "analyzer_ms_total": analyzer_ms_total,
            "stage_ms_total": sum(int(row["ms"]) for row in stages
                                  if isinstance(row.get("ms"), int | float)),
        },
        "metrics": {
            key: value for key, value in metrics.items()
            if key not in {"ts", "run_id", "trace_id", "stage", "event", "status"}
        } or None,
    }


__all__ = [
    "RunMetrics",
    "summarize_run_events",
]
