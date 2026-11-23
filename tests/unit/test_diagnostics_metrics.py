"""AR083 diagnostics metrics: RunMetrics counters and event-log emission.

Deterministic — no network, no LM Studio. Complements
tests/unit/test_run_events.py (AR003) with the additive metrics record and
the explain-run summarizer.
"""

from __future__ import annotations

import json
import threading

import pytest

from attackmap.diagnostics.metrics import RunMetrics, summarize_run_events
from attackmap.extraction.progress import EventLog

pytestmark = [pytest.mark.unit]


def test_snapshot_accumulates_counters_and_histograms():
    metrics = RunMetrics()
    metrics.record_analyzer("python-web", 12)
    metrics.record_analyzer("python-web", 30)
    metrics.record_analyzer("config", 7)
    metrics.record_stage("scan_and_merge", 100)
    metrics.add_files(42)
    metrics.add_files(8)
    metrics.add_signals(5)
    metrics.record_budget_skip("cve", "time budget of 600s expired")

    snap = metrics.snapshot()
    assert snap["files"] == 50
    assert snap["signals"] == 5
    assert snap["budget_skips"] == [{"stage": "cve", "reason": "time budget of 600s expired"}]
    assert snap["analyzer_ms"]["python-web"] == {"count": 2, "total_ms": 42, "max_ms": 30}
    assert snap["analyzer_ms"]["config"] == {"count": 1, "total_ms": 7, "max_ms": 7}
    assert snap["stage_ms"]["scan_and_merge"]["count"] == 1
    # Defensive: negative samples are clamped, duplicate skips are deduped.
    metrics.record_analyzer("config", -5)
    metrics.record_budget_skip("cve", "time budget of 600s expired")
    snap = metrics.snapshot()
    assert snap["analyzer_ms"]["config"]["total_ms"] == 7
    assert len(snap["budget_skips"]) == 1


def test_emit_events_records_one_additive_metrics_record():
    log = EventLog(run_id="run-1", trace_id="trace-1")
    metrics = RunMetrics()
    metrics.add_files(3)
    metrics.record_stage("publish", 9)

    assert metrics.emit_events(log) is True
    assert metrics.emit_events(log) is False  # idempotent

    rows = log.records()
    assert len(rows) == 1
    row = rows[0]
    # Every event still carries the required identity fields (AC-404).
    assert set(row) >= {"ts", "run_id", "trace_id", "stage", "event", "status"}
    assert row["run_id"] == "run-1"
    assert row["trace_id"] == "trace-1"
    assert row["event"] == "metrics"
    assert row["status"] == "ok"
    assert row["files"] == 3
    assert row["stage_ms"]["publish"]["total_ms"] == 9
    json.dumps(row)  # serializable for events.jsonl


def test_run_metrics_is_thread_safe():
    metrics = RunMetrics()
    def worker(n: int) -> None:
        for i in range(50):
            metrics.record_analyzer(f"a{n}", i)
            metrics.add_files(1)
            metrics.add_signals(1)
    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    snap = metrics.snapshot()
    assert snap["files"] == 200
    assert snap["signals"] == 200
    assert sum(h["count"] for h in snap["analyzer_ms"].values()) == 200


def _synthetic_records() -> list[dict]:
    base = {"run_id": "run-9", "trace_id": "trace-9"}
    return [
        {**base, "ts": "t0", "stage": "select_analyzers", "event": "stage", "status": "start"},
        {**base, "ts": "t1", "stage": "select_analyzers", "event": "stage", "status": "end", "ms": 4},
        {**base, "ts": "t2", "stage": "scan_and_merge", "event": "analyzer", "status": "start",
         "detail": "python-web"},
        {**base, "ts": "t3", "stage": "scan_and_merge", "event": "analyzer", "status": "end",
         "ms": 42, "detail": "python-web"},
        {**base, "ts": "t4", "stage": "scan_and_merge", "event": "stage", "status": "end", "ms": 50},
        {**base, "ts": "t5", "stage": "cve", "event": "stage", "status": "skip",
         "detail": "time budget of 600s expired"},
        {**base, "ts": "t6", "stage": "run_summary", "event": "metrics", "status": "ok",
         "files": 12, "signals": 7, "budget_skips": [
             {"stage": "cve", "reason": "time budget of 600s expired"}],
         "analyzer_ms": {"python-web": {"count": 1, "total_ms": 42, "max_ms": 42}},
         "stage_ms": {"scan_and_merge": {"count": 1, "total_ms": 50, "max_ms": 50}}},
    ]


def test_summarize_run_events_folds_stages_analyzers_skips_and_totals():
    payload = summarize_run_events(_synthetic_records(), generation="run-9")
    assert payload["generation"] == "run-9"
    assert payload["run_id"] == "run-9"
    assert payload["trace_id"] == "trace-9"
    assert payload["records"] == 7
    assert [(s["stage"], s["status"]) for s in payload["stages"]] == [
        ("select_analyzers", "start"),
        ("select_analyzers", "end"),
        ("scan_and_merge", "end"),
        ("cve", "skip"),
    ]
    assert payload["analyzers"] == [
        {"analyzer": "python-web", "status": "start", "ms": None},
        {"analyzer": "python-web", "status": "end", "ms": 42},
    ]
    assert payload["skips"] == [
        {"stage": "cve", "reason": "time budget of 600s expired"},
    ]
    assert payload["totals"]["files"] == 12
    assert payload["totals"]["signals"] == 7
    assert payload["totals"]["budget_skips"] == 1
    assert payload["totals"]["analyzer_ms_total"] == 42
    assert payload["totals"]["stage_ms_total"] == 54
    # The raw additive metrics row is exposed minus the identity fields.
    assert payload["metrics"]["files"] == 12
    assert "run_id" not in payload["metrics"]


def test_summarize_run_events_tolerates_odd_shapes():
    payload = summarize_run_events([
        {"run_id": "a", "trace_id": "b", "ts": "t", "stage": "x",
         "event": "mystery", "status": "ok"},
        {"stage": "loose"},
    ], generation="g")
    assert payload["records"] == 2
    assert payload["run_id"] == "a"
    assert payload["stages"] == []
    assert payload["metrics"] is None
