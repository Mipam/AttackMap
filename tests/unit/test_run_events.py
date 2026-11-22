"""Structured run event log (AR003, AC-006).

Every published generation must carry ``events.jsonl`` with one record per
pipeline stage and per analyzer, and every record must carry the required
identity fields.
"""

from __future__ import annotations

import json
import threading

from attackmap.pipeline import AnalyzeOptions, run_scan
from attackmap.progress import EventLog

REQUIRED_FIELDS = {"ts", "run_id", "stage", "event", "status"}

_APP = (
    "from flask import Flask, request\n"
    "app = Flask(__name__)\n\n"
    "@app.route('/users/<int:user_id>')\n"
    "def get_user(user_id):\n"
    "    return {'id': user_id}\n"
)


def _repo(tmp_path):
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "app.py").write_text(_APP, encoding="utf-8")
    return repo


def _records(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def test_event_log_records_carry_required_fields():
    counter = iter(range(100))
    log = EventLog(run_id="r1", clock=lambda: f"t{next(counter)}")
    log.stage("scan_and_merge", "start")
    log.stage("scan_and_merge", "end", ms=42, detail="ok")
    log.analyzer("python", "start")
    log.analyzer("python", "end", ms=10)
    rows = log.records()
    assert len(rows) == 4
    for row in rows:
        assert set(row) >= REQUIRED_FIELDS
        assert row["run_id"] == "r1"
        assert row["trace_id"] == "r1"
    assert rows[0]["ts"] == "t0"
    assert rows[1]["ms"] == 42
    assert [r["event"] for r in rows] == ["stage", "stage", "analyzer", "analyzer"]
    assert rows[3]["detail"] == "python"


def test_event_log_flush_writes_jsonl(tmp_path):
    log = EventLog(run_id="flush-1")
    log.stage("publish", "start")
    log.stage("publish", "end", ms=5)
    target = tmp_path / "events.jsonl"
    count = log.flush(target)
    assert count == 2
    rows = _records(target)
    assert [r["status"] for r in rows] == ["start", "end"]
    # Flush again is idempotent: the same records, not duplicated.
    assert log.flush(target) == 2


def test_event_log_is_thread_safe():
    log = EventLog(run_id="threads")
    def worker(n):
        for i in range(50):
            log.record(stage="scan_and_merge", event="analyzer", status="end", ms=i)
    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(log.records()) == 200


def test_published_generation_contains_events_jsonl(tmp_path):
    """AC-006: a published generation explains what ran and how it ended."""
    base = tmp_path / "reports"
    options = AnalyzeOptions(repo_path=_repo(tmp_path), output=base, no_progress=True)
    state = run_scan(options)
    assert state.exit_code == 0
    pointer = json.loads((base / "current-generation.json").read_text(encoding="utf-8"))
    generation = base / pointer["generation"]
    events_path = generation / "events.jsonl"
    assert events_path.is_file(), "published generation lacks events.jsonl"

    rows = _records(events_path)
    assert rows, "empty event log"
    for row in rows:
        assert set(row) >= REQUIRED_FIELDS, f"missing required fields: {row}"
    assert all(row["run_id"] == pointer["generation"] for row in rows)

    # One record per pipeline stage: every timed stage both started and ended.
    # The 'publication' stage is the one exception by construction: the log is
    # flushed before the pointer swap it finalizes, so it can carry only its
    # own 'start' — a log cannot record its own completion.
    stage_names = {r["stage"] for r in rows if r["event"] == "stage"}
    assert {"select_analyzers", "scan_and_merge", "translate", "publish"} <= stage_names
    starts = {(r["stage"], r["status"]) for r in rows}
    for name in stage_names - {"publication"}:
        assert (name, "start") in starts and (name, "end") in starts
    assert ("publication", "start") in starts

    # Analyzers: at least one ran, and every run has an end record.
    analyzer_rows = [r for r in rows if r["event"] == "analyzer"]
    assert analyzer_rows, "no analyzer records"
    assert any(r["status"] == "start" for r in analyzer_rows)
    assert any(r["status"] == "end" for r in analyzer_rows)
    started = {r["detail"] for r in analyzer_rows if r["status"] == "start"}
    ended = {r["detail"] for r in analyzer_rows if r["status"] == "end"}
    assert started == ended, f"unbalanced analyzer events: {started} vs {ended}"


def test_failed_publication_still_writes_events(tmp_path, monkeypatch):
    """A failing publication leaves the event log next to the diagnostic."""
    from attackmap import artifact_publisher

    base = tmp_path / "reports"
    options = AnalyzeOptions(repo_path=_repo(tmp_path), output=base, no_progress=True)

    def explode(b, r, **kwargs):
        raise ValueError("publication boom")

    monkeypatch.setattr(artifact_publisher, "publish_generation", explode)
    import pytest
    with pytest.raises(ValueError):
        run_scan(options)
    # The staged generation folder (never committed) still has the log.
    logs = list(base.glob("*/events.jsonl"))
    assert logs, "failed run wrote no events.jsonl"
    rows = _records(logs[0])
    assert any(r["event"] == "stage" and r["status"] in {"failed", "error"} for r in rows)
