"""Intra-stage budget cancellation (AR007, AC-010).

A between-stage ceiling that only fires at stage boundaries cannot bound a
30-minute scan stage. ``TimeBudget.tick`` cancels inside the stage, the
partial result survives, and the run still publishes with an explicit
ANALYSIS IS PARTIAL limitation.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from attackmap.errors import BudgetExpired
from attackmap.index import RepoIndex
from attackmap.orchestration.run_spec import BudgetSpec, RunSpec
from attackmap.pipeline import TimeBudget, run_scan
from attackmap.run_budget import active_budget, time_budget_scope
from attackmap.scanner import scan_files


def test_tick_raises_after_deadline_and_silent_before():
    expired = TimeBudget(seconds=0)
    with pytest.raises(BudgetExpired) as excinfo:
        expired.tick("scan_files")
    assert excinfo.value.stage == "scan_files"
    assert excinfo.value.partial is None

    fresh = TimeBudget(seconds=3600)
    fresh.tick("scan_files")  # must not raise


def test_time_budget_scope_sets_and_resets_active_budget():
    assert active_budget() is None
    budget = TimeBudget(seconds=60)
    with time_budget_scope(budget):
        assert active_budget() is budget
    assert active_budget() is None


def test_default_checkpoint_interval_is_about_256_files():
    assert TimeBudget(seconds=60).checkpoint_interval == 256


def test_scan_files_stops_with_partial_result_on_expiry(tmp_path: Path):
    for i in range(600):
        (tmp_path / f"mod_{i}.py").write_text(
            "from flask import Flask\napp = Flask(__name__)\n"
            f"@app.route('/r{i}')\ndef r{i}():\n    return {i}\n",
            encoding="utf-8",
        )
    index = RepoIndex.build(tmp_path)
    with time_budget_scope(TimeBudget(seconds=0)), pytest.raises(BudgetExpired) as excinfo:
        scan_files(tmp_path, suffixes={".py"}, progress=None, index=index)
    partial = excinfo.value.partial
    assert isinstance(partial, object)
    assert getattr(partial, "files_scanned", 0) > 0
    assert partial.files_scanned < 600, "expired budget must stop the per-file pass early"
    assert any("ANALYSIS IS PARTIAL" in note for note in partial.limitations)


def test_index_build_returns_partial_index_on_expiry(tmp_path: Path):
    for i in range(600):
        (tmp_path / f"f_{i}.py").write_text(f"x = {i}\n", encoding="utf-8")
    with time_budget_scope(TimeBudget(seconds=0)):
        index = RepoIndex.build(tmp_path)  # must not raise
    assert len(index.files) < 600
    assert any("ANALYSIS IS PARTIAL" in note for note in index.limitations)


def _big_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "app"
    repo.mkdir()
    body = (
        "from flask import Flask\napp = Flask(__name__)\n\n"
        "@app.route('/users/<int:user_id>', methods=['GET', 'POST'])\n"
        "def users(user_id):\n"
        "    data = request_read(user_id)\n"
        "    return {'id': user_id, 'rows': data}\n\n"
    )
    for i in range(2500):
        (repo / f"views_{i}.py").write_text(body, encoding="utf-8")
    return repo


def test_run_with_expired_budget_publishes_partial_within_ceiling(tmp_path: Path):
    """AC-010: the run stops soon after expiry and publishes a partial result."""
    base = tmp_path / "reports"
    started = time.perf_counter()
    state = run_scan(RunSpec(no_progress=True, budget=BudgetSpec(time_budget_seconds=1)),
                     repo_path=_big_repo(tmp_path), output=base)
    wall = time.perf_counter() - started
    assert state.exit_code == 0
    # AC-010's formal bound (wall <= 10 s for a 5 s budget) is verified on a
    # quiet host at the phase gate; under xdist contention this looser bound
    # still proves the budget bounds the run instead of scanning everything.
    assert wall < 20.0, f"1s budget must not take {wall:.1f}s wall"
    scan = state.scan
    assert scan is not None
    assert any("budget" in note.lower() and "PARTIAL" in note for note in scan.limitations), scan.limitations
    assert any(e.error_type == "time_budget_exceeded" for e in scan.analyzer_errors)
    # The generation was published and carries the event log with the skip.
    pointer = json.loads((base / "current-generation.json").read_text(encoding="utf-8"))
    generation = base / pointer["generation"]
    events = [json.loads(line) for line in
              (generation / "events.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    assert any(r["stage"] == "scan_and_merge" and r["status"] == "skip" for r in events)
