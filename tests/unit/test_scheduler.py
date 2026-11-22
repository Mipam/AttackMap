"""Analyzer execution scheduler (AR027, AC-107/AC-108).

Locks the scheduler contract: partition preserves the resolved plan order,
``workers=1`` runs inline with no pool (the serial-behaviour guarantee),
higher worker counts stay bounded, outcomes are keyed by analyzer name with
errors captured per job, and the RunSpec surface carries ``scheduler.workers``
with a serial default.
"""

from __future__ import annotations

import threading
import time
from dataclasses import FrozenInstanceError

import pytest

from attackmap.orchestration import scheduler
from attackmap.orchestration.run_spec import RunSpec, SchedulerSpec


class _Analyzer:
    def __init__(self, name: str, *, isolated: bool) -> None:
        self.name = name
        self._isolated = isolated


def _plan() -> list[_Analyzer]:
    # Resolved (priority, name) order: in-process first, then isolated.
    return [
        _Analyzer("a-in-1", isolated=False),
        _Analyzer("b-in-2", isolated=False),
        _Analyzer("c-iso-1", isolated=True),
        _Analyzer("d-iso-2", isolated=True),
    ]


def test_partition_preserves_plan_order_in_both_groups():
    in_process, isolated = scheduler.partition(_plan(), is_isolated=lambda a: a._isolated)
    assert [a.name for a in in_process] == ["a-in-1", "b-in-2"]
    assert [a.name for a in isolated] == ["c-iso-1", "d-iso-2"]


def test_workers_one_runs_inline_without_pool(monkeypatch: pytest.MonkeyPatch):
    """The serial contract: workers=1 must never construct a pool."""

    def _forbidden(*args, **kwargs):  # pragma: no cover - fail loud
        raise AssertionError("workers=1 must not spawn a ThreadPoolExecutor")

    monkeypatch.setattr(scheduler, "ThreadPoolExecutor", _forbidden)
    threads: list[int] = []
    jobs = [(f"job-{i}", (lambda i=i: threads.append(threading.get_ident()) or i))
            for i in range(3)]
    outcomes = scheduler.run_group(jobs, workers=1)
    caller = threading.get_ident()
    assert all(thread == caller for thread in threads), "inline execution expected"
    assert {name: outcome.value for name, outcome in outcomes.items()} == {
        "job-0": 0, "job-1": 1, "job-2": 2,
    }


def test_pool_concurrency_is_bounded_by_workers():
    lock = threading.Lock()
    state = {"current": 0, "peak": 0}

    def job() -> int:
        with lock:
            state["current"] += 1
            state["peak"] = max(state["peak"], state["current"])
        time.sleep(0.05)  # give other workers a chance to enter
        with lock:
            state["current"] -= 1
        return 1

    jobs = [(f"job-{i}", job) for i in range(8)]
    outcomes = scheduler.run_group(jobs, workers=3)
    assert len(outcomes) == 8
    assert all(outcome.value == 1 for outcome in outcomes.values())
    # Overlap happened, but never beyond the bound.
    assert state["peak"] <= 3
    assert state["peak"] >= 2


def test_outcomes_keyed_by_name_and_errors_captured_not_raised():
    def boom() -> object:
        raise ValueError("job exploded")

    jobs = [("ok", lambda: "fine"), ("bad", boom)]
    outcomes = scheduler.run_group(jobs, workers=4)
    assert outcomes["ok"].value == "fine"
    assert outcomes["ok"].error is None
    assert isinstance(outcomes["bad"].error, ValueError)
    assert outcomes["bad"].value is None
    assert outcomes["bad"].duration_ms >= 0.0


def test_on_start_fires_once_per_job_before_run():
    timeline: list[str] = []

    def job(tag: str):
        timeline.append(f"run:{tag}")

    jobs = [(tag, (lambda tag=tag: job(tag))) for tag in ("a", "b")]
    scheduler.run_group(jobs, workers=1, on_start=timeline.append)
    # Serial: one start precedes its own run for every job.
    assert timeline == ["a", "run:a", "b", "run:b"]


def test_empty_job_group_returns_empty_mapping():
    assert scheduler.run_group([], workers=4) == {}


def test_worker_count_below_one_clamps_to_serial():
    jobs = [("only", lambda: "x")]
    outcomes = scheduler.run_group(jobs, workers=0)
    assert outcomes["only"].value == "x"


def test_runspec_scheduler_group_defaults_to_serial():
    spec = RunSpec()
    assert spec.scheduler == SchedulerSpec(workers=1)
    assert RunSpec.from_cli({"workers": 4}).scheduler == SchedulerSpec(workers=4)
    # Every other group keeps its default when only workers is set.
    assert RunSpec.from_cli({"workers": 4}) == RunSpec(scheduler=SchedulerSpec(workers=4))


def test_runspec_scheduler_group_is_frozen():
    with pytest.raises(FrozenInstanceError):
        RunSpec().scheduler.workers = 3  # type: ignore[misc]
