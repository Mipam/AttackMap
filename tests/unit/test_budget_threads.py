"""TimeBudget under concurrent threads (AR028, AC-108).

The budget object may be observed from several threads (parallel scheduler
consumption, fleet workers each holding their own). Reads stay lock-free;
the only write — the single-reference ``exceeded_stage`` assignment in
``check()`` — is atomic under the GIL, so concurrent stress can never tear
the object: the recorded stage is always exactly one of the submitted names,
``exceeded`` flips monotonically, and unexpired budgets never raise.
"""

from __future__ import annotations

import threading

import pytest

from attackmap.errors import BudgetExpired
from attackmap.pipeline import TimeBudget  # the pipeline re-export (AR007)

THREADS = 8
ITERATIONS = 1000


def _run_threads(work) -> None:
    threads = [threading.Thread(target=work, args=(n,)) for n in range(THREADS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


def test_unexpired_budget_never_raises_under_concurrent_tick():
    budget = TimeBudget(seconds=3600)

    def worker(n: int) -> None:
        for _ in range(ITERATIONS):
            budget.tick("scan_files")  # must not raise
            assert budget.check("scan_files") is False

    _run_threads(worker)
    assert budget.exceeded_stage is None
    assert budget.exceeded is False


def test_expired_budget_tick_raises_in_every_thread():
    budget = TimeBudget(seconds=0)
    raised: list[str] = []

    def worker(n: int) -> None:
        for _ in range(ITERATIONS):
            with pytest.raises(BudgetExpired) as excinfo:
                budget.tick("the_stage")
            raised.append(excinfo.value.stage)
            assert budget.check("the_stage") is True

    _run_threads(worker)
    assert len(raised) == THREADS * ITERATIONS
    assert set(raised) == {"the_stage"}


def test_concurrent_check_records_exactly_one_submitted_stage():
    """No torn writes: whatever loses the race, the field holds one valid name."""
    budget = TimeBudget(seconds=0)
    submitted = [f"stage-{n}" for n in range(THREADS)]

    def worker(n: int) -> None:
        for _ in range(ITERATIONS):
            assert budget.check(submitted[n]) is True

    _run_threads(worker)
    assert budget.exceeded_stage in submitted
    assert budget.exceeded is True


def test_concurrent_mixed_check_and_tick_stays_consistent():
    budget = TimeBudget(seconds=0)

    def checker(n: int) -> None:
        for _ in range(ITERATIONS):
            assert budget.check("check_stage") is True

    def ticker(n: int) -> None:
        for _ in range(ITERATIONS):
            with pytest.raises(BudgetExpired):
                budget.tick("tick_stage")

    threads = [threading.Thread(target=checker, args=(n,)) for n in range(4)]
    threads += [threading.Thread(target=ticker, args=(n,)) for n in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    # One atomic reference write won; the object never holds a torn value.
    assert budget.exceeded_stage in {"check_stage", "tick_stage"}
    assert budget.exceeded is True
