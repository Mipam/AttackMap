"""Bounded parallel execution for isolated analyzers (AR027, AC-107/AC-108).

The scheduler partitions and runs; it never decides merge order. The
resolved analyzer list is split into an in-process group (built-ins stay on
the calling thread: they share the scanner/index ContextVar state) and an
isolated group (third-party analyzers already execute in supervised
subprocess hosts via ``analyzer_host``, so a bounded thread pool overlapping
the subprocess wait/IO is safe — the pool threads never run plugin code
in-process). Outcomes are returned keyed by analyzer name; the caller
(``analyze_repository``) consumes them strictly in the resolved
``(priority, name)`` plan order and merges exactly like the serial path.
Completion order never reaches the merge (determinism gate R3).

``workers=1`` (the ``RunSpec`` default) preserves the historical serial
behaviour exactly: jobs run inline on the calling thread and no pool is
created.

Stdlib only: importing anything from ``attackmap`` here would add import
edges to the engine graph and could grow the frozen cycle set
(tests/architecture). The analyzer shape is therefore typed as a structural
Protocol instead of importing the SDK contract.
"""
from __future__ import annotations

import time
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Protocol


class _NamedAnalyzer(Protocol):
    """The only analyzer surface the scheduler needs (AR027 scope)."""

    @property
    def name(self) -> str: ...


DEFAULT_WORKERS = 1


def partition(
    analyzers: Iterable[_NamedAnalyzer],
    *,
    is_isolated: Callable[[_NamedAnalyzer], bool],
) -> tuple[list[_NamedAnalyzer], list[_NamedAnalyzer]]:
    """Split resolved analyzers into (in-process, isolated) groups.

    Both groups keep the resolved ``(priority, name)`` plan order; the
    caller merges from the plan, never from these lists.
    """
    in_process: list[_NamedAnalyzer] = []
    isolated: list[_NamedAnalyzer] = []
    for analyzer in analyzers:
        (isolated if is_isolated(analyzer) else in_process).append(analyzer)
    return in_process, isolated


@dataclass(frozen=True)
class JobOutcome:
    """One scheduled job's result, keyed by analyzer name.

    ``value`` is whatever ``run`` returned (an isolated-host
    ``IsolatedOutcome``); ``error`` carries an unexpected in-worker
    exception so the caller's existing error handling replays it in plan
    order instead of completion order.
    """

    name: str
    value: object = None
    duration_ms: float = 0.0
    error: Exception | None = None


def run_group(
    jobs: Sequence[tuple[str, Callable[[], object]]],
    *,
    workers: int = DEFAULT_WORKERS,
    on_start: Callable[[str], None] | None = None,
) -> dict[str, JobOutcome]:
    """Run isolated-analyzer jobs, bounded by ``workers``; key by name.

    ``workers <= 1`` executes every job inline on the calling thread and
    never constructs a pool — the serial behaviour contract. With more
    workers, a ``ThreadPoolExecutor`` overlaps the supervised subprocess
    runs; ``on_start`` (e.g. the run's ``EventLog.analyzer(name, "start")``)
    fires from the worker thread before each job so event timestamps reflect
    actual execution. Exceptions are captured per job, never raised here.
    """
    if not jobs:
        return {}
    effective = max(1, int(workers))
    if effective == 1:
        return {name: _execute(name, run, on_start) for name, run in jobs}
    with ThreadPoolExecutor(max_workers=min(effective, len(jobs)),
                            thread_name_prefix="attackmap-isolated") as pool:
        futures = {name: pool.submit(_execute, name, run, on_start)
                   for name, run in jobs}
        return {name: future.result() for name, future in futures.items()}


def _execute(
    name: str,
    run: Callable[[], object],
    on_start: Callable[[str], None] | None,
) -> JobOutcome:
    started = time.monotonic()
    if on_start is not None:
        on_start(name)
    try:
        value = run()
    except Exception as exc:  # captured for ordered replay in plan order
        return JobOutcome(name=name, value=None,
                          duration_ms=(time.monotonic() - started) * 1000.0,
                          error=exc)
    return JobOutcome(name=name, value=value,
                      duration_ms=(time.monotonic() - started) * 1000.0)
