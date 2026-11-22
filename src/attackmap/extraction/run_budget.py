"""Wall-clock run budget shared across the deterministic scan (AR007).

``TimeBudget`` moved here from ``pipeline`` so the scanner and the index can
check the deadline without importing the pipeline (which would add an import
cycle; the architecture gate freezes the cycle set). ``pipeline.TimeBudget``
remains a re-export for compatibility.

The active budget is a ``ContextVar``, mirroring ``ai_budget``: fleet workers
scan repositories in thread pools, so a module global would let one
repository's budget bleed into another's.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field

from attackmap.foundation.errors import BudgetExpired

DEFAULT_CHECKPOINT_FILES = 256


@dataclass
class TimeBudget:
    """Wall-clock ceiling for one deterministic run (C35, AR007).

    Between stages a breach never aborts: the in-flight stage runs to
    completion, then later optional stages are skipped so the run always
    publishes (``check``). Inside long stages, ``tick`` cancels the stage at
    the next file checkpoint so a small budget actually bounds the run
    (AC-010: within ~5 s of expiry). The check is a single ``perf_counter``
    read — no threads, no sleeps.
    """

    seconds: int
    checkpoint_interval: int = DEFAULT_CHECKPOINT_FILES
    exceeded_stage: str | None = None
    _deadline: float = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._deadline = time.perf_counter() + self.seconds

    @property
    def exceeded(self) -> bool:
        return self.exceeded_stage is not None

    def check(self, skipped_stage: str) -> bool:
        """Record the first breach (naming the stage being skipped); idempotent."""
        if self.exceeded_stage is None and time.perf_counter() >= self._deadline:
            self.exceeded_stage = skipped_stage
        return self.exceeded_stage is not None

    def tick(self, stage: str) -> None:
        """Intra-stage deadline check: raises :class:`BudgetExpired` once past
        the deadline. Call every ~``checkpoint_interval`` processed files."""
        if time.perf_counter() >= self._deadline:
            raise BudgetExpired(stage)


_budget: ContextVar[TimeBudget | None] = ContextVar("attackmap_time_budget", default=None)


def active_budget() -> TimeBudget | None:
    """The budget for the running scan in this context, or None."""
    return _budget.get()


@contextmanager
def time_budget_scope(budget: TimeBudget | None) -> Iterator[None]:
    """Make ``budget`` the intra-stage budget for this context."""
    token = _budget.set(budget)
    try:
        yield
    finally:
        _budget.reset(token)
