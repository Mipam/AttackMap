"""The one-use analyzer run plan tied to a repository capture (AR030).

Lives in orchestration (AR031 layer map): selection binds the analyzer
registry's output to this capture. The persisted record models
(:class:`attackmap.extraction.ledger.AnalyzerRunLedger` and friends) stay
in ``extraction.ledger`` so every layer can depend on the data without
reaching up into orchestration; per-run identity observation lives in
:mod:`attackmap.orchestration.analyzers` next to the registry helpers it
reads.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from attackmap.extraction.ledger import (
    AnalyzerLifecycleEvent,
    AnalyzerRunLedger,
    AnalyzerRunRecord,
    safe_error_type,
)

if TYPE_CHECKING:
    from attackmap.reasoning.analyzer_contracts import AnalyzerProtocol


@dataclass
class AnalyzerRunPlan:
    """One-use selection tied to the actual capture, never a reusable name cache."""

    repository_root: Path
    index: object
    ledger: AnalyzerRunLedger
    analyzers: tuple[AnalyzerProtocol, ...] = ()
    _selected_records: tuple[AnalyzerRunRecord, ...] = field(default=(), repr=False)
    _claimed: bool = field(default=False, repr=False)
    _started_monotonic: float = field(default_factory=lambda: time.monotonic(), repr=False)

    @staticmethod
    def mark() -> float:
        return time.monotonic()

    @staticmethod
    def duration_ms(started: float) -> float:
        return max(0.0, (time.monotonic() - started) * 1000)

    def observe(self, row: AnalyzerRunRecord, stage: str, state: str, *, error_type: str | None = None) -> None:
        if len(row.lifecycle_events) < 16:
            row.lifecycle_events.append(AnalyzerLifecycleEvent(stage=stage, state=state,
                elapsed_ms=self.duration_ms(self._started_monotonic),
                error_type=safe_error_type(error_type) if error_type is not None else None))

    def claim(self, root: Path, index: object) -> None:
        if root != self.repository_root or index is not self.index:
            raise ValueError("Analyzer run plan does not belong to this repository capture")
        if self._claimed or not self.ledger.resolution_complete:
            raise ValueError("Analyzer run plan is unresolved or already consumed")
        self._claimed = True

    def skip_for_deadline(self) -> None:
        self._claimed = True
        for row in self._selected_records:
            if row.execution == "not_started":
                row.execution = "skipped"
                row.skip_reason = "pipeline_deadline"
                self.observe(row, "selection", "skipped")
        self.ledger.execution_complete = True
