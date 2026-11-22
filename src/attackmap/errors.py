"""Typed error taxonomy for AttackMap (AR007/AR012).

``BudgetExpired`` arrives with AR007 (intra-stage cancellation); the rest of
the taxonomy (AnalyzerLoadError, ArtifactIntegrityError, …) lands with AR012.
This module must stay import-cycle-free: every layer may use it.
"""

from __future__ import annotations


class BudgetExpired(Exception):
    """Raised inside a stage when the run's wall-clock deadline passed (AC-010).

    ``partial`` carries whatever the interrupted stage had already built (a
    per-file pass result, a merged scan, an index), so the stage boundary can
    publish a partial result with an explicit limitation instead of failing.
    """

    def __init__(self, stage: str, partial: object | None = None) -> None:
        self.stage = stage
        self.partial = partial
        super().__init__(f"time budget expired inside stage '{stage}'")
