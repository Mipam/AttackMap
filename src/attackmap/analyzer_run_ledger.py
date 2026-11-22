"""Deprecated alias for the analyzer run ledger surface (AR023, AR030).

The persisted ledger records live in ``attackmap.extraction.ledger``; the
run plan and identity observation live in
``attackmap.orchestration.analyzer_run_plan`` (AR030: they need the
analyzer registry, which is orchestration-owned). This shim re-exports the
full historical surface for one release so existing
``from attackmap.analyzer_run_ledger import ...`` call sites keep working.
Import from the owning modules instead; this module is removed after that
release.
"""
from __future__ import annotations

from .extraction.ledger import (
    AnalyzerLifecycleEvent,
    AnalyzerRunError,
    AnalyzerRunLedger,
    AnalyzerRunRecord,
    AnalyzerSignalCounts,
    safe_error_type,
)
from .orchestration.analyzer_run_plan import AnalyzerRunPlan
from .orchestration.analyzers import analyzer_run_identity

__all__ = [
    "AnalyzerLifecycleEvent",
    "AnalyzerRunError",
    "AnalyzerRunLedger",
    "AnalyzerRunPlan",
    "AnalyzerRunRecord",
    "AnalyzerSignalCounts",
    "analyzer_run_identity",
    "safe_error_type",
]
