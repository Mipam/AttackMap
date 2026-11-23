"""Canonical home of the AttackMap typed error taxonomy (AR012, AC-012).

This module is a **leaf**: it imports only :mod:`attackmap.foundation.errors`
(which imports nothing from attackmap), so every layer — core, surfaces, SDK,
analyzers — can import typed errors from ``attackmap.errors`` without creating
an import cycle. The architecture import-cycle gate depends on this staying
true; do not add attackmap imports here.

The class definitions currently live in :mod:`attackmap.foundation.errors` and
are re-exported here under their canonical names; both import paths yield the
identical classes, so ``except`` / ``isinstance`` checks interoperate
regardless of which path callers used.
"""

from __future__ import annotations

from attackmap.foundation.errors import (
    AnalyzerLoadError,
    AnalyzerRuntimeError,
    ArtifactIntegrityError,
    AttackMapError,
    BudgetExpired,
    FleetAdmissionError,
    UnsupportedInFleet,
    UntrustedAnalyzerError,
)

__all__ = [
    "AnalyzerLoadError",
    "AnalyzerRuntimeError",
    "ArtifactIntegrityError",
    "AttackMapError",
    "BudgetExpired",
    "FleetAdmissionError",
    "UnsupportedInFleet",
    "UntrustedAnalyzerError",
]
