"""Deprecated alias for :mod:`attackmap.model.evidence_labels` (AR030).

Evidence classification labels belong to the normalized model layer
(AR031 layer map: ``evidence`` -> model); this shim re-exports the
historical surface for one release so existing
``from attackmap.extraction.evidence import ...`` call sites keep working.
Import from ``attackmap.model.evidence_labels`` instead; this module is
removed after that release.
"""
from __future__ import annotations

from attackmap.model.evidence_labels import (  # noqa: F401
    SURFACE_EVIDENCE_CLASSES,
    classify_source_path,
    is_low_quality_source,
    is_protocol_derived_surface,
    surface_evidence_basis,
    surface_evidence_class,
    surface_evidence_counts,
)

__all__ = [
    "SURFACE_EVIDENCE_CLASSES",
    "classify_source_path",
    "is_low_quality_source",
    "is_protocol_derived_surface",
    "surface_evidence_basis",
    "surface_evidence_class",
    "surface_evidence_counts",
]
