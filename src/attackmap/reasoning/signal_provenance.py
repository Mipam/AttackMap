"""Deprecated alias for :mod:`attackmap.model.signal_provenance` (AR030).

Signal provenance operates purely on the normalized model types, so it
lives in the ``model`` package (AR031 layer map:
``signal_provenance`` -> model); this shim re-exports the historical
surface for one release so existing
``from attackmap.reasoning.signal_provenance import ...`` call sites keep
working. Import from ``attackmap.model.signal_provenance`` instead; this
module is removed after that release.
"""
from __future__ import annotations

from attackmap.model.signal_provenance import (
    CLASSIFICATION_FIELDS,
    KINDS,
    admit_isolated_provenance,
    merge_normalized_signals,
    merge_scan_provenance,
    normalized_view,
    stamp_scan_provenance,
)

__all__ = [
    "CLASSIFICATION_FIELDS",
    "KINDS",
    "admit_isolated_provenance",
    "merge_normalized_signals",
    "merge_scan_provenance",
    "normalized_view",
    "stamp_scan_provenance",
]
