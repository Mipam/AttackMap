"""Deprecated alias for :mod:`attackmap.sdk.analyzer_contracts` (AR030).

The analyzer contracts are the public plugin surface, so they live in the
``sdk`` package (AR031 layer map: ``analyzer_contracts`` -> sdk); this shim
re-exports the historical surface for one release so existing
``from attackmap.reasoning.analyzer_contracts import ...`` call sites keep
working. Import from ``attackmap.sdk.analyzer_contracts`` (or
``attackmap.sdk.contracts``) instead; this module is removed after that
release.
"""
from __future__ import annotations

from attackmap.sdk.analyzer_contracts import (
    EXTRACTION_PROTOCOL_VERSION,
    AnalyzerMetadata,
    AnalyzerProtocol,
    AnalyzerRepositoryModule,
    AnalyzerResult,
    ExtractionCompatibility,
    check_extraction_compatibility,
    describe_extraction_protocol,
    normalize_analyzer_metadata,
)

__all__ = [
    "EXTRACTION_PROTOCOL_VERSION",
    "AnalyzerMetadata",
    "AnalyzerProtocol",
    "AnalyzerRepositoryModule",
    "AnalyzerResult",
    "ExtractionCompatibility",
    "check_extraction_compatibility",
    "describe_extraction_protocol",
    "normalize_analyzer_metadata",
]
