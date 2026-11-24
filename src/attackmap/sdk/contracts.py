"""Analyzer contracts plus the extraction contract v2 container (AR060).

Protocol 2.0 (AR082 / AC-403) is the declared analyzer wire protocol:
`EXTRACTION_PROTOCOL_VERSION` in ``attackmap.analyzer_contracts`` is "2.0"
and every official analyzer declares it (see
:func:`attackmap.sdk.analyzer_contracts.declared_extraction_protocol` and
``tools.check_analyzer_versions``). The v2 contract is additive:
`ExtractionResult` carries one discriminated `observations` list instead of
the per-kind hint lists, and :mod:`attackmap.extraction.adapters` converts
in both directions, so plugins written against protocol 1.0 keep working
indefinitely.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from attackmap.sdk.analyzer_contracts import (
    AnalyzerMetadata,
    AnalyzerProtocol,
    AnalyzerRepositoryModule,
    AnalyzerResult,
    normalize_analyzer_metadata,
)

from ..model.observations import (
    AnalyzerError,
    Anomaly,
    AuthHint,
    BolaCandidate,
    CryptoWeakness,
    DatabaseHint,
    ExternalCall,
    Observation,
    SecretHistoryHit,
    WebHardeningIssue,
)
from ..model.paths import TaintChain

__all__ = [
    "EXTRACTION_CONTRACT_VERSION",
    "AnalyzerMetadata",
    "AnalyzerProtocol",
    "AnalyzerRepositoryModule",
    "AnalyzerResult",
    "ExtractionResult",
    "normalize_analyzer_metadata",
]

# Version of the extraction contract v2 container declared below. The v1
# analyzer wire protocol (`EXTRACTION_PROTOCOL_VERSION`) flipped to "2.0"
# with AR082 (AC-403): official analyzers declare 2.0, and protocol-1.0
# plugins keep working via attackmap.extraction.adapters.
EXTRACTION_CONTRACT_VERSION: Literal["2.0"] = "2.0"


class ExtractionResult(BaseModel):
    """Extraction contract v2: one discriminated list of observations.

    The twelve per-kind observation variants (`RouteObservation` …
    `SupplyChainObservation`) wrap their protocol-1.0 hint objects verbatim,
    so `to_scan_result` can rebuild a `ScanResult` with every payload list
    preserved exactly.

    v1 payload lists that have no observation kind yet (`external_calls`,
    `databases`, `auth_hints`, `taint_chains`, `authz_candidates`,
    `crypto_weaknesses`, `web_hardening_issues`, `anomalies`,
    `secret_history`) ride along unchanged until AR082 migrates them, which
    keeps the v2 -> v1 round trip lossless.

    Run-infrastructure fields of `ScanResult` (`signals` — synthesized on
    demand via `ScanResult.all_signals()`, `resource_limit_*`,
    `analyzer_run_ledger`, `scan_snapshot`) are intentionally not part of the
    extraction payload contract.
    """

    extraction_version: Literal["2.0"] = EXTRACTION_CONTRACT_VERSION
    root: str
    observations: list[Observation] = Field(default_factory=list)
    languages: list[str] = Field(default_factory=list)
    # None means the analyzer did not enumerate coverage (same semantics as
    # ScanResult.scanned_files).
    scanned_files: list[str] | None = None
    files_scanned: int = 0
    limitations: list[str] = Field(default_factory=list)
    analyzer_errors: list[AnalyzerError] = Field(default_factory=list)
    # v1 payload carried verbatim (no v2 observation kind yet).
    external_calls: list[ExternalCall] = Field(default_factory=list)
    databases: list[DatabaseHint] = Field(default_factory=list)
    auth_hints: list[AuthHint] = Field(default_factory=list)
    taint_chains: list[TaintChain] = Field(default_factory=list)
    authz_candidates: list[BolaCandidate] = Field(default_factory=list)
    crypto_weaknesses: list[CryptoWeakness] = Field(default_factory=list)
    web_hardening_issues: list[WebHardeningIssue] = Field(default_factory=list)
    anomalies: list[Anomaly] = Field(default_factory=list)
    secret_history: list[SecretHistoryHit] = Field(default_factory=list)
    # "2.0" when produced natively; "1.0" when adapted from a protocol-1.0
    # ScanResult by attackmap.extraction.adapters.to_extraction_result.
    source_protocol_version: Literal["1.0", "2.0"] = "2.0"
