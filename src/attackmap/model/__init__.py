"""Typed analysis models.

``attackmap.models`` is a deprecation shim over this package; import
from here (or the narrow submodule) going forward.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from ..extraction.ledger import AnalyzerRunLedger
from .evidence import (  # noqa: F401
    _EVIDENCE_LIST_FIELDS,
    _EVIDENCE_TEXT_FIELDS,
    _PROVENANCE_FIELD,
    _RedactedEvidence,
)
from .findings import (  # noqa: F401
    Asset,
    AssetKind,
    AttackTechnique,
    Control,
    ControlKind,
    ControlStrength,
    DetectionOpportunity,
    Finding,
    FindingLocation,
    FindingTaxonomy,
    Insight,
    InsightKind,
    finding_rule_id,
    title_slug,
)
from .observations import (  # noqa: F401
    DEPENDENCY_ECOSYSTEMS,
    AnalyzerError,
    Anomaly,
    AttackSurface,
    AuthHint,
    BolaCandidate,
    CodeWeakness,
    CryptoWeakness,
    DatabaseHint,
    DependencyEcosystem,
    DependencyHint,
    EdgeHint,
    EntrypointHint,
    ExternalCall,
    FrameworkHint,
    ProtocolHint,
    Route,
    RouteAuth,
    SecretHint,
    SecretHistoryHit,
    ServiceHint,
    Signal,
    SignalClassification,
    SignalConflict,
    SignalKind,
    SignalOrigin,
    SourceRole,
    SupplyChainIssue,
    Vulnerability,
    WebHardeningIssue,
    WorkflowIssue,
)
from .paths import (  # noqa: F401
    AttackPath,
    ExploitabilityChainIdentity,
    ExploitabilityFactor,
    ExploitabilityScore,
    ExploitabilityScoreReference,
    ExploitabilityTier,
    TaintChain,
    TaintFlowStep,
)
from .snapshot import ResourceLimitEvent, ResourceLimitScope, ScanSnapshotIdentity


class ScanResult(BaseModel):
    root: str
    signals: list[Signal] = Field(default_factory=list)
    # None means the analyzer did not enumerate coverage; hint locations are
    # never substituted for the set of files actually scanned.
    scanned_files: list[str] | None = None
    resource_limit_events: list[ResourceLimitEvent] = Field(default_factory=list)
    # Completeness applies ONLY to listed producer/category scopes, never all
    # resource limits, analyzer coverage, timeouts or provider allowances.
    resource_limit_scopes: list[ResourceLimitScope] = Field(default_factory=list)
    resource_limit_reporting: Literal["complete", "partial", "unknown"] = "unknown"
    languages: list[str] = Field(default_factory=list)
    routes: list[Route] = Field(default_factory=list)
    external_calls: list[ExternalCall] = Field(default_factory=list)
    databases: list[DatabaseHint] = Field(default_factory=list)
    auth_hints: list[AuthHint] = Field(default_factory=list)
    service_hints: list[ServiceHint] = Field(default_factory=list)
    edge_hints: list[EdgeHint] = Field(default_factory=list)
    entrypoint_hints: list[EntrypointHint] = Field(default_factory=list)
    protocol_hints: list[ProtocolHint] = Field(default_factory=list)
    framework_hints: list[FrameworkHint] = Field(default_factory=list)
    secret_hints: list[SecretHint] = Field(default_factory=list)
    taint_chains: list[TaintChain] = Field(default_factory=list)
    dependencies: list[DependencyHint] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    authz_candidates: list[BolaCandidate] = Field(default_factory=list)
    crypto_weaknesses: list[CryptoWeakness] = Field(default_factory=list)
    web_hardening_issues: list[WebHardeningIssue] = Field(default_factory=list)
    code_weaknesses: list[CodeWeakness] = Field(default_factory=list)
    workflow_issues: list[WorkflowIssue] = Field(default_factory=list)
    supply_chain_issues: list[SupplyChainIssue] = Field(default_factory=list)
    secret_history: list[SecretHistoryHit] = Field(default_factory=list)
    anomalies: list[Anomaly] = Field(default_factory=list)
    # What the scan deliberately did not analyze (e.g. symlinks that point out
    # of the repo, #234) — so a clean report isn't mistaken for full coverage.
    limitations: list[str] = Field(default_factory=list)
    # Analyzers that failed and were skipped (#220).
    analyzer_errors: list[AnalyzerError] = Field(default_factory=list)
    # Selection and observed invocation outcomes; absence means legacy/unknown.
    analyzer_run_ledger: AnalyzerRunLedger | None = None
    files_scanned: int = 0
    # Content identity of the analyzed file snapshot (C33/AM047): set by the
    # index; the artifact manifest verifies the working tree against it at
    # publication and marks drifted runs incomplete instead of publishing
    # silently mixed revisions.
    scan_snapshot: ScanSnapshotIdentity | None = None

    @property
    def root_path(self) -> Path:
        return Path(self.root)

    def all_signals(self) -> list[Signal]:
        """Synthesize the unified Signal stream from typed hint lists.

        Does not mutate `self`. Preserved normalized observations take
        precedence over their lossy typed representatives; output uses stable
        canonical ordering and retains corroborating origins and conflicts.
        """
        signals: list[Signal] = []
        for r in self.routes:
            signals.append(
                Signal(
                    kind="route",
                    label=f"{r.method} {r.path}",
                    file=r.file,
                    line=r.line,
                    properties={"method": r.method, "path": r.path, "auth": r.auth},
                )
            )
        for ext in self.external_calls:
            signals.append(
                Signal(
                    kind="external_call",
                    label=ext.target,
                    file=ext.file,
                    line=ext.line,
                    evidence_text=ext.evidence_text,
                    properties={"method": ext.method or "unknown"},
                )
            )
        for db in self.databases:
            signals.append(
                Signal(
                    kind="database",
                    label=db.kind,
                    file=db.file,
                    line=db.line,
                    evidence_text=db.evidence_text,
                    properties={"kind": db.kind},
                )
            )
        _hint_kind_pairs: tuple[tuple[SignalKind, list], ...] = (
            ("auth", self.auth_hints),
            ("service", self.service_hints),
            ("edge", self.edge_hints),
            ("entrypoint", self.entrypoint_hints),
            ("protocol", self.protocol_hints),
            ("framework", self.framework_hints),
        )
        for kind, hints in _hint_kind_pairs:
            for h in hints:
                signals.append(
                    Signal(
                        kind=kind,
                        label=h.hint,
                        file=h.file,
                        line=getattr(h, "line", None),
                        evidence_text=getattr(h, "evidence_text", None),
                        confidence=getattr(h, "confidence", 0.7),
                    )
                )
        for s in self.secret_hints:
            signals.append(
                Signal(
                    kind="secret",
                    label=s.name,
                    file=s.file,
                    line=s.line,
                    evidence_text=s.evidence_text,
                    confidence=getattr(s, "confidence", 0.85),
                )
            )
        for tc in self.taint_chains:
            signals.append(
                Signal(
                    kind="taint",
                    label=f"{tc.route_method} {tc.route_path} → {tc.sink_kind}",
                    file=tc.sink_file,
                    line=tc.sink_line,
                    evidence_text=tc.evidence_text,
                    confidence=tc.confidence,
                    properties={
                        "hops": str(tc.hops),
                        "sink_kind": tc.sink_kind,
                        "route_file": tc.route_file,
                    },
                )
            )
        for dep in self.dependencies:
            signals.append(
                Signal(
                    kind="dependency",
                    label=f"{dep.ecosystem}:{dep.name}@{dep.version}",
                    file=dep.file,
                    line=dep.line,
                    evidence_text=dep.evidence_text,
                    confidence=0.9,  # manifest declarations are hard evidence
                    properties={
                        "ecosystem": dep.ecosystem,
                        "name": dep.name,
                        "version": dep.version,
                        "dev": "true" if dep.dev else "false",
                    },
                )
            )
        from attackmap.reasoning.signal_provenance import normalized_view
        return normalized_view(self, signals)

