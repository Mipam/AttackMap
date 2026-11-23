"""Row shapes of the derived index (AR061).

The derived index is a disposable projection of published generations. Every
value in it is copied verbatim from a generation's artifact manifest or
section files — never scored, normalised or inferred — plus the structural
keys that say where it came from (the run id and its position in a section).

One frozen shape per table, used on all three routes a row travels: extracted
from a generation, written to and read back from SQLite, and read straight
from the filesystem when the index is unusable. Because the same dataclasses
carry all three, the filesystem fallback and the index cannot drift apart.

``None`` always means "the generation does not publish this field"; an empty
tuple means it publishes an empty list. The two are never merged.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

__all__ = [
    "EvidenceRow",
    "FindingRow",
    "GenerationRow",
    "IndexRows",
    "RouteRow",
    "RunRow",
    "SuppressionRow",
]


@dataclass(frozen=True, slots=True)
class GenerationRow:
    """One generation directory under an output base.

    ``valid`` is the artifact-manifest validation result. ``indexed`` is True
    only when this generation's rows were read; ``error`` says why they were
    not. A generation that fails validation is listed but never read.
    """

    run_id: str
    path: str  # relative to the output base, posix
    valid: bool
    indexed: bool
    parent_run_id: str | None = None  # fleet child: the fleet generation's run id
    manifest_sha256: str | None = None
    created_at: str | None = None
    engine_version: str | None = None
    profile: str | None = None  # "scan" or "fleet"; None when unknown
    error: str | None = None


@dataclass(frozen=True, slots=True)
class RunRow:
    """The analysis one valid scan generation records (its manifest identity
    and exit state). Fleet generations are containers and get no run row;
    their children each get one."""

    run_id: str
    repo_root: str
    repo_name: str
    engine_version: str
    status: str
    exit_code: int
    analyzer_identity: str | None = None
    snapshot_id: str | None = None
    snapshot_state: str | None = None  # e.g. "incomplete" when the snapshot drifted
    files_scanned: int | None = None


@dataclass(frozen=True, slots=True)
class FindingRow:
    """One active finding, exactly as ``findings.json`` publishes it."""

    run_id: str
    idx: int  # position in findings.json
    finding_id: str
    title: str
    severity: str
    confidence: str
    identity_scheme: str | None = None
    rule_id: str | None = None  # None when the finding carries none (no title-slug fallback)
    entity_id: str | None = None
    score: int | None = None  # the published score; never computed here
    exploitability: int | None = None
    exploitability_tier: str | None = None
    tags: tuple[str, ...] | None = None
    cwe: tuple[str, ...] | None = None


@dataclass(frozen=True, slots=True)
class SuppressionRow:
    """One suppressed finding from ``suppressed_findings.json``: the finding
    plus the suppression that silenced it."""

    run_id: str
    idx: int  # position in suppressed_findings.json
    finding_id: str
    title: str
    severity: str
    rule: str  # the suppression selector as published (e.g. "rule=hardcoded-secret")
    reason: str
    identity_scheme: str | None = None
    rule_id: str | None = None
    entity_id: str | None = None
    suppressed_by: tuple[str, ...] | None = None


@dataclass(frozen=True, slots=True)
class RouteRow:
    """One request route from the generation's ``scan`` section."""

    run_id: str
    idx: int  # position in scan.routes
    method: str
    path: str
    file: str
    auth: str | None = None
    line: int | None = None
    guards: tuple[str, ...] | None = None


@dataclass(frozen=True, slots=True)
class EvidenceRow:
    """One evidence line or one location of a finding.

    ``suppressed`` says whether the finding it belongs to was active (False)
    or suppressed (True) in that run — a finding can appear in both lists.
    """

    run_id: str
    finding_id: str
    suppressed: bool
    kind: str  # "text" (an evidence line) or "location"
    idx: int  # position within its own list
    text: str | None = None  # kind == "text"
    file: str | None = None  # kind == "location"
    line: int | None = None  # kind == "location"
    fingerprint: str | None = None  # kind == "location"


# Sort keys that put every table in one canonical order. Both the rebuild and
# the index read-back apply them, so the two can be compared for equality and
# the rebuilt file is byte-identical for the same generations.
_OrderKey = Callable[[Any], Any]
_ORDER: dict[type, _OrderKey] = {
    GenerationRow: lambda row: row.path,
    RunRow: lambda row: row.run_id,
    FindingRow: lambda row: (row.run_id, row.idx),
    SuppressionRow: lambda row: (row.run_id, row.idx),
    RouteRow: lambda row: (row.run_id, row.idx),
    EvidenceRow: lambda row: (row.run_id, row.suppressed, row.finding_id, row.kind, row.idx),
}


@dataclass(frozen=True, slots=True)
class IndexRows:
    """The whole index content in canonical order."""

    fingerprint: str  # identity of the generation set these rows were read from
    generations: tuple[GenerationRow, ...]
    runs: tuple[RunRow, ...]
    findings: tuple[FindingRow, ...]
    suppressions: tuple[SuppressionRow, ...]
    routes: tuple[RouteRow, ...]
    evidence: tuple[EvidenceRow, ...]

    @classmethod
    def canonical(
        cls,
        *,
        fingerprint: str,
        generations: list[GenerationRow],
        runs: list[RunRow],
        findings: list[FindingRow],
        suppressions: list[SuppressionRow],
        routes: list[RouteRow],
        evidence: list[EvidenceRow],
    ) -> IndexRows:
        """Build with every table sorted by its canonical key."""
        return cls(
            fingerprint=fingerprint,
            generations=tuple(sorted(generations, key=_ORDER[GenerationRow])),
            runs=tuple(sorted(runs, key=_ORDER[RunRow])),
            findings=tuple(sorted(findings, key=_ORDER[FindingRow])),
            suppressions=tuple(sorted(suppressions, key=_ORDER[SuppressionRow])),
            routes=tuple(sorted(routes, key=_ORDER[RouteRow])),
            evidence=tuple(sorted(evidence, key=_ORDER[EvidenceRow])),
        )

    def counts(self) -> dict[str, int]:
        """Row count per data table (``index_meta`` excluded)."""
        return {
            "generations": len(self.generations),
            "runs": len(self.runs),
            "findings": len(self.findings),
            "suppressions": len(self.suppressions),
            "routes": len(self.routes),
            "evidence": len(self.evidence),
        }

    def not_indexed(self) -> tuple[GenerationRow, ...]:
        """Generations listed but not read, in canonical order."""
        return tuple(row for row in self.generations if not row.indexed)
