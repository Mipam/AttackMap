"""Versioned ``EvidenceBundle`` — the AI layer's compact projection of an analysis result (AR067/AC-309).

The bundle is the single object the AI prompt layer consumes: prompts are
rendered from it, and citations in model output are validated against its
stable citation ids. It is a *projection*, not a copy of the analysis result:

- ``findings`` reference the detector's ``rationale`` and ``evidence`` lists
  (AR049/AC-207) instead of duplicating source text wholesale;
- record shapes match the evidence-pack records the prompts already used, so
  the serialized pack content is unchanged apart from the additions the
  bundle owns (``rationale`` on findings, the ``limitations`` section);
- every record carries a stable citation id (``finding:N``, ``path:N``, and
  the control's own id) that :mod:`attackmap.output.citations` enforces.

``BUNDLE_SCHEMA_VERSION`` + :func:`gate_bundle_schema_version` are the
compatibility gate: the current version and documented older versions are
accepted, unknown and newer versions raise :class:`BundleSchemaError`. This
is the hook point AR083 (run observability) replays bundles through.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from attackmap.model import AttackPath, AttackSurface, Finding, ScanResult
from attackmap.output.finding_identity import finding_id
from attackmap.output.security_overlay import SecurityOverlay, build_security_overlay

# Bump on any schema change (field add/remove/rename, id scheme change, or
# semantics change). Document each retired version in
# LEGACY_BUNDLE_SCHEMA_VERSIONS so the gate can keep accepting it.
BUNDLE_SCHEMA_VERSION = 1

# Documented older schema versions the compatibility gate still accepts.
# None exist yet — version 1 is the first versioned bundle. The frozenset is
# the AR083 hook: when version 2 lands, version 1 is recorded here so replay
# of older bundles keeps working.
LEGACY_BUNDLE_SCHEMA_VERSIONS: frozenset[int] = frozenset()
SUPPORTED_BUNDLE_SCHEMA_VERSIONS: frozenset[int] = frozenset(
    {BUNDLE_SCHEMA_VERSION, *LEGACY_BUNDLE_SCHEMA_VERSIONS}
)

# Caps mirror the evidence-pack limits so the projection stays compact and
# the prompt size stays bounded. Omissions are disclosed in ``limitations``.
MAX_BUNDLE_FINDINGS = 30
MAX_BUNDLE_PATHS = 10
MAX_BUNDLE_EVIDENCE_REFS = 10


class BundleSchemaError(ValueError):
    """Raised when an evidence bundle carries an unknown or newer schema version."""


def gate_bundle_schema_version(version: object) -> int:
    """Accept the current schema version and documented older versions.

    Unknown versions and versions newer than :data:`BUNDLE_SCHEMA_VERSION`
    (i.e. bundles produced by a newer AttackMap) raise
    :class:`BundleSchemaError` with an actionable message. This is the
    AR083 observability hook point: every bundle entering or leaving the AI
    layer passes through here.
    """
    if type(version) is not int:
        raise BundleSchemaError(
            f"evidence bundle schema_version must be an integer, got {version!r}"
        )
    if version in SUPPORTED_BUNDLE_SCHEMA_VERSIONS:
        return version
    supported = ", ".join(str(v) for v in sorted(SUPPORTED_BUNDLE_SCHEMA_VERSIONS))
    if version > BUNDLE_SCHEMA_VERSION:
        raise BundleSchemaError(
            f"evidence bundle schema version {version} is newer than this AttackMap "
            f"supports (current {BUNDLE_SCHEMA_VERSION}); upgrade AttackMap to read it"
        )
    raise BundleSchemaError(
        f"unknown evidence bundle schema version {version}; supported versions: {supported}"
    )


def _json_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def _default_run_id(scan: ScanResult) -> str:
    """Deterministic run identity for the projection.

    Prefers the content snapshot id when the scan carries one; otherwise a
    digest of the coarse run summary. Two projections of the same analyzed
    snapshot get the same ``run_id``; it identifies the projection input, not
    the wall-clock run.
    """
    snapshot = scan.scan_snapshot
    snapshot_id = getattr(snapshot, "snapshot_id", None)
    if isinstance(snapshot_id, str) and snapshot_id:
        return snapshot_id
    identity = {
        "root": scan.root,
        "files_scanned": scan.files_scanned,
        "languages": sorted(scan.languages),
        "route_count": len(scan.routes),
    }
    return "run-" + _json_digest(identity)[:16]


@dataclass(frozen=True)
class BundleFinding:
    """One finding projection. ``rationale`` and ``evidence`` are referenced
    from the detector's own Finding (AR049) — the bundle never re-derives or
    copies source text beyond them."""

    id: str  # stable citation id, "finding:N"
    finding_id: str  # stable aggregate identity (rule slug), never renumbered
    rule_id: str | None
    title: str
    severity: str
    confidence: str
    score: int | None
    exploitability: int | None
    rationale: str
    evidence: tuple[str, ...]
    locations: tuple[dict[str, Any], ...]
    mitigation: str
    taxonomy: dict[str, Any] | None

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "finding_id": self.finding_id,
            "title": self.title,
            "rule_id": self.rule_id,
            "taxonomy": self.taxonomy,
            "severity": self.severity,
            "confidence": self.confidence,
            "score": self.score,
            "exploitability": self.exploitability,
            "rationale": self.rationale,
            "evidence": list(self.evidence),
            "locations": [dict(location) for location in self.locations],
            "mitigation": self.mitigation,
        }

    @classmethod
    def from_record(cls, record: Mapping[str, Any]) -> BundleFinding:
        return cls(
            id=str(record["id"]),
            finding_id=str(record.get("finding_id") or record["id"]),
            rule_id=record.get("rule_id"),
            title=str(record.get("title") or ""),
            severity=str(record.get("severity") or "medium"),
            confidence=str(record.get("confidence") or "medium"),
            score=record.get("score"),
            exploitability=record.get("exploitability"),
            rationale=str(record.get("rationale") or ""),
            evidence=tuple(str(value) for value in record.get("evidence") or ()),
            locations=tuple(dict(value) for value in record.get("locations") or ()),
            mitigation=str(record.get("mitigation") or ""),
            taxonomy=record.get("taxonomy"),
        )


@dataclass(frozen=True)
class BundlePath:
    """One attack-path projection with its stable citation id, "path:N"."""

    id: str
    name: str
    steps: tuple[str, ...]
    impact: str

    def to_payload(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name,
                "steps": list(self.steps), "impact": self.impact}

    @classmethod
    def from_record(cls, record: Mapping[str, Any]) -> BundlePath:
        return cls(
            id=str(record["id"]),
            name=str(record.get("name") or ""),
            steps=tuple(str(value) for value in record.get("steps") or ()),
            impact=str(record.get("impact") or ""),
        )


@dataclass(frozen=True)
class BundleControl:
    """One observed/absent control projection. The citation id IS the
    control's own stable ``id`` (never renumbered by the projection). The
    record is the control's model dump, held read-only by the bundle."""

    id: str
    record: Mapping[str, Any]

    def to_payload(self) -> dict[str, Any]:
        return dict(self.record)

    @classmethod
    def from_record(cls, record: Mapping[str, Any]) -> BundleControl:
        return cls(id=str(record["id"]), record=dict(record))


@dataclass(frozen=True)
class EvidenceBundle:
    """Compact, versioned projection of the post-analysis result consumed by
    the AI layer. See the module docstring for the contract."""

    schema_version: int
    run_id: str
    findings: tuple[BundleFinding, ...]
    paths: tuple[BundlePath, ...]
    controls: tuple[BundleControl, ...]
    limitations: tuple[str, ...]

    def __post_init__(self) -> None:
        gate_bundle_schema_version(self.schema_version)

    def citation_ids(self) -> tuple[str, ...]:
        """All stable citation ids this bundle enforces."""
        return tuple(
            [finding.id for finding in self.findings]
            + [path.id for path in self.paths]
            + [control.id for control in self.controls]
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "findings": [finding.to_payload() for finding in self.findings],
            "paths": [path.to_payload() for path in self.paths],
            "controls": [control.to_payload() for control in self.controls],
            "limitations": list(self.limitations),
        }

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> EvidenceBundle:
        """Rebuild a bundle from its serialized form, enforcing the
        compatibility gate. This is the AR083 replay hook."""
        if not isinstance(payload, Mapping):
            raise BundleSchemaError(f"evidence bundle payload must be a mapping, got {type(payload).__name__}")
        version = gate_bundle_schema_version(payload.get("schema_version"))
        return cls(
            schema_version=version,
            run_id=str(payload.get("run_id") or ""),
            findings=tuple(
                BundleFinding.from_record(record) for record in payload.get("findings") or ()
            ),
            paths=tuple(BundlePath.from_record(record) for record in payload.get("paths") or ()),
            controls=tuple(
                BundleControl.from_record(record) for record in payload.get("controls") or ()
            ),
            limitations=tuple(str(value) for value in payload.get("limitations") or ()),
        )

    def citation_context(self):
        """A :class:`~attackmap.output.citations.CitationContext` over this
        bundle's records — the enforcement point the citation validator uses.
        Imported lazily so the band dependency stays one-directional at
        module load (output.review_prompts imports this module)."""
        from attackmap.output.citations import context_from_payload

        return context_from_payload(self.to_payload(), (), repository_root="")


@dataclass(frozen=True)
class BundleCitationValidation:
    """Result of enforcing bundle citations on model output.

    ``rejected_claims`` are the substantive claim lines that cite no bundle
    id — they are rejected, per AC-309. ``accepted`` is true only when every
    claim line carries at least one valid bundle citation and no invalid
    reference ids appear.
    """

    reference_validity: Literal["valid", "invalid", "missing"]
    valid_references: tuple[str, ...]
    invalid_references: tuple[str, ...]
    rejected_claims: tuple[str, ...]

    @property
    def accepted(self) -> bool:
        return not self.rejected_claims and self.reference_validity != "invalid"


def validate_bundle_citations(markdown: str, bundle: EvidenceBundle) -> BundleCitationValidation:
    """Enforce the bundle grounding contract on AI output (AC-309).

    Reference validity is the mechanical check from
    :mod:`attackmap.output.citations`; claim lines without any citation to a
    bundle id are rejected. Claim detection is deliberately conservative
    (headings, fences, blockquotes, tables and short label lines are not
    claims), so narrative structure is never mistaken for an uncited claim.
    """
    from attackmap.output.citations import uncited_claim_lines, validate_references

    context = bundle.citation_context()
    validated = validate_references(markdown, context)
    rejected = uncited_claim_lines(markdown, context)
    return BundleCitationValidation(
        reference_validity=validated.reference_validity,
        valid_references=validated.valid_references,
        invalid_references=validated.invalid_references,
        rejected_claims=rejected,
    )


def find_uncited_claims(markdown: str, bundle: EvidenceBundle) -> tuple[str, ...]:
    """Bundle-facing wrapper over the citations enforcement point (kept as a
    named helper so AR083 observability can count rejections directly)."""
    return validate_bundle_citations(markdown, bundle).rejected_claims


def build_evidence_bundle(
    scan: ScanResult,
    attack_surfaces: list[AttackSurface],
    findings: list[Finding],
    attack_paths: list[AttackPath],
    *,
    overlay: SecurityOverlay | None = None,
    run_id: str | None = None,
) -> EvidenceBundle:
    """Project the post-AR049 analysis result into a versioned bundle.

    Every finding already carries its detector ``rationale`` and ``evidence``
    references (AR049); the bundle carries them verbatim and never re-derives
    or invents evidence. Caps mirror the evidence-pack limits; every omission
    is disclosed in ``limitations`` so no partial projection reads as complete
    coverage.
    """
    if overlay is None:
        overlay = build_security_overlay(scan, attack_surfaces, findings, attack_paths)

    bundle_findings = tuple(
        BundleFinding(
            id=f"finding:{idx + 1}",
            finding_id=finding_id(finding),
            rule_id=finding.rule_id,
            title=finding.title,
            severity=finding.severity,
            confidence=finding.confidence,
            score=finding.score,
            exploitability=finding.exploitability,
            rationale=finding.rationale,
            evidence=tuple(finding.evidence[:MAX_BUNDLE_EVIDENCE_REFS]),
            locations=tuple(
                dict(location.model_dump(mode="json")) for location in finding.locations
            ),
            mitigation=finding.mitigation,
            taxonomy=finding.taxonomy.model_dump() if finding.taxonomy else None,
        )
        for idx, finding in enumerate(findings[:MAX_BUNDLE_FINDINGS])
    )
    bundle_paths = tuple(
        BundlePath(
            id=f"path:{idx + 1}",
            name=path.name,
            steps=tuple(path.steps[:8]),  # mirror the evidence-pack step cap
            impact=path.impact,
        )
        for idx, path in enumerate(attack_paths[:MAX_BUNDLE_PATHS])
    )
    bundle_controls = tuple(
        BundleControl(id=str(control.id), record=control.model_dump())
        for control in overlay.controls
    )

    limitations = [str(note) for note in scan.limitations]
    if len(findings) > MAX_BUNDLE_FINDINGS:
        limitations.append(
            f"evidence bundle projects {MAX_BUNDLE_FINDINGS} of {len(findings)} findings"
        )
    if len(attack_paths) > MAX_BUNDLE_PATHS:
        limitations.append(
            f"evidence bundle projects {MAX_BUNDLE_PATHS} of {len(attack_paths)} attack paths"
        )
    limitations.append(
        "static analysis projection: runtime exposure, effective authorization and "
        "deployed controls remain unverified without separate runtime evidence"
    )

    return EvidenceBundle(
        schema_version=BUNDLE_SCHEMA_VERSION,
        run_id=run_id or _default_run_id(scan),
        findings=bundle_findings,
        paths=bundle_paths,
        controls=bundle_controls,
        limitations=tuple(limitations),
    )


__all__ = [
    "BUNDLE_SCHEMA_VERSION",
    "LEGACY_BUNDLE_SCHEMA_VERSIONS",
    "MAX_BUNDLE_EVIDENCE_REFS",
    "MAX_BUNDLE_FINDINGS",
    "MAX_BUNDLE_PATHS",
    "SUPPORTED_BUNDLE_SCHEMA_VERSIONS",
    "BundleCitationValidation",
    "BundleControl",
    "BundleFinding",
    "BundlePath",
    "BundleSchemaError",
    "EvidenceBundle",
    "build_evidence_bundle",
    "find_uncited_claims",
    "gate_bundle_schema_version",
    "validate_bundle_citations",
]
