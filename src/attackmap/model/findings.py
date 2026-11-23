"""Findings, assets, controls and insights (#214, #223, #250)."""


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator

from .evidence import _RedactedEvidence
from .paths import ExploitabilityScoreReference, ExploitabilityTier, TaintFlowStep


class AttackTechnique(BaseModel):
    """Reference to a MITRE ATT&CK technique (Enterprise matrix)."""

    technique_id: str  # e.g., "T1190", "T1078.004"
    name: str  # e.g., "Exploit Public-Facing Application"
    tactic: str  # e.g., "Initial Access"
    url: str | None = None  # https://attack.mitre.org/techniques/T1190/


def title_slug(title: str) -> str:
    """Legacy rule id: the slugified finding title (pre-#223)."""
    import re as _re

    slug = _re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    return slug or "finding"


def finding_rule_id(finding: Finding) -> str:
    """The finding's stable rule id, or its title slug when it has none."""
    return finding.rule_id or title_slug(finding.title)


class FindingLocation(BaseModel):
    """A file (and line, when known) a finding applies to (#214). Carried
    structurally so SARIF, suppression and diffing don't have to parse
    evidence prose."""

    file: str
    line: int | None = None
    # Instance identity across runs (#222): rule + file + normalized source
    # line, without the line number. Set by `fingerprint.assign_fingerprints`.
    fingerprint: str | None = None


class FindingTaxonomy(BaseModel):
    """Standard ids for a finding's rule (#250), looked up by `rule_id` in
    `attackmap.taxonomy` — never inferred from title or evidence text."""

    cwe: list[str] = Field(default_factory=list)  # ["CWE-918"]
    owasp: list[str] = Field(default_factory=list)  # ["A10:2021", "API7:2023"]
    asvs: list[str] = Field(default_factory=list)  # ASVS 4.0.3, ["V12.6.1"]
    attack: list[str] = Field(default_factory=list)  # ["T1190", "T1552.005"]


class Finding(_RedactedEvidence):
    title: str
    severity: Literal["low", "medium", "high"]
    # Stable, short detector id (#223) — SARIF ruleId and suppress `rule:`.
    # Titles are prose and may be reworded; this never changes. `None` for
    # findings from callers that don't set one (falls back to the title slug).
    rule_id: str | None = None
    # Stable detector-owned entity key for rules emitting multiple findings.
    # Aggregate rules leave this unset; never derive it from display prose.
    entity_id: str | None = None
    evidence: list[str] = Field(default_factory=list)
    # Why this finding exists, in the detector's own words (AR049/AC-207):
    # the rule's rationale plus the concrete observation that fired. Every
    # finding a scan emits must carry a non-empty rationale; the default only
    # keeps hand-built/test fixtures constructible. `evidence` above is the
    # finding's evidence-reference list — at least one entry is required on
    # emitted findings alongside this field.
    rationale: str = ""
    # Every location the finding covers — not capped like `evidence` (#214).
    locations: list[FindingLocation] = Field(default_factory=list)
    mitigation: str
    confidence: Literal["low", "medium", "high"] = "medium"
    attack_techniques: list[AttackTechnique] = Field(default_factory=list)
    # Optional categorization tags. Vocabulary (see #4): exposed-endpoint,
    # auth-missing, data-risk, secret-exposure, integration-risk,
    # framework-chain, service-chain, atproto-chain, weak-signal. Multiple
    # tags may apply per finding.
    tags: list[str] = Field(default_factory=list)
    # Numeric prioritization score (higher = triage first within the same
    # severity band). Computed from severity + confidence; used as a
    # secondary sort key. `None` means "not scored" for backward compat.
    score: int | None = None
    # Fused 'exploitable now' score (#79), 0-100, with a tier. Set on
    # findings that sit on a route→sink path; `None` when not applicable.
    exploitability: int | None = None
    exploitability_tier: ExploitabilityTier | None = None
    # Exact producer decision; absent on legacy findings. Never infer from value.
    exploitability_reference: ExploitabilityScoreReference | None = None
    # Source→sink steps behind a taint finding (#239), one list per traced
    # flow; emitted as SARIF `codeFlows` on the matching sink result.
    code_flows: list[list[TaintFlowStep]] = Field(default_factory=list)
    # CWE / OWASP / ASVS / ATT&CK ids for `rule_id` (#250). Filled from the
    # registry on construction; `None` for rules it doesn't know.
    taxonomy: FindingTaxonomy | None = None

    @model_validator(mode="after")
    def _apply_rule_taxonomy(self) -> Finding:
        from attackmap.model.taxonomy import ATTACK_TECHNIQUES, attack_url, taxonomy_for

        entry = taxonomy_for(self.rule_id)
        if entry is None:
            return self
        if self.taxonomy is None:
            object.__setattr__(
                self,
                "taxonomy",
                FindingTaxonomy(
                    cwe=entry.cwe_ids, owasp=list(entry.owasp), asvs=list(entry.asvs), attack=list(entry.attack)
                ),
            )
        if entry.attack:
            # The registry is authoritative for ATT&CK on registered rules.
            object.__setattr__(
                self,
                "attack_techniques",
                [
                    AttackTechnique(technique_id=tid, name=name, tactic=tactic, url=attack_url(tid))
                    for tid in entry.attack
                    for name, tactic in [ATTACK_TECHNIQUES[tid]]
                ],
            )
        return self


AssetKind = Literal[
    "credentials",
    "session",
    "user_pii",
    "payment",
    "internal_secret",
    "audit_log",
    "business_data",
    "configuration",
]


class Asset(_RedactedEvidence):
    id: str
    kind: AssetKind
    name: str
    criticality: Literal["critical", "high", "medium", "low"]
    locations: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)


ControlKind = Literal[
    "authentication",
    "authorization",
    "input_validation",
    "output_encoding",
    "rate_limiting",
    "csrf_protection",
    "encryption_at_rest",
    "encryption_in_transit",
    "audit_logging",
    "rbac",
    "mfa",
    "secret_management",
    "security_headers",
]


ControlStrength = Literal["strong", "moderate", "weak", "absent"]


class Control(_RedactedEvidence):
    id: str
    kind: ControlKind
    name: str
    strength: ControlStrength
    scope: Literal["global", "module", "route", "service", "asset"]
    placements: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    notes: str | None = None


InsightKind = Literal[
    "shared_secret_blast_radius",
    "sensitive_asset_reachability",
    "control_bypass",
    "defense_gap_in_chain",
    "asymmetric_protection",
    "trust_boundary_violation",
    "audit_gap",
    "control_strength_mismatch",
    "single_point_of_failure",
    "stale_or_contradictory_signal",
    "admin_action_without_auth",
]


class Insight(_RedactedEvidence):
    id: str
    kind: InsightKind
    title: str
    narrative: str
    severity: Literal["critical", "high", "medium", "low", "informational"]
    confidence: Literal["high", "medium", "low"]
    evidence: list[str] = Field(default_factory=list)
    related_assets: list[str] = Field(default_factory=list)
    related_controls: list[str] = Field(default_factory=list)
    related_routes: list[str] = Field(default_factory=list)
    suggested_action: str | None = None
    attack_techniques: list[AttackTechnique] = Field(default_factory=list)


class DetectionOpportunity(BaseModel):
    """A defender-facing detection-engineering hint produced from an insight or finding.

    Designed to answer: "given this static-analysis finding, what runtime
    detection signal would catch the same condition in production?"
    """

    id: str
    title: str
    rationale: str
    signal_kind: Literal["log", "metric", "trace", "network", "config_audit"]
    suggested_rule: str  # human-readable rule sketch (Sigma/KQL/Splunk-style)
    related_insight_ids: list[str] = Field(default_factory=list)
    related_finding_titles: list[str] = Field(default_factory=list)
    # Rule ids of the linked findings (#250), linked via the taxonomy registry.
    related_rule_ids: list[str] = Field(default_factory=list)
    attack_techniques: list[AttackTechnique] = Field(default_factory=list)
