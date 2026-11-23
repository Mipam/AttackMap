"""Supply-chain and CI-workflow rule family (AR045).

Ports the three finding branches of the legacy
``threat_model.generate_findings`` cascade that consume the dependency-risk
observations onto the rule kernel, using the AR045-widened
`ReasoningContext` slices (`vulnerabilities`, `workflow_issues`,
`supply_chain_issues`):

- ``vulnerable_dependency`` — CVE/advisory findings on the dependency path
  (#60): one finding per (ecosystem, package, resolved version), every
  advisory affecting it aggregated in the evidence list, transitive
  provenance cited when any advisory is indirect.
- ``workflow_security`` — GitHub Actions findings (#142/#246): one
  aggregated finding per issue kind present, severity the max over that
  kind's issues, evidence lines carrying ``file:line [job/step] — detail``.
- ``supply_chain_risk`` — dependency supply-chain findings beyond CVEs
  (#247): one aggregated finding per issue kind, same max-severity and
  capped-evidence shape.

The legacy cascade remains the active producer until the pipeline wires the
registry (a later task); these rules are proven field-equivalent on the same
inputs by ``tests/rules/test_supply_chain.py``.

Stable rule ids and the legacy (dashed, pre-kernel) ``rule_id`` values they
replace — findings keep every evidence string, location, severity band,
mitigation and tag of the legacy branches; only the suppression key moves to
the new id:

- ``vulnerable_dependency`` ← ``vulnerable-dependency``
- ``workflow_security`` ← ``unpinned-action``, ``pr-target-checkout``,
  ``secret-in-run``, ``script-injection``, ``broad-permissions``,
  ``self-hosted-pr``, ``workflow-run-artifact-poisoning``,
  ``issue-comment-pr-checkout``, ``github-script-injection``,
  ``github-env-injection``, ``default-token-permissions``,
  ``oidc-on-untrusted-trigger``, ``secrets-inherit``,
  ``checkout-persist-credentials``, ``cache-poisoning-pr-target``,
  ``docker-action-unpinned``, ``curl-pipe-shell``
- ``supply_chain_risk`` ← ``dependency-confusion``, ``typosquat-candidate``,
  ``mutable-vcs-dependency``, ``install-script``, ``unlocked-manifest``,
  ``insecure-registry``

Per-kind CWE mapping (``external/cwe/cwe-NNN`` tags) is resolved from the
model taxonomy through each kind's legacy id, so findings carry exactly the
CWE tags they carried before; ``RuleMeta.cwe`` stays empty on the two
aggregated families because no single CWE describes them honestly.
AR046 registered ``vulnerable_dependency`` in ``RULE_TAXONOMY`` from its
1:1 legacy entry, so its findings auto-attach the legacy enrichment; the
two aggregated families stay unregistered on purpose — no single CWE/
OWASP entry honestly describes them, and their per-kind CWE tags already
travel on the findings' ``tags``. Every rule records the dashed ids it
replaces as ``legacy_rule_ids``.
``_dependency_entity_id`` mirrors
``attackmap.output.finding_identity.dependency_entity_id`` byte for byte
(importing it would add a reasoning -> output layer edge; a drift test
guards the lockstep).
"""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING, Literal

from ...foundation.srcpaths import evidence_locations
from ...model import (
    Finding,
    FindingLocation,
    SupplyChainIssue,
    Vulnerability,
    WorkflowIssue,
)
from ...model.taxonomy import cwe_tag, taxonomy_for
from ...policy import SEVERITY_ORDER, SEVERITY_RANK
from ..rule_specs import SUPPLY_CHAIN_FINDING_SPEC, WORKFLOW_FINDING_SPEC
from .base import RuleMeta, confidence_band
from .registry import REGISTRY

if TYPE_CHECKING:
    from ..context import ReasoningContext

__all__ = [
    "SupplyChainRiskRule",
    "VulnerableDependencyRule",
    "WorkflowSecurityRule",
]

# The legacy cascade caps aggregated evidence at the first 10 items and
# collapses the rest into one overflow line; keep the shape identical.
_EVIDENCE_CAP = 10
_Band = Literal["low", "medium", "high"]


def _legacy_rule_id(kind: str) -> str:
    """The dashed legacy rule id of a spec kind (threat_model._rule_slug_kind)."""
    return kind.replace("_", "-")


def _cwe_tags(kind: str) -> list[str]:
    """``external/cwe/cwe-NNN`` tags the legacy branch derived for ``kind``."""
    entry = taxonomy_for(_legacy_rule_id(kind))
    return [cwe_tag(c) for c in entry.cwe] if entry else []


def _locations(items: list[WorkflowIssue | SupplyChainIssue]) -> list[FindingLocation]:
    """Structured locations, de-duplicated on (file, line), in scan order —
    the same shape the legacy ``_locs`` helper emits."""
    out: list[FindingLocation] = []
    seen: set[tuple[str, int | None]] = set()
    for item in items:
        if not item.file:
            continue
        key = (item.file, item.line)
        if key not in seen:
            seen.add(key)
            out.append(FindingLocation(file=item.file, line=item.line))
    return out


def _severity_max(items: list[WorkflowIssue | SupplyChainIssue]) -> _Band:
    """The legacy aggregated severity: the max over the kind's issues."""
    return max((item.severity for item in items), key=SEVERITY_ORDER.__getitem__)


def _dependency_entity_id(ecosystem: str, name: str, version: str) -> str:
    """Stable entity key for one vulnerable package.

    Byte-identical to ``attackmap.output.finding_identity.dependency_entity_id``
    (kept in lockstep by a drift test; importing it here would add a
    reasoning -> output layer edge, which the layer map forbids).
    """
    canonical = json.dumps([ecosystem, name, version], ensure_ascii=True, separators=(",", ":"))
    return "dependency/v1:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _issue_evidence_line(issue: WorkflowIssue | SupplyChainIssue, *, with_context: bool) -> str:
    """One evidence line, byte-identical to the legacy branch's format.

    ``context`` (the workflow's job/step) only exists on workflow issues and
    only joins the line for the workflow family; supply-chain lines are
    ``file:line — detail``.
    """
    loc = f"{issue.file}:{issue.line}" if issue.line else issue.file
    context = getattr(issue, "context", None)
    ctx = f" [{context}]" if with_context and context else ""
    detail = f" — {issue.evidence_text}" if issue.evidence_text else ""
    return f"{loc}{ctx}{detail}"


def _aggregate_kind_findings(
    issues: tuple[WorkflowIssue | SupplyChainIssue, ...],
    spec_table: dict[str, dict[str, str]],
    rule_id: str,
    base_tags: tuple[str, ...],
    confidence_by_kind: dict[str, _Band],
    *,
    with_context: bool,
) -> list[Finding]:
    """The legacy aggregated shape (#142/#247): one finding per spec kind.

    Iterates the spec table in declaration order (deterministic), skips
    kinds with no issues, takes the max severity over the kind's issues and
    caps evidence at the first ten items with a ``+N more`` overflow line.
    """
    by_kind: dict[str, list[WorkflowIssue | SupplyChainIssue]] = {}
    for issue in issues:
        by_kind.setdefault(issue.kind, []).append(issue)
    findings: list[Finding] = []
    for kind, spec in spec_table.items():
        items = by_kind.get(kind)
        if not items:
            continue
        evidence = [_issue_evidence_line(i, with_context=with_context) for i in items[:_EVIDENCE_CAP]]
        if len(items) > _EVIDENCE_CAP:
            evidence.append(f"+{len(items) - _EVIDENCE_CAP} more occurrence(s)")
        findings.append(
            Finding(
                title=spec["title"],
                rule_id=rule_id,
                severity=_severity_max(items),
                evidence=evidence,
                locations=_locations(items),
                mitigation=spec["mitigation"],
                confidence=confidence_by_kind[kind],
                tags=[*base_tags, *_cwe_tags(kind)],
            )
        )
    return findings


class VulnerableDependencyRule:
    """CVE advisories on the dependency path (#60), one finding per package.

    Equivalent port of the legacy branch: advisories are grouped by
    (ecosystem, package name, resolved version) in scan order, the finding
    severity tracks the most severe advisory, and the evidence list carries
    the advisory-count headline, the transitive provenance line (when any
    advisory is indirect) and up to ten advisory lines sorted by severity
    then id. Locations are derived from the evidence prose exactly as the
    legacy ``_fill_missing_locations`` pass derived them.
    """

    meta = RuleMeta(
        id="vulnerable_dependency",
        title="Vulnerable dependency (known advisory on the dependency path)",
        cwe="CWE-1395",
        severity="high",
        confidence=0.9,
        rationale=(
            "A package dependency resolves to a version with a published "
            "advisory; known-vulnerable code on the dependency path is the "
            "most direct supply-chain exposure (CWE-1395), so every advisory "
            "is aggregated into one finding per package for triage."
        ),
        tags=("cve", "dependency"),
    )
    legacy_rule_ids = ("vulnerable-dependency",)

    def evaluate(self, ctx: ReasoningContext) -> list[Finding]:
        findings: list[Finding] = []
        vulns_by_pkg: dict[tuple[str, str, str], list[Vulnerability]] = {}
        for vuln in ctx.vulnerabilities:
            vulns_by_pkg.setdefault(
                (vuln.ecosystem, vuln.package_name, vuln.package_version), []
            ).append(vuln)
        for (eco, name, version), pkg_vulns in vulns_by_pkg.items():
            top_severity = min(
                (SEVERITY_RANK.get(v.severity, 3) for v in pkg_vulns),
                default=SEVERITY_RANK["medium"],
            )
            title_severity_word = {0: "critical", 1: "moderate", 2: "low"}.get(top_severity, "moderate")
            evidence_lines: list[str] = []
            for v in sorted(pkg_vulns, key=lambda x: (SEVERITY_RANK.get(x.severity, 3), x.id)):
                summary_snip = (v.summary[:120] + "…") if len(v.summary) > 120 else v.summary
                aliases = f" (aka {', '.join(v.aliases[:3])})" if v.aliases else ""
                score = f" CVSS {v.cvss_score:.1f}" if v.cvss_score is not None else ""
                ref = v.references[0] if v.references else ""
                ref_part = f" — {ref}" if ref else ""
                evidence_lines.append(f"{v.id}{aliases} [{v.severity}{score}]: {summary_snip}{ref_part}")
            severity: _Band = (
                "high" if top_severity == 0 else ("medium" if top_severity == 1 else "low")
            )
            # Transitive-dependency provenance (#143): cite the resolution
            # path so a reviewer can see how the package was pulled in.
            transitive = next((v for v in pkg_vulns if not v.direct), None)
            provenance_lines: list[str] = []
            if transitive is not None:
                if transitive.resolution_path:
                    provenance_lines.append(
                        f"Transitive dependency — resolution path: {transitive.resolution_path}"
                    )
                else:
                    provenance_lines.append("Transitive (indirect) dependency")
            evidence = [
                f"{len(pkg_vulns)} known advisor{'y' if len(pkg_vulns) == 1 else 'ies'} for "
                f"{title_severity_word}-severity impact",
                *provenance_lines,
                *evidence_lines[:_EVIDENCE_CAP],
            ]
            findings.append(
                Finding(
                    title=f"Vulnerable dependency: {name}@{version} ({eco})",
                    rule_id=self.meta.id,
                    entity_id=_dependency_entity_id(eco, name, version),
                    severity=severity,
                    evidence=evidence,
                    mitigation=(
                        f"Upgrade `{name}` beyond the affected range shown, verify no direct"
                        " or transitive callers depend on removed symbols, and re-run"
                        " `attackmap analyze --cve` to confirm the finding clears."
                    ),
                    confidence=confidence_band(self.meta.confidence),
                    tags=["cve", "dependency", eco],
                    locations=[
                        FindingLocation(file=file, line=line)
                        for file, line in evidence_locations(evidence)
                    ],
                )
            )
        return findings


class WorkflowSecurityRule:
    """GitHub Actions workflow findings (#142/#246), one per issue kind.

    Equivalent port of the legacy branch: findings aggregate every issue of
    a kind, severity is the max over that kind's issues, evidence lines keep
    the ``file:line [context] — detail`` structure (the workflow's job/step
    context survives verbatim) with the legacy ten-item cap, and tags carry
    the kind's taxonomy CWE tags. Confidence is ``high`` for every kind,
    exactly as the legacy branch emitted.
    """

    meta = RuleMeta(
        id="workflow_security",
        title="CI workflow security issue (GitHub Actions)",
        cwe="",
        severity="high",
        confidence=0.9,
        rationale=(
            "A workflow file contains a positively-present CI misconfiguration — "
            "an unpinned action, an untrusted checkout, an interpolated secret, "
            "write-all token permissions, OIDC on an untrusted trigger — that "
            "lets a pushed commit or PR run attacker-chosen code with the "
            "repository's token and secrets in scope. Per-kind CWE tags are "
            "attached to each finding from the taxonomy."
        ),
        tags=("ci-security", "supply-chain"),
    )
    # One aggregated rule replaces the whole per-kind dashed family; the
    # legacy ids stay registered (they key the cascade's findings and the
    # per-kind CWE resolution) and are surfaced by the generated docs.
    legacy_rule_ids = tuple(_legacy_rule_id(kind) for kind in WORKFLOW_FINDING_SPEC)

    def evaluate(self, ctx: ReasoningContext) -> list[Finding]:
        return _aggregate_kind_findings(
            ctx.workflow_issues,
            WORKFLOW_FINDING_SPEC,
            self.meta.id,
            ("ci-security", "supply-chain"),
            {kind: "high" for kind in WORKFLOW_FINDING_SPEC},
            with_context=True,
        )


class SupplyChainRiskRule:
    """Dependency supply-chain findings beyond CVEs (#247), one per kind.

    Equivalent port of the legacy branch: dependency-confusion, typosquat,
    mutable VCS/URL pins, install scripts, unlocked manifests and insecure
    registries aggregate per kind with the max instance severity; only the
    typosquat kind keeps the legacy ``medium`` confidence band.
    """

    meta = RuleMeta(
        id="supply_chain_risk",
        title="Dependency supply-chain risk",
        cwe="",
        severity="medium",
        confidence=0.8,
        rationale=(
            "A manifest, lockfile or package-manager config contains a "
            "positively-present supply-chain risk — an internal-looking name "
            "resolvable from a public registry, a one-edit distance from a "
            "popular package, a mutable VCS pin, an install hook, a missing "
            "lockfile/integrity hash, or plain-HTTP registry traffic. Per-kind "
            "CWE tags are attached to each finding from the taxonomy."
        ),
        tags=("supply-chain", "dependency-risk"),
    )
    legacy_rule_ids = tuple(_legacy_rule_id(kind) for kind in SUPPLY_CHAIN_FINDING_SPEC)

    def evaluate(self, ctx: ReasoningContext) -> list[Finding]:
        return _aggregate_kind_findings(
            ctx.supply_chain_issues,
            SUPPLY_CHAIN_FINDING_SPEC,
            self.meta.id,
            ("supply-chain", "dependency-risk"),
            {kind: ("medium" if kind == "typosquat_candidate" else "high") for kind in SUPPLY_CHAIN_FINDING_SPEC},
            with_context=False,
        )


REGISTRY.register(VulnerableDependencyRule())
REGISTRY.register(WorkflowSecurityRule())
REGISTRY.register(SupplyChainRiskRule())
