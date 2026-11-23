"""AR045 tests: supply-chain/workflow rule port and the context widening.

The rules in ``attackmap.reasoning.rules.supply_chain`` re-emit exactly the
findings the legacy ``threat_model.generate_findings`` cascade produces for
the #60 CVE, #142 GitHub-workflow and #247 dependency supply-chain branches;
the equivalence tests run BOTH producers on the same in-code fixture scans
and compare every preserved field (title, severity, confidence band,
mitigation, evidence, locations, tags). Fixtures follow the todo card: an
unpinned action, curl-pipe-bash, a write-all token, OIDC misuse, a CVE on
the dependency path, plus a negative (hardened) scan.

Self-contained by design: models are built in-code, no shared conftest or
harness (AR047 owns those).
"""

from __future__ import annotations

import pytest

from attackmap.model import Finding, ScanResult, SupplyChainIssue, Vulnerability, WorkflowIssue
from attackmap.output.finding_identity import dependency_entity_id
from attackmap.reasoning import REGISTRY, ReasoningContext
from attackmap.reasoning.rule_specs import SUPPLY_CHAIN_FINDING_SPEC, WORKFLOW_FINDING_SPEC
from attackmap.reasoning.rules import supply_chain as supply_chain_rules
from attackmap.reasoning.rules.supply_chain import (
    SupplyChainRiskRule,
    VulnerableDependencyRule,
    WorkflowSecurityRule,
    _dependency_entity_id,
)
from attackmap.reasoning.threat_model import generate_findings

pytestmark = [pytest.mark.unit]

NEW_RULE_IDS = ("vulnerable_dependency", "workflow_security", "supply_chain_risk")

# The legacy producer emits one finding per kind under the dashed rule id.
_TITLE_TO_WORKFLOW_KIND = {spec["title"]: kind for kind, spec in WORKFLOW_FINDING_SPEC.items()}
_TITLE_TO_SUPPLY_KIND = {spec["title"]: kind for kind, spec in SUPPLY_CHAIN_FINDING_SPEC.items()}

# Fields the AR045 port must preserve exactly; rule_id intentionally moves to
# the new stable snake_case id, and taxonomy/attack_techniques re-attach when
# the new ids are registered in the taxonomy (AR046).
_PRESERVED_FIELDS = ("title", "severity", "confidence", "mitigation", "evidence", "locations", "tags")


# --- fixtures (todo card AR045 step 3) ---------------------------------------


def _workflow_scan() -> ScanResult:
    """Unpinned action, curl-pipe-bash, write-all token and OIDC misuse."""
    return ScanResult(
        root="C:/tmp/fake-repo",
        workflow_issues=[
            WorkflowIssue(
                kind="unpinned_action",
                file=".github/workflows/ci.yml",
                line=31,
                context="build",
                evidence_text="uses: actions/checkout@v4",
                severity="medium",
            ),
            WorkflowIssue(
                kind="unpinned_action",
                file=".github/workflows/release.yml",
                line=9,
                evidence_text="uses: actions/upload-artifact@v3",
                severity="high",
            ),
            WorkflowIssue(
                kind="curl_pipe_shell",
                file=".github/workflows/setup.yml",
                line=14,
                context="install",
                evidence_text="run: curl -fsSL https://example.com/install.sh | sh",
                severity="high",
            ),
            WorkflowIssue(
                kind="broad_permissions",
                file=".github/workflows/ci.yml",
                line=5,
                evidence_text="permissions: write-all",
                severity="high",
            ),
            WorkflowIssue(
                kind="oidc_on_untrusted_trigger",
                file=".github/workflows/deploy.yml",
                line=17,
                context="deploy",
                evidence_text="id-token: write on pull_request_target",
                severity="high",
            ),
            # No line and no context: the evidence line is bare "file — detail".
            WorkflowIssue(
                kind="broad_permissions",
                file=".github/workflows/other.yml",
                evidence_text="permissions: write-all",
                severity="medium",
            ),
        ],
    )


def _cve_scan() -> ScanResult:
    """CVE-on-path: a direct package with two advisories plus a transitive one."""
    return ScanResult(
        root="C:/tmp/fake-repo",
        vulnerabilities=[
            Vulnerability(
                id="GHSA-35jh-r3h4-6jhm",
                aliases=["CVE-2021-23337"],
                summary="Command injection in lodash template",
                severity="high",
                cvss_score=7.2,
                references=["https://nvd.example/CVE-2021-23337"],
                package_name="lodash",
                package_version="4.17.20",
                ecosystem="npm",
                direct=True,
            ),
            Vulnerability(
                id="CVE-2020-8203",
                summary="Prototype pollution in lodash",
                severity="high",
                package_name="lodash",
                package_version="4.17.20",
                ecosystem="npm",
                direct=True,
            ),
            Vulnerability(
                id="CVE-2022-24999",
                summary="qs DoS via many = signs",
                severity="low",
                package_name="qs",
                package_version="6.5.2",
                ecosystem="npm",
                direct=False,
                resolution_path="express > body-parser > qs",
            ),
        ],
    )


def _supply_chain_scan() -> ScanResult:
    """Dependency findings: insecure registry, confusion, typosquat, unlocked."""
    return ScanResult(
        root="C:/tmp/fake-repo",
        supply_chain_issues=[
            SupplyChainIssue(
                kind="insecure_registry",
                file=".npmrc",
                line=2,
                ecosystem="npm",
                evidence_text="registry=http://registry.example.com — index reachable over plain http",
                severity="high",
            ),
            SupplyChainIssue(
                kind="dependency_confusion",
                file="requirements.txt",
                line=6,
                package="internal-tools",
                ecosystem="pypi",
                evidence_text="internal-tools is installed with --extra-index-url (requirements.txt)",
                severity="high",
            ),
            SupplyChainIssue(
                kind="typosquat_candidate",
                file="package.json",
                line=13,
                package="lodah",
                ecosystem="npm",
                evidence_text="lodah is one edit away from the popular package lodash",
                severity="medium",
            ),
            SupplyChainIssue(
                kind="unlocked_manifest",
                file="package.json",
                ecosystem="npm",
                evidence_text="package.json declares dependencies but no lockfile is committed",
                severity="low",
            ),
        ],
    )


def _clean_scan() -> ScanResult:
    """Negative case: a hardened repo — no workflow, CVE or supply-chain issues."""
    return ScanResult(root="C:/tmp/fake-repo", scanned_files=[".github/workflows/ci.yml"], files_scanned=1)


# --- shared equivalence helpers ----------------------------------------------


def _legacy_findings(scan: ScanResult) -> list[Finding]:
    """The old-cascade findings for a fixture scan (still the active producer)."""
    return generate_findings(scan)


def _assert_finding_equivalent(new: Finding, old: Finding) -> None:
    for field in _PRESERVED_FIELDS:
        assert getattr(new, field) == getattr(old, field), f"field {field} differs"


def _old_by_title(findings: list[Finding]) -> dict[str, Finding]:
    return {f.title: f for f in findings}


def _legacy_id(kind: str) -> str:
    """The dashed legacy rule id of a spec kind."""
    return kind.replace("_", "-")


# --- rule metadata and registration ------------------------------------------


def test_rules_register_with_stable_ids():
    for rule_id in NEW_RULE_IDS:
        rule = REGISTRY.get(rule_id)
        assert rule is not None, rule_id
        assert rule.meta.id == rule_id  # ^[a-z][a-z0-9_]*$, stable + suppressible


def test_legacy_rule_id_mappings_are_documented():
    """Every legacy dashed id replaced by this family is in the module docstring."""
    doc = supply_chain_rules.__doc__ or ""
    legacy_ids = ["vulnerable-dependency"]
    legacy_ids += [_legacy_id(kind) for kind in WORKFLOW_FINDING_SPEC]
    legacy_ids += [_legacy_id(kind) for kind in SUPPLY_CHAIN_FINDING_SPEC]
    missing = [legacy for legacy in legacy_ids if legacy not in doc]
    assert not missing, f"legacy ids missing from module docstring: {missing}"


def test_context_widening_carries_supply_chain_slices():
    scan = _workflow_scan()
    scan.supply_chain_issues = _supply_chain_scan().supply_chain_issues
    scan.vulnerabilities = _cve_scan().vulnerabilities
    ctx = ReasoningContext.from_scan(scan)
    assert isinstance(ctx.workflow_issues, tuple)
    assert isinstance(ctx.vulnerabilities, tuple)
    assert isinstance(ctx.supply_chain_issues, tuple)
    assert len(ctx.workflow_issues) == 6
    assert len(ctx.vulnerabilities) == 3
    assert len(ctx.supply_chain_issues) == 4
    # Records are shared by reference (AR022 convention), never the scan lists.
    assert ctx.workflow_issues[0] is scan.workflow_issues[0]
    assert not hasattr(ctx, "scan")
    assert "scan" not in ReasoningContext.model_fields


# --- CVE-on-path (#60) --------------------------------------------------------


@pytest.mark.rule("vulnerable_dependency")
def test_cve_on_path_equivalence():
    scan = _cve_scan()
    old = _old_by_title([f for f in _legacy_findings(scan) if f.rule_id == "vulnerable-dependency"])
    new = VulnerableDependencyRule().evaluate(ReasoningContext.from_scan(scan))
    assert {f.title for f in new} == set(old)
    for finding in new:
        assert finding.rule_id == "vulnerable_dependency"
        _assert_finding_equivalent(finding, old[finding.title])


@pytest.mark.rule("vulnerable_dependency")
def test_cve_finding_groups_advisories_and_cites_transitive_path():
    findings = {f.title: f for f in VulnerableDependencyRule().evaluate(ReasoningContext.from_scan(_cve_scan()))}
    lodash = findings["Vulnerable dependency: lodash@4.17.20 (npm)"]
    assert lodash.severity == "high"
    assert lodash.evidence[0] == "2 known advisories for critical-severity impact"
    assert any(line.startswith("CVE-2020-8203") for line in lodash.evidence)
    assert any("(aka CVE-2021-23337)" in line for line in lodash.evidence)
    qs = findings["Vulnerable dependency: qs@6.5.2 (npm)"]
    assert qs.severity == "low"
    assert "Transitive dependency — resolution path: express > body-parser > qs" in qs.evidence
    assert qs.tags == ["cve", "dependency", "npm"]
    assert qs.confidence == "high"


@pytest.mark.rule("vulnerable_dependency")
def test_entity_id_matches_canonical_identity():
    """The ported entity key stays byte-identical to the canonical helper."""
    assert _dependency_entity_id("npm", "lodash", "4.17.20") == dependency_entity_id("npm", "lodash", "4.17.20")
    findings = list(VulnerableDependencyRule().evaluate(ReasoningContext.from_scan(_cve_scan())))
    lodash = next(f for f in findings if "lodash" in f.title)
    assert lodash.entity_id == _dependency_entity_id("npm", "lodash", "4.17.20")
    qs = next(f for f in findings if "qs@" in f.title)
    assert qs.entity_id == dependency_entity_id("npm", "qs", "6.5.2")


# --- GitHub workflows (#142/#246) ---------------------------------------------


@pytest.mark.rule("workflow_security")
def test_workflow_findings_equivalence():
    scan = _workflow_scan()
    old_by_title = _old_by_title(_legacy_findings(scan))
    new = WorkflowSecurityRule().evaluate(ReasoningContext.from_scan(scan))
    kinds_present = {issue.kind for issue in scan.workflow_issues}
    assert {f.rule_id for f in new} == {"workflow_security"}
    assert {_TITLE_TO_WORKFLOW_KIND[f.title] for f in new} == kinds_present
    for finding in new:
        legacy_id = _legacy_id(_TITLE_TO_WORKFLOW_KIND[finding.title])
        old = old_by_title[finding.title]
        assert old.rule_id == legacy_id  # the compared branch is the legacy one
        _assert_finding_equivalent(finding, old)


@pytest.mark.rule("workflow_security")
def test_workflow_evidence_structure_is_intact():
    """Evidence lines keep the legacy ``file:line [job/step] — detail`` shape."""
    findings = {f.title: f for f in WorkflowSecurityRule().evaluate(ReasoningContext.from_scan(_workflow_scan()))}
    unpinned = findings["Unpinned GitHub Action (not pinned to a commit SHA)"]
    assert unpinned.evidence == [
        ".github/workflows/ci.yml:31 [build] — uses: actions/checkout@v4",
        ".github/workflows/release.yml:9 — uses: actions/upload-artifact@v3",
    ]
    # Max instance severity: the medium tag + the high release issue -> high.
    assert unpinned.severity == "high"
    assert unpinned.tags == ["ci-security", "supply-chain", "external/cwe/cwe-829", "external/cwe/cwe-1357"]
    oidc = findings["OIDC token (id-token: write) available to pull-request-triggered workflow"]
    # Evidence text is redacted at model construction (#235), before either
    # producer sees it — the shared record carries the same redacted string.
    assert oidc.evidence == [".github/workflows/deploy.yml:17 [deploy] — id-token: *** on pull_request_target"]
    bare = findings["Over-broad GITHUB_TOKEN permissions (write-all)"]
    assert ".github/workflows/other.yml — permissions: write-all" in bare.evidence
    assert ".github/workflows/ci.yml:5 — permissions: write-all" in bare.evidence
    curl = findings["Remote script piped into a shell in CI (curl | sh)"]
    assert curl.locations[0].file == ".github/workflows/setup.yml"
    assert curl.locations[0].line == 14


@pytest.mark.rule("workflow_security")
def test_workflow_evidence_cap_and_location_dedupe():
    issues = [
        WorkflowIssue(
            kind="unpinned_action",
            file=".github/workflows/shared.yml" if index < 2 else f".github/workflows/w{index}.yml",
            line=7 if index < 2 else index,
            evidence_text=f"uses: actions/checkout@v4 #{index}",
            severity="medium",
        )
        for index in range(12)
    ]
    ctx = ReasoningContext(workflow_issues=tuple(issues))
    findings = WorkflowSecurityRule().evaluate(ctx)
    assert len(findings) == 1
    finding = findings[0]
    assert len(finding.evidence) == 11  # 10 capped lines + the legacy overflow line
    assert finding.evidence[-1] == "+2 more occurrence(s)"
    # Issues 0 and 1 share (file, line): one merged location.
    assert len(finding.locations) == 11


# --- dependency supply-chain (#247) -------------------------------------------


@pytest.mark.rule("supply_chain_risk")
def test_dependency_findings_equivalence():
    scan = _supply_chain_scan()
    old_by_title = _old_by_title(_legacy_findings(scan))
    new = SupplyChainRiskRule().evaluate(ReasoningContext.from_scan(scan))
    kinds_present = {issue.kind for issue in scan.supply_chain_issues}
    assert {f.rule_id for f in new} == {"supply_chain_risk"}
    assert {_TITLE_TO_SUPPLY_KIND[f.title] for f in new} == kinds_present
    for finding in new:
        legacy_id = _legacy_id(_TITLE_TO_SUPPLY_KIND[finding.title])
        old = old_by_title[finding.title]
        assert old.rule_id == legacy_id
        _assert_finding_equivalent(finding, old)


@pytest.mark.rule("supply_chain_risk")
def test_typosquat_keeps_medium_confidence_band():
    findings = {
        f.title: f
        for f in SupplyChainRiskRule().evaluate(ReasoningContext.from_scan(_supply_chain_scan()))
    }
    typosquat = findings["Possible typosquatted dependency (one edit from a popular package)"]
    assert typosquat.confidence == "medium"
    registry = findings["Package registry reached over plain HTTP or without TLS verification"]
    assert registry.confidence == "high"
    assert registry.severity == "high"
    assert registry.evidence == [
        ".npmrc:2 — registry=http://registry.example.com — index reachable over plain http"
    ]


# --- negative case -------------------------------------------------------------


@pytest.mark.rule("vulnerable_dependency", "workflow_security", "supply_chain_risk")
def test_clean_scan_produces_no_supply_chain_findings():
    ctx = ReasoningContext.from_scan(_clean_scan())
    assert VulnerableDependencyRule().evaluate(ctx) == []
    assert WorkflowSecurityRule().evaluate(ctx) == []
    assert SupplyChainRiskRule().evaluate(ctx) == []
    result = REGISTRY.evaluate_all(ctx)
    assert result.errors == []
    assert {f.rule_id for f in result.findings}.isdisjoint(NEW_RULE_IDS)


# --- kernel end-to-end ----------------------------------------------------------


@pytest.mark.rule("vulnerable_dependency", "workflow_security", "supply_chain_risk")
def test_registry_evaluate_all_runs_the_family():
    scan = _workflow_scan()
    scan.vulnerabilities = _cve_scan().vulnerabilities
    scan.supply_chain_issues = _supply_chain_scan().supply_chain_issues
    result = REGISTRY.evaluate_all(ReasoningContext.from_scan(scan))
    assert result.errors == []
    by_id: dict[str, list[Finding]] = {rule_id: [] for rule_id in NEW_RULE_IDS}
    for finding in result.findings:
        if finding.rule_id in by_id:
            by_id[finding.rule_id].append(finding)
    assert len(by_id["vulnerable_dependency"]) == 2
    assert len(by_id["workflow_security"]) == 4  # one aggregated finding per kind present
    assert len(by_id["supply_chain_risk"]) == 4
    rules = {rule_id: REGISTRY.get(rule_id) for rule_id in NEW_RULE_IDS}
    for rule_id, family in by_id.items():
        for finding in family:
            assert finding.rule_id == rules[rule_id].meta.id
