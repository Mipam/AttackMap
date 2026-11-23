"""Wiring-pass tests: the 49-rule REGISTRY is the scan pipeline's producer.

Owner decision 2026-11-23 (commit 11ed09d): reports switch to the registry's
snake_case rule ids and the ported legacy cascade branches inside
``threat_model.generate_findings`` are retired. These tests pin what the
wiring itself guarantees, on top of the per-rule suites in ``tests/rules``:

* ported families emit snake_case ids through ``generate_findings`` — no
  dashed counterpart appears, and the dashed ids of the *kept* cascade
  branches are still there (the two producers must not duplicate each other);
* the demo rule (the AR048 FN-becomes-TP) flows into pipeline reports, while
  the four AR042 edge rules stay registry-only (deliberately not merged);
* exploitability fusion still attaches to the aggregated registry taint
  finding exactly as it did to the cascade's;
* ``limited-surface`` and the unported dashed-id branches behave as before.

Self-contained: fixtures are built in-code, ``unit`` tier.
"""

from __future__ import annotations

import pytest

from attackmap.model import (
    Finding,
    Route,
    ScanResult,
    SecretHint,
    TaintChain,
    Vulnerability,
    WebHardeningIssue,
)
from attackmap.reasoning import REGISTRY
from attackmap.reasoning.exploitability import best_by_sink_kind, score_exploitability
from attackmap.reasoning.threat_model import (
    _REGISTRY_ONLY_RULE_IDS,
    compute_finding_score,
    generate_findings,
)

pytestmark = [pytest.mark.unit]

# Dashed ids the retired cascade branches used for the now-registry families;
# none of these may appear in pipeline output anymore.
RETIRED_DASHED_IDS = {
    "public-webhook",
    "exposed-admin-route",
    "upload-route",
    "weak-auth-route",
    "hardcoded-secret",
    "secret-env-reference",
    "debug-enabled",
    "vulnerable-dependency",
}

# Dashed ids of cascade branches generate_findings still owns.
KEPT_DASHED_IDS = {
    "unauth-outbound-integration",
    "secret-in-git-history",
    "public-data-route",
    "limited-surface",
    "bola-modify",
}


def _registry_ported_ids() -> set[str]:
    """Registered ids that replaced a retired cascade branch (legacy ids recorded)."""
    from attackmap.reasoning.rules.route_auth import (
        RouteExposedAdminRule,
        RoutePublicWebhookRule,
        RouteUploadImportRule,
        RouteWeakAuthControlsRule,
    )
    from attackmap.reasoning.rules.secrets import (
        DebugModeExposureRule,
        HardcodedSecretLiteralsRule,
        SecretEnvReferencesRule,
    )
    from attackmap.reasoning.rules.supply_chain import (
        SupplyChainRiskRule,
        VulnerableDependencyRule,
        WorkflowSecurityRule,
    )
    from attackmap.reasoning.rules.taint_flow import (
        FLOW_SINK_RULES,
        SPECULATIVE_RULES,
        TAINT_SINK_RULES,
    )

    ids = {rule.meta.id for rule in TAINT_SINK_RULES + FLOW_SINK_RULES + SPECULATIVE_RULES}
    ids |= {
        cls.meta.id
        for cls in (
            RoutePublicWebhookRule,
            RouteExposedAdminRule,
            RouteUploadImportRule,
            RouteWeakAuthControlsRule,
            HardcodedSecretLiteralsRule,
            SecretEnvReferencesRule,
            DebugModeExposureRule,
            VulnerableDependencyRule,
            WorkflowSecurityRule,
            SupplyChainRiskRule,
        )
    }
    return ids


def _wired_scan() -> ScanResult:
    """One scan touching every ported family plus a kept dashed-id branch."""
    return ScanResult(
        root="C:/tmp/fake-repo",
        routes=[
            Route(path="/admin/users", method="ANY", file="app/admin.py", line=10),
            Route(path="/login", method="POST", file="app/web.py", line=30),
        ],
        taint_chains=[
            TaintChain(
                route_path="/run",
                route_method="POST",
                route_file="app/web.py",
                sink_kind="eval",
                sink_file="svc/dynamic.py",
                sink_line=10,
                hops=1,
                files=["app/web.py", "svc/dynamic.py"],
                evidence_text="eval(expr)",
                confidence=0.6,
            )
        ],
        secret_hints=[
            SecretHint(
                name="exam…",
                file="app/settings.py",
                line=12,
                kind="credential_assignment",
                confidence=0.9,
                evidence_text='ADMIN_PASSWORD = "***"',
            ),
        ],
        web_hardening_issues=[
            WebHardeningIssue(
                kind="weak_csp",
                file="app/middleware.py",
                line=9,
                evidence_text="unsafe-inline",
                severity="medium",
            ),
        ],
        vulnerabilities=[
            Vulnerability(
                id="CVE-2020-8203",
                summary="Prototype pollution in lodash",
                severity="high",
                package_name="lodash",
                package_version="4.17.20",
                ecosystem="npm",
                direct=True,
            ),
        ],
        scanned_files=["app/admin.py", "app/web.py", "svc/dynamic.py", "app/settings.py"],
        files_scanned=4,
    )


def test_ported_families_emit_snake_case_ids_and_no_dashed_counterparts():
    findings = generate_findings(_wired_scan(), attack_surfaces=[])
    ids = {finding.rule_id for finding in findings}
    ported = _registry_ported_ids()
    assert ported & ids, "no ported registry finding flowed into the pipeline"
    assert ids.isdisjoint(RETIRED_DASHED_IDS), ids & RETIRED_DASHED_IDS
    for finding in findings:
        if finding.rule_id in ported:
            assert finding.rule_id.isidentifier()
            assert finding.score == compute_finding_score(finding.severity, finding.confidence)


def test_kept_cascade_branches_still_emit_dashed_ids():
    findings = generate_findings(_wired_scan(), attack_surfaces=[])
    ids = {finding.rule_id for finding in findings}
    # weak_csp is a kept web-hardening kind: its dashed spec id still fires
    # alongside the registry findings (debug_enabled was the only ported one).
    assert "weak-csp" in ids, ids
    # No registry-only ids leak into the pipeline.
    assert ids.isdisjoint(_REGISTRY_ONLY_RULE_IDS)


def test_edge_rules_are_not_merged_into_pipeline_reports():
    assert {
        "same_file_datastore_edge",
        "same_file_external_edge",
        "same_module_datastore_edge",
        "same_module_external_edge",
    } == _REGISTRY_ONLY_RULE_IDS
    findings = generate_findings(_wired_scan(), attack_surfaces=[])
    assert {f.rule_id for f in findings}.isdisjoint(_REGISTRY_ONLY_RULE_IDS)
    # They remain registered and evaluable through the registry, though.
    for rule_id in _REGISTRY_ONLY_RULE_IDS:
        assert REGISTRY.get(rule_id) is not None


def test_demo_rule_flows_into_pipeline_reports():
    """The AR048 demo rule (no legacy ids) merges like any other registry rule."""
    scan = ScanResult(
        root="C:/tmp/fake-repo",
        secret_hints=[
            SecretHint(
                name="default_admin_password",
                file="app/boot.py",
                line=3,
                kind="default_credential",
                confidence=0.9,
                evidence_text='DEFAULT_ADMIN_PASSWORD = "***"',
            ),
        ],
        scanned_files=["app/boot.py"],
        files_scanned=1,
    )
    findings = generate_findings(scan, attack_surfaces=[])
    demo = [f for f in findings if f.rule_id == "demo_weak_default_credentials"]
    assert len(demo) == 1
    # It suppresses the limited-surface fallback: a real finding exists.
    assert all(f.rule_id != "limited-surface" for f in findings)


def test_exploitability_fusion_attaches_to_registry_taint_finding():
    scan = _wired_scan()
    findings = generate_findings(scan, attack_surfaces=[])
    taint = [f for f in findings if f.rule_id == "taint_sink_eval"]
    assert len(taint) == 1
    expected = best_by_sink_kind(score_exploitability(scan, [])).get("eval")
    if expected is None:
        assert taint[0].exploitability is None
    else:
        assert taint[0].exploitability == expected.score
        assert taint[0].exploitability_tier == expected.tier
    # Speculative recall findings never receive fusion, as with the cascade.
    assert all(
        f.exploitability is None for f in findings if "speculative" in f.tags
    )


def test_speculative_findings_carry_registry_ids_in_pipeline():
    scan = ScanResult(
        root="C:/tmp/fake-repo",
        routes=[Route(path="/run", method="POST", file="app/web.py")],
        taint_chains=[
            TaintChain(
                route_path="/run",
                route_method="POST",
                route_file="app/web.py",
                sink_kind="exec",
                sink_file="svc/runner.py",
                sink_line=5,
                hops=0,
                files=["app/web.py", "svc/runner.py"],
                speculative=True,
                confidence=0.3,
            )
        ],
        scanned_files=["app/web.py", "svc/runner.py"],
        files_scanned=2,
    )
    findings = generate_findings(scan, attack_surfaces=[])
    assert {f.rule_id for f in findings} == {"taint_speculative_exec"}


def test_unported_secret_history_branch_still_dashed():
    from attackmap.model import SecretHistoryHit

    scan = ScanResult(
        root="C:/tmp/fake-repo",
        secret_history=[
            SecretHistoryHit(
                name="OLD_KEY",
                kind="credential_assignment",
                file="app/legacy.py",
                introduced_in="abcdef1234567890",
                still_in_head=False,
            )
        ],
        scanned_files=["app/legacy.py"],
        files_scanned=1,
    )
    findings = generate_findings(scan, attack_surfaces=[])
    assert [f.rule_id for f in findings] == ["secret-in-git-history"]


def test_empty_scan_still_falls_back_to_limited_surface():
    findings = generate_findings(ScanResult(root="C:/tmp/fake-repo"), attack_surfaces=[])
    assert [f.rule_id for f in findings] == ["limited-surface"]


def test_pipeline_findings_are_sorted_and_scored():
    findings = generate_findings(_wired_scan(), attack_surfaces=[])

    def rank(finding: Finding) -> tuple[int, int, str]:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return (order[finding.severity], -(finding.score or 0), finding.title)

    assert findings == sorted(findings, key=rank)
    assert all(finding.score is not None for finding in findings)
