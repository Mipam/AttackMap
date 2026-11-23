"""AR041 route/auth rule tests: positive/negative/low-quality fixtures per
rule plus field-for-field equivalence against the legacy cascade branches
(``threat_model.generate_findings``), which stay the active producer until
the cascade-retirement wiring.

Self-contained by design: scans and contexts are built in-memory here; no
shared harness. ``unit`` tier: pure functions, no filesystem or network.
"""

from __future__ import annotations

import re

import pytest

from attackmap.model import AuthHint, Route, ScanResult, TaintChain
from attackmap.reasoning import REGISTRY, ReasoningContext
from attackmap.reasoning.rules.route_auth import (
    RouteExposedAdminRule,
    RoutePublicWebhookRule,
    RouteUploadImportRule,
    RouteWeakAuthControlsRule,
)
from attackmap.reasoning.threat_model import compute_finding_score, generate_findings

pytestmark = [pytest.mark.unit]

# Legacy cascade rule_id -> kernel rule id (AR041 mapping under test).
LEGACY_TO_RULE = {
    "public-webhook": RoutePublicWebhookRule,
    "exposed-admin-route": RouteExposedAdminRule,
    "upload-route": RouteUploadImportRule,
    "weak-auth-route": RouteWeakAuthControlsRule,
}

ROUTE_ID_RE = re.compile(r"[a-z][a-z0-9_]*")


# --- helpers ------------------------------------------------------------------


def _ctx(scan: ScanResult) -> ReasoningContext:
    return ReasoningContext.from_scan(scan)


def _legacy_findings(scan: ScanResult, legacy_rule_id: str):
    """The old cascade's findings for one legacy rule id on the same scan."""
    return [f for f in generate_findings(scan) if f.rule_id == legacy_rule_id]


def _assert_equivalent(rule, scan: ScanResult, legacy_rule_id: str) -> None:
    """Every Finding field the cascade sets must match, except the two
    intentional deltas: ``rule_id`` (kernel contract: ``meta.id``) and
    ``score`` (assigned by the pipeline, derived from severity/confidence).
    """
    new = rule.evaluate(_ctx(scan))
    old = _legacy_findings(scan, legacy_rule_id)
    assert len(new) == len(old)
    for new_finding, old_finding in zip(new, old, strict=True):
        new_dump = new_finding.model_dump()
        old_dump = old_finding.model_dump()
        assert new_dump.keys() == old_dump.keys()
        for field in new_dump.keys() - {"rule_id", "score"}:
            assert new_dump[field] == old_dump[field], f"field {field!r} diverges"
        # score is derived: the same severity/confidence must score the same.
        assert compute_finding_score(new_finding.severity, new_finding.confidence) == old_finding.score


# --- registration / metadata sanity --------------------------------------------


def test_all_route_rules_are_registered():
    for rule_cls in LEGACY_TO_RULE.values():
        rule = REGISTRY.get(rule_cls.meta.id)
        assert isinstance(rule, rule_cls)
        assert rule.meta.id == rule_cls.meta.id
        assert ROUTE_ID_RE.fullmatch(rule.meta.id)  # stable, suppressible SARIF ruleId


def test_rule_ids_carry_stable_metadata():
    assert RoutePublicWebhookRule.meta.severity == "high"
    assert RouteExposedAdminRule.meta.severity == "high"
    assert RouteUploadImportRule.meta.severity == "high"
    assert RouteWeakAuthControlsRule.meta.severity == "medium"
    # Confidence bands must reproduce the cascade's confidence strings.
    assert RoutePublicWebhookRule.meta.cwe == "CWE-345"
    assert RouteWeakAuthControlsRule.meta.cwe == "CWE-287"


# --- AM-ROUTE-001 / route_public_webhook (cascade: public-webhook) --------------


def _webhook_scan(**route_kwargs) -> ScanResult:
    return ScanResult(
        root=".",
        routes=[Route(path="/webhook/stripe", method="POST", file="api.py", **route_kwargs)],
        taint_chains=[
            TaintChain(
                route_path="/webhook/stripe",
                route_method="POST",
                route_file="api.py",
                sink_kind="ssrf",
                sink_file="api.py",
                hops=0,
            )
        ],
    )


@pytest.mark.rule("route_public_webhook")
def test_public_webhook_positive_and_equivalent():
    scan = _webhook_scan()
    findings = RoutePublicWebhookRule().evaluate(_ctx(scan))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "route_public_webhook"
    assert finding.severity == "high"
    assert finding.confidence == "high"
    assert finding.tags == ["exposed-endpoint", "auth-missing"]
    assert finding.locations[0].file == "api.py"
    assert finding.evidence == ["POST /webhook/stripe in api.py; no auth signals observed; inferred outbound relationship"]
    # taxonomy/ATT&CK auto-attach from the registered stable id (AR046):
    # identical to the legacy entry's data.
    assert finding.taxonomy is not None and finding.taxonomy.cwe == ["CWE-345"]
    assert [t.technique_id for t in finding.attack_techniques] == ["T1190", "T1199"]
    _assert_equivalent(RoutePublicWebhookRule(), scan, "public-webhook")


@pytest.mark.rule("route_public_webhook")
def test_public_webhook_negative_plugin_declared_auth():
    scan = _webhook_scan(auth="required", guards=["requireSignature"])
    assert RoutePublicWebhookRule().evaluate(_ctx(scan)) == []
    assert _legacy_findings(scan, "public-webhook") == []


@pytest.mark.rule("route_public_webhook")
def test_public_webhook_negative_strong_auth_signal_nearby():
    scan = _webhook_scan()
    scan.auth_hints.append(AuthHint(hint="authorization", file="api.py", line=1))
    assert RoutePublicWebhookRule().evaluate(_ctx(scan)) == []
    assert _legacy_findings(scan, "public-webhook") == []


@pytest.mark.rule("route_public_webhook")
def test_public_webhook_ignores_low_quality_sources():
    scan = ScanResult(
        root=".",
        routes=[Route(path="/webhook/stripe", method="POST", file="tests/webhook_test.ts")],
        taint_chains=[
            TaintChain(
                route_path="/webhook/stripe",
                route_method="POST",
                route_file="tests/webhook_test.ts",
                sink_kind="ssrf",
                sink_file="tests/webhook_test.ts",
                hops=0,
            )
        ],
    )
    assert RoutePublicWebhookRule().evaluate(_ctx(scan)) == []
    assert _legacy_findings(scan, "public-webhook") == []


# --- AM-ROUTE-002 / route_exposed_admin (cascade: exposed-admin-route) ----------


def _admin_scan() -> ScanResult:
    return ScanResult(
        root=".",
        routes=[
            Route(path="/admin/users", method="ANY", file="app/admin.py", line=10),
            Route(path="/manage/secrets", method="GET", file="app/admin_extra.py", line=22),
        ],
    )


@pytest.mark.rule("route_exposed_admin")
def test_exposed_admin_positive_and_equivalent():
    scan = _admin_scan()
    findings = RouteExposedAdminRule().evaluate(_ctx(scan))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "route_exposed_admin"
    assert finding.severity == "high"
    assert finding.confidence == "high"
    assert finding.tags == ["exposed-endpoint", "auth-missing", "privileged"]
    assert [loc.file for loc in finding.locations] == ["app/admin.py", "app/admin_extra.py"]
    assert finding.taxonomy is not None and finding.taxonomy.cwe == ["CWE-285"]
    _assert_equivalent(RouteExposedAdminRule(), scan, "exposed-admin-route")


@pytest.mark.rule("route_exposed_admin")
def test_exposed_admin_negative_non_admin_routes():
    scan = ScanResult(root=".", routes=[Route(path="/api/users", method="GET", file="app/api.py")])
    assert RouteExposedAdminRule().evaluate(_ctx(scan)) == []
    assert _legacy_findings(scan, "exposed-admin-route") == []


@pytest.mark.rule("route_exposed_admin")
def test_exposed_admin_ignores_low_quality_sources():
    scan = ScanResult(root=".", routes=[Route(path="/admin/users", method="ANY", file="tests/admin_routes.py")])
    assert RouteExposedAdminRule().evaluate(_ctx(scan)) == []
    assert _legacy_findings(scan, "exposed-admin-route") == []


# --- AM-ROUTE-003 / route_upload_import (cascade: upload-route) -----------------


@pytest.mark.rule("route_upload_import")
def test_upload_import_positive_and_equivalent():
    scan = ScanResult(root=".", routes=[Route(path="/upload", method="POST", file="app/upload.py", line=5)])
    findings = RouteUploadImportRule().evaluate(_ctx(scan))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "route_upload_import"
    assert finding.severity == "high"
    assert finding.confidence == "medium"
    assert finding.tags == ["exposed-endpoint", "input-handling"]
    assert finding.locations[0].file == "app/upload.py"
    assert finding.locations[0].line == 5
    assert finding.taxonomy is not None and finding.taxonomy.cwe == ["CWE-434"]
    _assert_equivalent(RouteUploadImportRule(), scan, "upload-route")


@pytest.mark.rule("route_upload_import")
def test_upload_import_negative_other_categories():
    scan = ScanResult(root=".", routes=[Route(path="/health", method="GET", file="app/health.py")])
    assert RouteUploadImportRule().evaluate(_ctx(scan)) == []
    assert _legacy_findings(scan, "upload-route") == []


@pytest.mark.rule("route_upload_import")
def test_upload_import_ignores_low_quality_sources():
    scan = ScanResult(root=".", routes=[Route(path="/import/data", method="POST", file="examples/upload_demo.py")])
    assert RouteUploadImportRule().evaluate(_ctx(scan)) == []
    assert _legacy_findings(scan, "upload-route") == []


# --- AM-ROUTE-004 / route_weak_auth_controls (cascade: weak-auth-route) ---------


def _auth_scan(**route_kwargs) -> ScanResult:
    return ScanResult(
        root=".",
        routes=[Route(path="/login", method="POST", file="app/web.py", line=30, **route_kwargs)],
    )


@pytest.mark.rule("route_weak_auth_controls")
def test_weak_auth_positive_and_equivalent():
    scan = _auth_scan()
    findings = RouteWeakAuthControlsRule().evaluate(_ctx(scan))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "route_weak_auth_controls"
    assert finding.severity == "medium"
    assert finding.confidence == "medium"
    assert finding.tags == ["exposed-endpoint", "auth-missing"]
    assert finding.locations[0].file == "app/web.py"
    assert finding.locations[0].line == 30
    assert finding.taxonomy is not None
    assert finding.taxonomy.cwe == ["CWE-287", "CWE-307"]
    _assert_equivalent(RouteWeakAuthControlsRule(), scan, "weak-auth-route")


@pytest.mark.rule("route_weak_auth_controls")
def test_weak_auth_negative_auth_hint_within_window():
    scan = _auth_scan()
    scan.auth_hints.append(AuthHint(hint="jwt", file="app/web.py", line=35))
    assert RouteWeakAuthControlsRule().evaluate(_ctx(scan)) == []
    assert _legacy_findings(scan, "weak-auth-route") == []


@pytest.mark.rule("route_weak_auth_controls")
def test_weak_auth_negative_plugin_declared_auth():
    scan = _auth_scan(auth="required")
    assert RouteWeakAuthControlsRule().evaluate(_ctx(scan)) == []
    assert _legacy_findings(scan, "weak-auth-route") == []


@pytest.mark.rule("route_weak_auth_controls")
def test_weak_auth_hint_outside_window_still_flags():
    # Hints exist in the file but outside the +/-40-line attribution window:
    # the legacy classifier attributes no signal to the route, so it fires.
    scan = _auth_scan()
    scan.auth_hints.append(AuthHint(hint="jwt", file="app/web.py", line=300))
    findings = RouteWeakAuthControlsRule().evaluate(_ctx(scan))
    assert len(findings) == 1
    _assert_equivalent(RouteWeakAuthControlsRule(), scan, "weak-auth-route")


@pytest.mark.rule("route_weak_auth_controls")
def test_weak_auth_ignores_low_quality_sources():
    scan = ScanResult(root=".", routes=[Route(path="/login", method="POST", file="__tests__/login_flow.ts")])
    assert RouteWeakAuthControlsRule().evaluate(_ctx(scan)) == []
    assert _legacy_findings(scan, "weak-auth-route") == []


# --- kernel integration ---------------------------------------------------------


@pytest.mark.rule("route_exposed_admin", "route_weak_auth_controls")
def test_route_rules_flow_through_registry_evaluation():
    scan = _admin_scan()
    scan.routes.append(Route(path="/login", method="POST", file="app/web.py"))
    result = REGISTRY.evaluate_all(_ctx(scan))
    assert result.errors == []
    ids = {finding.rule_id for finding in result.findings}
    assert {"route_exposed_admin", "route_weak_auth_controls"} <= ids
