"""AR046 ``evaluate_rules`` tests: registry evaluation plus the triage score.

The ports leave ``Finding.score`` unset (the legacy cascade attaches it in a
post-pass); ``evaluate_rules`` reproduces that pass over REGISTRY output. The
kernel mirrors the cascade's scoring formula (it must not import the cascade),
so the mirror is kept in lockstep by the drift test here.
"""

from __future__ import annotations

import pytest

from attackmap.model import Route, ScanResult, SecretHint, TaintChain
from attackmap.reasoning import REGISTRY, ReasoningContext
from attackmap.reasoning.rules import evaluate_rules
from attackmap.reasoning.rules.evaluation import _compute_finding_score
from attackmap.reasoning.threat_model import compute_finding_score

pytestmark = [pytest.mark.unit]


def _scan() -> ScanResult:
    """A mixed fixture that fires several rule families at once."""
    return ScanResult(
        root="C:/tmp/fake-repo",
        routes=[Route(path="/admin/users", method="GET", file="app/admin.py")],
        secret_hints=[
            SecretHint(
                name="ADMIN_PASSWORD",
                file="app/config.py",
                line=12,
                kind="hardcoded",
                evidence_text="ADMIN_PASSWORD = '...'",
            )
        ],
        taint_chains=[
            TaintChain(
                route_path="/admin/users",
                route_method="GET",
                route_file="app/admin.py",
                sink_kind="eval",
                sink_file="app/dyn.py",
                sink_line=9,
                hops=1,
            )
        ],
        scanned_files=["app/admin.py", "app/config.py", "app/dyn.py"],
        files_scanned=3,
    )


def test_score_formula_matches_the_cascade_helper():
    # The kernel-side mirror must not drift from threat_model's formula.
    for severity in ("high", "medium", "low"):
        for confidence in ("high", "medium", "low"):
            assert _compute_finding_score(severity, confidence) == compute_finding_score(severity, confidence)


def test_unknown_severity_confidence_defaults_match_the_cascade():
    # Defensive defaults: unknown severity bands to weight 0, unknown
    # confidence bands to the 0.5 multiplier — identical on both sides.
    assert _compute_finding_score("critical", "high") == compute_finding_score("critical", "high")
    assert _compute_finding_score("high", "unknown") == compute_finding_score("high", "unknown")


def test_evaluate_rules_scores_every_finding():
    findings = evaluate_rules(ReasoningContext.from_scan(_scan()))
    assert len(findings) >= 4  # route + secret + demo + taint families all fire
    for finding in findings:
        assert finding.score is not None
        assert finding.score == compute_finding_score(finding.severity, finding.confidence)


def test_evaluate_rules_matches_registry_evaluation_plus_scores():
    baseline = REGISTRY.evaluate_all(ReasoningContext.from_scan(_scan()))
    scored = evaluate_rules(ReasoningContext.from_scan(_scan()))
    assert [f.rule_id for f in scored] == [f.rule_id for f in baseline.findings]
    assert [f.model_dump(exclude={"score"}) for f in scored] == [
        f.model_dump(exclude={"score"}) for f in baseline.findings
    ]


def test_registry_evaluation_alone_leaves_scores_unset():
    # The convenience owns the score pass; bare REGISTRY output stays unscored.
    for finding in REGISTRY.evaluate_all(ReasoningContext.from_scan(_scan())).findings:
        assert finding.score is None
