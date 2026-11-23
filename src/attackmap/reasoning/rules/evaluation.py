"""Registry-side evaluation convenience (AR046): run every rule, attach the
triage score.

The rule ports leave ``Finding.score`` unset — the legacy cascade attaches
the score in a post-pass over all its findings. This helper reproduces that
pass over ``REGISTRY.evaluate_all`` output so callers get triage-ready
findings without importing the cascade. The registry itself is NOT yet the
pipeline producer (the cascade-retirement task owns that wiring, plus the
exploitability fusion the taint port documents as pipeline-side).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .registry import REGISTRY

if TYPE_CHECKING:
    from ...model import Finding
    from ..context import ReasoningContext

__all__ = ["evaluate_rules"]

# Mirror of ``threat_model.compute_finding_score`` (#4): severity weight x
# confidence multiplier, truncated to int. The kernel must not import the
# cascade it is replacing, so the formula is mirrored here and kept in
# lockstep by tests/rules/test_evaluate_rules.py.
_SEVERITY_WEIGHT = {"high": 100, "medium": 50, "low": 10}
_CONFIDENCE_MULTIPLIER = {"high": 1.0, "medium": 0.75, "low": 0.5}


def _compute_finding_score(severity: str, confidence: str) -> int:
    return int(_SEVERITY_WEIGHT.get(severity, 0) * _CONFIDENCE_MULTIPLIER.get(confidence, 0.5))


def evaluate_rules(ctx: ReasoningContext) -> list[Finding]:
    """Evaluate every registered rule against ``ctx`` and score the findings.

    Convenience over ``REGISTRY.evaluate_all``: findings come back in
    registry order with ``Finding.score`` attached (the same severity x
    confidence formula the cascade's post-pass applies). Rules that raise
    stay isolated — their errors are reported on the registry's own result,
    which this helper intentionally does not re-expose; callers that must
    surface evaluation errors call ``REGISTRY.evaluate_all`` directly.
    """
    result = REGISTRY.evaluate_all(ctx)
    for finding in result.findings:
        finding.score = _compute_finding_score(finding.severity, finding.confidence)
        # AR049/AC-207: a rule finding must explain itself even when the rule's
        # own construction did not set a rationale — fall back to the rule's
        # declared rationale rather than emitting an unexplained finding.
        if not finding.rationale and finding.rule_id:
            rule = REGISTRY.get(finding.rule_id)
            if rule is not None:
                finding.rationale = rule.meta.rationale
    return result.findings
