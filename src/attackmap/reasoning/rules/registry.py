"""The rule registry (AR040): deterministic order, duplicate detection,
per-rule exception isolation.

Registry order is `meta.id` order — registration order never leaks into
output. A rule that raises during evaluation is skipped and reported in the
result's ``errors`` list: evidence-first means a broken rule is never
swallowed silently, and its failure must not silence the other rules.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .base import RuleMeta

if TYPE_CHECKING:
    from ...model import Finding
    from ..context import ReasoningContext
    from .base import Rule

__all__ = ["REGISTRY", "EvaluationResult", "RuleEvaluationError", "RuleRegistry"]


@dataclass(frozen=True)
class RuleEvaluationError:
    """One rule's evaluation failure, kept for reporting (never silent)."""

    rule_id: str
    error_type: str
    message: str = ""


@dataclass(frozen=True)
class EvaluationResult:
    """Findings concatenated in registry order plus the rules that failed."""

    findings: list[Finding]
    errors: list[RuleEvaluationError]


class RuleRegistry:
    """Deterministic, duplicate-free registry of `Rule` objects."""

    def __init__(self) -> None:
        self._by_id: dict[str, Rule] = {}

    def register(self, rule: Rule) -> None:
        """Register ``rule``; raises ValueError on a duplicate id."""
        meta = getattr(rule, "meta", None)
        if not isinstance(meta, RuleMeta):
            raise TypeError(f"rule must carry RuleMeta, got {type(rule).__name__}")
        if meta.id in self._by_id:
            raise ValueError(f"rule id already registered: {meta.id!r}")
        self._by_id[meta.id] = rule

    def get(self, rule_id: str) -> Rule | None:
        """The registered rule with this id, or None."""
        return self._by_id.get(rule_id)

    def ids(self) -> tuple[str, ...]:
        """Registered rule ids in registry (sorted) order."""
        return tuple(sorted(self._by_id))

    def all_rules(self) -> tuple[Rule, ...]:
        """Registered rules in registry (sorted-by-id) order."""
        return tuple(sorted(self._by_id.values(), key=lambda rule: rule.meta.id))

    def evaluate_all(self, ctx: ReasoningContext) -> EvaluationResult:
        """Evaluate every rule against ``ctx`` in registry order.

        Each rule runs in isolation: one that raises is skipped and recorded
        as a `RuleEvaluationError`; the remaining rules still contribute.
        """
        findings: list[Finding] = []
        errors: list[RuleEvaluationError] = []
        for rule in self.all_rules():
            try:
                findings.extend(rule.evaluate(ctx))
            except Exception as exc:  # isolation is the contract; the error is reported, not swallowed
                errors.append(
                    RuleEvaluationError(rule_id=rule.meta.id, error_type=type(exc).__name__, message=str(exc))
                )
        return EvaluationResult(findings=findings, errors=errors)

    def __len__(self) -> int:
        return len(self._by_id)

    def __contains__(self, rule_id: object) -> bool:
        return rule_id in self._by_id


REGISTRY = RuleRegistry()
"""The process-wide rule registry the rule ports register into."""
