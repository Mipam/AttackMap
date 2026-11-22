"""Reasoning rule kernel (AR040).

The pivot of Phase 2: rules become DATA (`RuleMeta`) plus one `evaluate`
method, and this kernel - context, protocol, registry - is the fixed contract
the rule ports (AR041-AR045) plug into. The kernel never branches on rule
kinds; adding rules never changes kernel code.

Dependency direction is downward only: this package imports from
`attackmap.model` (the stable AR022 package) and the stdlib, nothing else.
"""

from __future__ import annotations

from .context import ReasoningContext
from .rules import REGISTRY, WeakDefaultCredentialsRule
from .rules.base import Rule, RuleMeta, confidence_band
from .rules.registry import EvaluationResult, RuleEvaluationError, RuleRegistry

__all__ = [
    "REGISTRY",
    "EvaluationResult",
    "ReasoningContext",
    "Rule",
    "RuleEvaluationError",
    "RuleMeta",
    "RuleRegistry",
    "WeakDefaultCredentialsRule",
    "confidence_band",
]
