"""Rule contract (AR040): stable metadata plus one evaluate method.

This module is the contract the rule ports (AR041-AR045) plug into. It holds
no logic beyond validation: rules are data (`RuleMeta`) plus a single
`evaluate` method; the kernel and registry never branch on rule kinds.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, field_validator

if TYPE_CHECKING:
    from ...model import Finding
    from ..context import ReasoningContext

__all__ = ["Rule", "RuleMeta", "confidence_band"]

_RULE_ID_RE = re.compile(r"[a-z][a-z0-9_]*")


class RuleMeta(BaseModel):
    """Stable, suppressible identity of one rule.

    ``id`` is the SARIF ruleId and the suppression key — it never changes and
    never carries prose. ``confidence`` is the rule's measured trust in its
    own detection (0.0-1.0); ``rationale`` states why the rule exists so every
    finding it emits is explainable.
    """

    model_config = ConfigDict(frozen=True)

    id: str
    title: str
    cwe: str = ""
    severity: Literal["high", "medium", "low"]
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str
    tags: tuple[str, ...] = ()

    @field_validator("id")
    @classmethod
    def _id_is_stable_snake_case(cls, value: str) -> str:
        if not _RULE_ID_RE.fullmatch(value):
            raise ValueError("rule id must match ^[a-z][a-z0-9_]*$ (stable, suppressible)")
        return value

    @field_validator("title", "rationale")
    @classmethod
    def _text_is_meaningful(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must be non-empty")
        return value


@runtime_checkable
class Rule(Protocol):
    """Anything that carries `RuleMeta` and evaluates a context to findings.

    Findings must be `attackmap.model.Finding` instances and carry
    ``rule_id=meta.id`` so output stays attributable and suppressible.
    """

    meta: RuleMeta

    def evaluate(self, ctx: ReasoningContext) -> list[Finding]: ...


def confidence_band(confidence: float) -> Literal["low", "medium", "high"]:
    """Map a rule's 0.0-1.0 confidence onto Finding's low/medium/high band."""
    if confidence >= 0.8:
        return "high"
    if confidence >= 0.5:
        return "medium"
    return "low"
