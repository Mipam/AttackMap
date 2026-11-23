"""Reasoning rule package: the contract (`base`), the registry (`registry`),
the seed reference rule, and the ported cascade rule modules (AR041-AR045).

Each rule module self-registers its rules into ``REGISTRY`` on import.
AR046 unified the emitted ``Finding.rule_id`` convention (``meta.id`` —
stable snake_case ids registered in ``RULE_TAXONOMY`` with their legacy
entries' data), added the catalog surface (``attackmap rules``), the
generated reference docs and the ``evaluate_rules`` score helper. The
registry is still NOT the scan-pipeline producer — the legacy cascade in
``threat_model`` stays active until the cascade-retirement wiring lands.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from ...model import Finding, FindingLocation
from .base import RuleMeta, confidence_band
from .evaluation import evaluate_rules
from .registry import REGISTRY

if TYPE_CHECKING:
    from ..context import ReasoningContext

__all__ = [
    "WeakDefaultCredentialsRule",
    "evaluate_rules",
]

# Names a hard-coded default credential typically travels under. Name-only
# heuristic on purpose: the seed rule's job is to prove the pipeline, not to
# maximize recall.
_DEFAULT_CREDENTIAL_RE = re.compile(
    r"(?:default|admin)[_-]?(?:password|passwd|pwd|credential|credentials|secret|token)",
    re.IGNORECASE,
)


class WeakDefaultCredentialsRule:
    """Seed rule: flags hard-coded default/admin credentials in scanned sources.

    Reference implementation for the whole kernel: metadata-driven, one
    `evaluate` method, findings attributed to `meta.id`.
    """

    meta = RuleMeta(
        id="demo_weak_default_credentials",
        title="Hard-coded default credential",
        cwe="CWE-798",
        severity="high",
        confidence=0.8,
        rationale=(
            "A secret hint whose name names a default or admin credential appears "
            "as a literal in scanned sources; shipped defaults are a well-known "
            "account-takeover path (CWE-798)."
        ),
        tags=("secret-exposure", "auth-missing"),
    )

    def evaluate(self, ctx: ReasoningContext) -> list[Finding]:
        findings: list[Finding] = []
        for hint in ctx.secret_hints:
            if hint.kind == "env_reference":
                # The value resolves at runtime; nothing hard-coded is observed.
                continue
            if not _DEFAULT_CREDENTIAL_RE.search(hint.name):
                continue
            findings.append(
                Finding(
                    title=self.meta.title,
                    severity=self.meta.severity,
                    rule_id=self.meta.id,
                    confidence=confidence_band(self.meta.confidence),
                    mitigation=(
                        "Rotate the default credential and load it from a managed "
                        "secret store; never ship defaults in source or images."
                    ),
                    evidence=[hint.evidence_text] if hint.evidence_text else [hint.name],
                    locations=[FindingLocation(file=hint.file, line=hint.line)],
                    tags=list(self.meta.tags),
                )
            )
        return findings


REGISTRY.register(WeakDefaultCredentialsRule())

# Ported cascade rules (AR041-AR045): import-for-registration only.
from . import datastore_edges, route_auth, secrets, supply_chain, taint_flow  # noqa: E402,F401
