"""Secret / config-exposure rules (AR043): data plus one evaluate method each.

Ported 1:1 from the legacy cascade branches in ``threat_model.generate_findings``
(the cascade stays the active producer until AR046 wires the registry in; these
rules must reproduce its findings exactly — proven field-by-field against
``generate_findings`` in ``tests/rules/test_secrets.py``).

Legacy rule-id mappings (the old dashed ids remain in the taxonomy registry):

============================  -------------------------  ------------------------------------
``RuleMeta.id``               legacy cascade ``rule_id``  source branch
============================  -------------------------  ------------------------------------
``hardcoded_secret_literals``  ``hardcoded-secret``        secret-hint split (#39), HIGH branch
``secret_env_references``      ``secret-env-reference``    secret-hint split (#39), env branch
``debug_mode_exposure``        ``debug-enabled``           web-hardening ``debug_enabled`` (#71)
============================  -------------------------  ------------------------------------

Each rule emits ``rule_id=meta.id`` and records its legacy dashed id as
``legacy_rule_ids``. AR046 registered every snake_case id in
``RULE_TAXONOMY`` with exactly its legacy entry's data, so the CWE/OWASP/
ASVS/ATT&CK enrichment auto-attaches by the stable id — byte-identical to
what the cascade branch emits — and no explicit carry-over remains.

Deliberately NOT ported here:
* ``secret-in-git-history`` — its branch reads ``scan.secret_history``, a slice
  ``ReasoningContext`` does not expose; widening the context is another lease.
* deployment-alias findings — the cascade has none: ``extract_deployment_aliases``
  feeds topology seam resolution (C28), never a ``Finding``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ...model import Finding, FindingLocation
from ...policy import SEVERITY_ORDER
from ..finding_format import _rule_rationale
from .base import RuleMeta
from .registry import REGISTRY

if TYPE_CHECKING:
    from ..context import ReasoningContext

__all__ = [
    "DebugModeExposureRule",
    "HardcodedSecretLiteralsRule",
    "SecretEnvReferencesRule",
]

# SecretHint kinds that name a secret without containing its value (#39).
# Local copy of ``threat_model.NON_LITERAL_SECRET_KINDS`` — importing the
# cascade from a rule module would couple the kernel to the code that will
# call the registry, a forward import cycle once AR046 lands.
_NON_LITERAL_SECRET_KINDS = frozenset({"env_reference", "env_template"})

# The cascade caps every evidence list at 10 lines.
_EVIDENCE_CAP = 10


def _locations(records) -> list[FindingLocation]:
    """Structured locations for every record behind a finding (#214): one per
    distinct (file, line), scan order, empty files skipped — the cascade's
    ``_locs``."""
    out: list[FindingLocation] = []
    seen: set[tuple[str, int | None]] = set()
    for record in records:
        if not record.file:
            continue
        key = (record.file, record.line)
        if key not in seen:
            seen.add(key)
            out.append(FindingLocation(file=record.file, line=record.line))
    return out


class HardcodedSecretLiteralsRule:
    """Secret hints whose value is a literal pasted into source or config.

    Port of the legacy ``hardcoded-secret`` branch (#39): exposure is broader
    than env references — anyone with repo read access already has these
    secrets — so severity is HIGH and the finding carries its own tags.
    """

    meta = RuleMeta(
        id="hardcoded_secret_literals",
        title="Hard-coded secret literals were found in source or config",
        cwe="CWE-798",
        severity="high",
        # Rule-level prior; the per-finding band replicates the legacy
        # hint-confidence tier exactly (see evaluate).
        confidence=0.85,
        rationale=(
            "Literal credential values in scanned sources or config files are "
            "readable by anyone with repository access and by every build or "
            "deployment system that checks the code out (CWE-798)."
        ),
        tags=("secret-exposure", "data-risk", "hardcoded-literal"),
    )
    legacy_rule_ids = ("hardcoded-secret",)

    def evaluate(self, ctx: ReasoningContext) -> list[Finding]:
        literals = [h for h in ctx.secret_hints if h.kind not in _NON_LITERAL_SECRET_KINDS]
        if not literals:
            return []
        # Grouped by kind for evidence-line density; still capped at 10 total.
        evidence = [f"[{hint.kind}] {hint.name} in {hint.file}" for hint in literals[:_EVIDENCE_CAP]]
        return [
            Finding(
                title=self.meta.title,
                severity=self.meta.severity,
                rule_id=self.meta.id,
                evidence=evidence,
                locations=_locations(literals),
                mitigation=(
                    "Rotate every detected credential immediately, purge it from git history, "
                    "and move to environment-injected or vault-managed values. Anyone with read "
                    "access to the repository already has these secrets."
                ),
                # Keyword-proximity assignments alone (#252) are a weaker signal.
                confidence="high" if any(hint.confidence >= 0.6 for hint in literals) else "medium",
                tags=list(self.meta.tags),
                rationale=_rule_rationale(self.meta, evidence),
            )
        ]


class SecretEnvReferencesRule:
    """Secret-bearing environment variables referenced in executable paths.

    Port of the legacy ``secret-env-reference`` branch (#39): ``env_reference``
    and ``env_template`` hints name a secret whose value resolves at runtime,
    so the finding asks whether injection/logging/scoping are handled rather
    than claiming a leaked value.
    """

    meta = RuleMeta(
        id="secret_env_references",
        title="Secret-bearing environment variables are referenced in executable paths",
        cwe="CWE-526",
        severity="medium",
        confidence=0.8,
        rationale=(
            "Executable paths that read secret-named environment variables put "
            "the runtime secret one hop from logs, errors and child processes; "
            "handling must be verified even though no value is hard-coded "
            "(CWE-526)."
        ),
        tags=("secret-exposure",),
    )
    legacy_rule_ids = ("secret-env-reference",)

    def evaluate(self, ctx: ReasoningContext) -> list[Finding]:
        env_references = [h for h in ctx.secret_hints if h.kind in _NON_LITERAL_SECRET_KINDS]
        if not env_references:
            return []
        evidence = [f"{hint.name} in {hint.file}" for hint in env_references[:_EVIDENCE_CAP]]
        return [
            Finding(
                title=self.meta.title,
                severity=self.meta.severity,
                rule_id=self.meta.id,
                evidence=evidence,
                locations=_locations(env_references),
                mitigation=(
                    "Confirm these secrets are injected securely, never logged or returned, "
                    "rotated regularly, and scoped only to the privileges each route actually needs."
                ),
                confidence="high",
                tags=list(self.meta.tags),
                rationale=_rule_rationale(self.meta, evidence),
            )
        ]


class DebugModeExposureRule:
    """Debug mode or unrestricted management endpoints enabled.

    Port of the ``debug_enabled`` config-exposure family of the cascade's
    web-hardening loop (#71): Flask/Django/Rails debug flags and Spring
    actuator wildcard exposure leak internals and can enable RCE. Only this
    kind belongs to the secrets/config port; the other web-hardening kinds
    keep their cascade branch until their own port.
    """

    meta = RuleMeta(
        id="debug_mode_exposure",
        title="Debug mode or unrestricted management endpoints enabled",
        cwe="CWE-489",
        severity="medium",
        confidence=0.8,
        rationale=(
            "Debug mode and wildcard-exposed management endpoints positively "
            "present in source expose stack traces, internals and privileged "
            "diagnostics to anyone who can reach the app (CWE-489)."
        ),
        tags=("web-hardening",),
    )
    legacy_rule_ids = ("debug-enabled",)

    def evaluate(self, ctx: ReasoningContext) -> list[Finding]:
        issues = [issue for issue in ctx.web_hardening_issues if issue.kind == "debug_enabled"]
        if not issues:
            return []
        evidence = [
            f"{issue.file}:{issue.line} — {issue.evidence_text}" if issue.evidence_text else f"{issue.file}:{issue.line}"
            for issue in issues[:_EVIDENCE_CAP]
        ]
        if len(issues) > _EVIDENCE_CAP:
            evidence.append(f"+{len(issues) - _EVIDENCE_CAP} more occurrence(s)")
        return [
            Finding(
                title=self.meta.title,
                # Aggregated severity is the strongest issue behind the finding.
                severity=max((issue.severity for issue in issues), key=SEVERITY_ORDER.__getitem__),
                rule_id=self.meta.id,
                evidence=evidence,
                locations=_locations(issues),
                mitigation=(
                    "Never ship with debug mode on (Flask/Django `DEBUG`, Rails "
                    "`consider_all_requests_local`) or Spring actuator endpoints exposed with "
                    "`*`. Debug consoles leak internals and can enable RCE."
                ),
                confidence="medium",
                tags=list(self.meta.tags),
                rationale=_rule_rationale(self.meta, evidence),
            )
        ]


REGISTRY.register(HardcodedSecretLiteralsRule())
REGISTRY.register(SecretEnvReferencesRule())
REGISTRY.register(DebugModeExposureRule())
