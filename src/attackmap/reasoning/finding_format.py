"""Finding formatting helpers shared by the cascade and the ported rules.

AR041's route/auth port reuses the cascade's private formatters. The rule
kernel may not import the cascade it replaces (once the wiring makes the
cascade call the registry, ``rules/route_auth.py -> threat_model`` would be
an import cycle), so the shared helpers live here and both sides import them
from a module that depends on nothing in ``reasoning``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from attackmap.model import AttackSurface, FindingLocation
from attackmap.policy import LOW_QUALITY_SEGMENTS

if TYPE_CHECKING:
    from .rules.base import RuleMeta

__all__ = ["_finding_evidence", "_is_low_quality_source", "_locs", "_rule_rationale", "_surface_label"]


def _surface_label(surface: AttackSurface) -> str:
    return f"{surface.method} {surface.route} in {surface.file}"


def _is_low_quality_source(path_or_text: str) -> bool:
    normalized = path_or_text.replace("\\", "/").lower()
    return any(segment in f"/{normalized}/" for segment in LOW_QUALITY_SEGMENTS)


def _locs(items, file_attr: str = "file", line_attr: str = "line") -> list[FindingLocation]:
    """Structured locations for every item behind a finding (#214)."""
    out: list[FindingLocation] = []
    seen: set[tuple[str, int | None]] = set()
    for item in items:
        file = getattr(item, file_attr, None)
        if not file:
            continue
        line = getattr(item, line_attr, None)
        key = (file, line)
        if key not in seen:
            seen.add(key)
            out.append(FindingLocation(file=file, line=line))
    return out


def _finding_evidence(surface: AttackSurface) -> str:
    details: list[str] = [_surface_label(surface)]
    if surface.auth_signals:
        details.append(f"auth signals: {', '.join(surface.auth_signals)}")
    else:
        details.append("no auth signals observed")
    if surface.data_store_interaction:
        details.append("inferred datastore relationship")
    if surface.outbound_integration:
        details.append("inferred outbound relationship")
    return "; ".join(details)


def _rule_rationale(meta: RuleMeta, evidence: list[str]) -> str:
    """AR049/AC-207: a rule finding's rationale = why the rule exists
    (``RuleMeta.rationale``) plus the concrete observation that fired (the
    first evidence line). The text is redacted with the evidence fields at
    construction, so an observation copied from the repo cannot leak a
    credential through the rationale."""
    base = meta.rationale.rstrip(".")
    if evidence:
        return f"{base}. Observed: {evidence[0]}"
    return f"{base}."
