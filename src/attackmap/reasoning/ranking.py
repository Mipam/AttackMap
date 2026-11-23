"""Central ranking and dedupe policy (AR050 / AC-208).

Single home for the weight tables, confidence multipliers and tie-breakers
that order findings, hotspots, evidence chains and exploitability chains,
plus the identity-based dedupe applied before ranking. Ordering is total
and deterministic: the finding id is the final tie-breaker, so ranked output
is a pure function of the input set, independent of input order.

Moved here, verbatim, from:

- ``reasoning/threat_model.py`` — ``_SEVERITY_WEIGHT`` /
  ``_CONFIDENCE_MULTIPLIER`` and ``compute_finding_score`` (#4). The tables
  no longer exist anywhere else; ``threat_model`` re-exports the function
  for its existing callers.
- ``output/defensive_review.py`` — the severity/risk/confidence rank
  helpers, ``_surface_priority`` / ``_path_priority`` / ``_finding_priority``
  weighting, ``_finding_source_quality``, and the hotspot dedupe.
- ``output/triage.py`` — the deterministic finding sort key (extended with
  the finding-id tie-breaker) and id-based dedupe.
- ``output/diff.py`` — the severity→title listing key.
- ``reasoning/exploitability.py`` — the chain-ordering tie-breaker.

Everything is a verbatim move: ordering semantics are preserved exactly. The
finding-id final tie-breaker only resolves ties that previously depended on
input order (Python's stable sort), which is what makes the order total.

The mirror in ``reasoning/rules/evaluation.py`` stays rules-lane property
(it must stay importable without the output/reasoning reporting stack).
"""

from __future__ import annotations

import re
from typing import Any

from attackmap.extraction.evidence import (
    is_low_quality_source as _is_low_quality_source,
)
from attackmap.extraction.evidence import (
    is_protocol_derived_surface as _is_protocol_derived_surface,
)
from attackmap.models import (
    AttackPath,
    AttackSurface,
    ExploitabilityScore,
    Finding,
)
from attackmap.policy import SEVERITY_RANK as _SEVERITY_RANK
from attackmap.reasoning.finding_identity import finding_id

# --- Finding score: severity weight x confidence multiplier (#4) --------------
# Higher score = triage first within a severity band.
_SEVERITY_WEIGHT = {"high": 100, "medium": 50, "low": 10}
_CONFIDENCE_MULTIPLIER = {"high": 1.0, "medium": 0.75, "low": 0.5}


def compute_finding_score(severity: str, confidence: str) -> int:
    """Compute the prioritization score for a finding.

    Range: 5 (low/low) to 100 (high/high). Used as a secondary sort key
    inside a severity band so a HIGH/HIGH lands above a HIGH/LOW.
    """
    return int(_SEVERITY_WEIGHT.get(severity, 0) * _CONFIDENCE_MULTIPLIER.get(confidence, 0.5))


def score_components(severity: str, confidence: str) -> tuple[int, float]:
    """Read-only exposure of (severity weight, confidence multiplier).

    Presentation layers show the decomposition of ``compute_finding_score``;
    this keeps the displayed numbers derived from the one table pair above.
    """
    return _SEVERITY_WEIGHT.get(severity, 0), _CONFIDENCE_MULTIPLIER.get(confidence, 0.5)


# --- Rank helpers (defensive review) ------------------------------------------
def _severity_rank(value: str) -> int:
    return {"high": 0, "medium": 1, "low": 2}.get(value, 3)


def _surface_risk_rank(value: str) -> int:
    return {"high": 0, "medium": 1, "low": 2}.get(value, 3)


def _confidence_rank(value: str) -> float:
    return {"high": 3.0, "medium": 2.0, "low": 1.0}.get(value, 1.0)


def _extract_numeric_confidence(text: str) -> float | None:
    match = re.search(r"confidence=([0-9]+(?:\.[0-9]+)?)", text.lower())
    if match is None:
        return None
    try:
        return float(match.group(1))
    except ValueError:
        return None


def _contains_any(text: str, keywords: tuple[str, ...]) -> bool:
    lowered = text.lower()
    return any(keyword in lowered for keyword in keywords)


def _surface_priority(surface: AttackSurface) -> tuple[float, dict[str, float]]:
    exposure_score = {"public": 3.0, "unknown": 2.0, "internal": 1.0}.get(surface.exposure, 1.0)
    privilege_score = {
        "admin": 3.0,
        "auth": 3.0,
        "webhook": 2.0,
        "upload": 2.0,
        "public_api": 1.5,
        "internal": 1.0,
        "health": 0.5,
    }.get(surface.category, 1.0)
    reachability_score = 2.0 if surface.exposure == "public" else 1.0
    trust_boundary_score = (2.0 if surface.data_store_interaction else 0.0) + (2.0 if surface.outbound_integration else 0.0)
    chain_depth_score = 1.0 + (1.0 if surface.data_store_interaction and surface.outbound_integration else 0.0)
    confidence_score = 2.0 if surface.auth_signals else 1.0
    weighted = {
        "exposure": 2.0 * exposure_score,
        "privilege": 2.0 * privilege_score,
        "reachability": 1.5 * reachability_score,
        "trust_boundary": 1.5 * trust_boundary_score,
        "chain_depth": 1.0 * chain_depth_score,
        "confidence": 1.0 * confidence_score,
    }
    if _is_low_quality_source(surface.file):
        weighted["source_quality_penalty"] = -8.0
    elif _is_protocol_derived_surface(surface):
        weighted["source_quality_penalty"] = -3.0
    elif surface.exposure == "public":
        weighted["source_quality_bonus"] = 1.0
    return round(sum(weighted.values()), 2), weighted


def _path_priority(path: AttackPath) -> tuple[float, dict[str, float]]:
    text = f"{path.name} {path.impact} {' '.join(path.steps)}"
    exposure_score = 3.0 if _contains_any(text, ("attacker reaches", "public", "/xrpc/")) else 2.0
    privilege_score = 1.0 + (
        2.0
        if _contains_any(text, ("admin", "privileged", "authorization", "authz", "token", "identity"))
        else 0.5
    )
    reachability_score = 2.0 if any(step.lower().startswith("entry:") for step in path.steps) else 1.0
    trust_boundary_score = 1.0 + sum(
        1.0
        for step in path.steps
        if _contains_any(step, ("propagation", "service", "edge", "external", "config risk", "sink"))
    )
    chain_depth_score = max(1.0, min(len(path.steps), 8) / 2.0)
    evidence_text = " ".join(path.steps)
    numeric_confidence = _extract_numeric_confidence(evidence_text)
    confidence_score = 1.5 + (numeric_confidence if numeric_confidence is not None else 0.5)
    weighted = {
        "exposure": 2.0 * exposure_score,
        "privilege": 2.0 * privilege_score,
        "reachability": 1.5 * reachability_score,
        "trust_boundary": 2.0 * trust_boundary_score,
        "chain_depth": 1.2 * chain_depth_score,
        "confidence": 1.5 * confidence_score,
    }
    if _is_low_quality_source(text):
        weighted["source_quality_penalty"] = -10.0
    return round(sum(weighted.values()), 2), weighted


def _finding_source_quality(finding: Finding) -> str:
    paths = [location.file for location in finding.locations if location.file]
    if not paths:
        return "unknown"
    low_quality = [_is_low_quality_source(path) for path in paths]
    return "low_quality" if all(low_quality) else "mixed" if any(low_quality) else "unclassified"


_FINDING_PRIORITY_SEVERITY_WEIGHT = {"high": 6.0, "medium": 4.0, "low": 2.0}


def _finding_priority(finding: Finding, attack_surfaces: list[AttackSurface], attack_paths: list[AttackPath]) -> tuple[float, dict[str, float]]:
    # Finding has no detector-owned surface/path IDs. Repository prose matches
    # cannot contribute exposure, reachability, boundary or chain scores.
    weighted = {
        "heuristic_severity": _FINDING_PRIORITY_SEVERITY_WEIGHT[finding.severity],
        "heuristic_confidence": 1.5 * _confidence_rank(finding.confidence),
    }
    quality = _finding_source_quality(finding)
    if quality in {"low_quality", "mixed"}:
        weighted["owned_source_quality_penalty"] = -10.0 if quality == "low_quality" else -3.0
    return round(sum(weighted.values()), 2), weighted


def dedupe_hotspots(
    scored_surfaces: list[tuple[tuple[float, dict[str, float]], AttackSurface]],
    *,
    limit: int = 2,
) -> list[tuple[tuple[float, dict[str, float]], AttackSurface]]:
    """Avoid duplicate hotspot rows for the same logical surface (e.g. ANY/
    SUBSCRIBE variants in one lexicon file). Score order is preserved; at
    most ``limit`` rows are kept."""
    deduped: list[tuple[tuple[float, dict[str, float]], AttackSurface]] = []
    seen_hotspot_keys: set[tuple[str, str, str, str]] = set()
    for scored_surface in scored_surfaces:
        (_score, _factors), surface = scored_surface
        key = (surface.route, surface.file, surface.category, surface.exposure)
        if key in seen_hotspot_keys:
            continue
        seen_hotspot_keys.add(key)
        deduped.append(scored_surface)
        if len(deduped) >= limit:
            break
    return deduped


# --- Finding ordering and dedupe (triage) -------------------------------------
def finding_sort_key(finding: Finding) -> tuple:
    """Deterministic priority key: severity, then exploitability, then score,
    then title, then finding id. The id tie-breaker makes the order total, so
    output is reproducible regardless of input order."""
    return (
        _SEVERITY_RANK.get(finding.severity, 3),
        -(finding.exploitability or 0),
        -(finding.score or 0),
        finding.title,
        finding_id(finding),
    )


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """De-duplicate findings by ``finding_id``; the first occurrence wins."""
    seen: set[str] = set()
    unique: list[Finding] = []
    for finding in findings:
        fid = finding_id(finding)
        if fid in seen:
            continue
        seen.add(fid)
        unique.append(finding)
    return unique


def rank_findings(findings: list[Finding], ctx: Any = None) -> list[Finding]:
    """Findings de-duplicated by ``finding_id`` and ordered by
    ``finding_sort_key`` (a total order).

    ``ctx`` is reserved for future per-run ranking context (e.g. scan
    metadata); the ranking policy itself lives in this module so every
    surface orders findings identically.
    """
    del ctx  # reserved for future per-run context; policy is centralized here.
    return sorted(dedupe_findings(findings), key=finding_sort_key)


# --- Shared listing keys --------------------------------------------------------
def severity_title_sort_key(severity: str, title: str) -> tuple[int, str]:
    """Severity-band→title listing order shared by diff Markdown sections."""
    return (_SEVERITY_RANK.get(severity, 3), title)


def exploitability_chain_sort_key(score: ExploitabilityScore) -> tuple:
    """Deterministic chain ordering: score descending, then route, then location."""
    return (-score.score, score.route, score.location)
