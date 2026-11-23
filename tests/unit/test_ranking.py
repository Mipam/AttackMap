"""AR050 / AC-208: central ranking and dedupe policy in ``reasoning.ranking``.

Pins the contract every report surface now shares:

- ``rank_findings`` ordering is total and deterministic: shuffled input yields
  identical ranked output (the finding id is the final tie-breaker).
- ``dedupe_findings`` collapses identity duplicates; first occurrence wins.
- The severity-weight / confidence-multiplier tables live only in
  ``reasoning.ranking`` (AC-208 grep gate).
"""

from __future__ import annotations

from itertools import permutations

from attackmap.models import Finding
from attackmap.reasoning import finding_identity
from attackmap.reasoning.ranking import (
    compute_finding_score,
    dedupe_findings,
    finding_sort_key,
    rank_findings,
    score_components,
    severity_title_sort_key,
)


def _finding(
    title: str,
    severity: str = "medium",
    confidence: str = "medium",
    *,
    score: int = 0,
    exploitability: int | None = None,
    rule_id: str | None = None,
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        confidence=confidence,
        mitigation="Synthetic mitigation",
        score=score,
        exploitability=exploitability,
        rule_id=rule_id,
    )


# --- Determinism / total order -------------------------------------------------


def test_rank_findings_is_input_order_independent() -> None:
    findings = [
        _finding("Alpha", "high", "high", score=100, exploitability=90),
        _finding("Beta", "high", "high", score=100, exploitability=95),
        _finding("Gamma", "high", "medium", score=75),
        _finding("Delta", "medium", "high", score=50),
        _finding("Echo", "low", "low", score=5),
    ]
    expected = [f.title for f in rank_findings(list(findings))]
    # Severity band first; within high, exploitability desc beats score.
    assert expected == ["Beta", "Alpha", "Gamma", "Delta", "Echo"]
    for order in permutations(range(len(findings))):
        shuffled = [findings[i] for i in order]
        assert [f.title for f in rank_findings(shuffled)] == expected


def test_rank_findings_ties_break_on_finding_id_not_input_order() -> None:
    # Identical keys except rule_id: the finding id must decide.
    a = _finding("Same title", "high", "high", score=100, rule_id="rule/aaa")
    b = _finding("Same title", "high", "high", score=100, rule_id="rule/bbb")
    ids = sorted(finding_identity.finding_id(f) for f in (a, b))
    for pair in ([a, b], [b, a]):
        ranked = rank_findings(pair)
        assert [finding_identity.finding_id(f) for f in ranked] == ids


def test_finding_sort_key_orders_score_desc_then_title_asc() -> None:
    b_title = _finding("B-title", "high", score=50)
    a_title = _finding("A-title", "high", score=50)
    higher_score = _finding("Z-title", "high", score=75)
    assert finding_sort_key(higher_score) < finding_sort_key(a_title) < finding_sort_key(b_title)


# --- Dedupe ---------------------------------------------------------------------


def test_dedupe_findings_first_occurrence_wins() -> None:
    a = _finding("Duplicate", "high", "high", score=100, rule_id="rule/x")
    dup = _finding("Duplicate", "low", "low", score=5, rule_id="rule/x")
    other = _finding("Other", "low", "low", score=5, rule_id="rule/y")
    assert dedupe_findings([a, dup, other]) == [a, other]


def test_rank_findings_dedupes_before_ranking() -> None:
    a = _finding("Duplicate", "high", "high", score=100, rule_id="rule/x")
    dup = _finding("Duplicate", "low", "low", score=5, rule_id="rule/x")
    other = _finding("Other", "medium", "medium", score=50, rule_id="rule/y")
    # First occurrence wins, then the survivor ranks by its own fields.
    ranked = rank_findings([other, dup, a])
    assert [f.title for f in ranked] == ["Other", "Duplicate"]
    assert ranked[1].severity == "low"
    ranked = rank_findings([a, dup, other])
    assert [f.title for f in ranked] == ["Duplicate", "Other"]
    assert ranked[0].severity == "high"


# --- Score tables (single home in ranking.py) ------------------------------------


def test_compute_finding_score_table() -> None:
    assert compute_finding_score("high", "high") == 100
    assert compute_finding_score("high", "medium") == 75
    assert compute_finding_score("high", "low") == 50
    assert compute_finding_score("medium", "high") == 50
    assert compute_finding_score("medium", "medium") == 37
    assert compute_finding_score("low", "low") == 5
    # Unknown bands fall back to the documented defaults (0 weight / 0.5 multiplier).
    assert compute_finding_score("critical", "high") == 0
    assert compute_finding_score("high", "unknown") == 50


def test_score_components_matches_score_formula() -> None:
    for severity in ("high", "medium", "low", "other"):
        for confidence in ("high", "medium", "low", "other"):
            weight, multiplier = score_components(severity, confidence)
            assert int(weight * multiplier) == compute_finding_score(severity, confidence)


# --- Shared listing key -----------------------------------------------------------


def test_severity_title_sort_key() -> None:
    assert severity_title_sort_key("high", "Z") < severity_title_sort_key("medium", "A")
    assert severity_title_sort_key("medium", "A") < severity_title_sort_key("low", "A")
    assert severity_title_sort_key("unknown", "A") == (3, "A")


# --- Legacy import paths keep resolving (consumers untouched) ---------------------


def test_legacy_import_paths_still_resolve() -> None:
    from attackmap.output.defensive_review import _finding_priority
    from attackmap.output.triage import rank_findings as triage_rank
    from attackmap.reasoning.threat_model import compute_finding_score as threat_model_score

    assert threat_model_score is compute_finding_score
    finding = _finding("X", "high", "high", score=100)
    assert triage_rank([finding]) == [finding]
    # 6.0 (high) + 1.5 x 3.0 (high confidence) = 10.5; no locations -> no penalty.
    assert _finding_priority(finding, [], [])[0] == 10.5
