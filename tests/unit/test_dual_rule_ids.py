"""Dual-id suppressions/SARIF (owner decision 2026-11-23).

During the rule-id cutover, reports may carry either the legacy dashed rule
id or the registry's stable snake_case id. The consumption side must accept
BOTH forms, in both directions, matched through each rule's recorded
``legacy_rule_ids``. These tests pin that bilingual matching and cross-check
the model-layer alias map against the kernel registry so the two sides
cannot drift apart before the flip.

Report content is unchanged by this lane: SARIF ``ruleId`` values still
carry whatever the finding carries.
"""

from __future__ import annotations

import pytest

from attackmap.model.taxonomy import RULE_TAXONOMY, rule_id_aliases
from attackmap.models import Finding
from attackmap.output.sarif import build_sarif
from attackmap.output.suppress import Suppression, SuppressionSet

pytestmark = [pytest.mark.unit]

# A registered legacy<->stable pair from the AR046 taxonomy block.
LEGACY_ID = "hardcoded-secret"
STABLE_ID = "hardcoded_secret_literals"


def _finding(rule_id: str | None, title: str = "Secrets committed in source") -> Finding:
    # The title slug ("secrets-committed-in-source") deliberately differs
    # from both rule id forms, so a match can only come from the alias map.
    return Finding(
        title=title,
        rule_id=rule_id,
        severity="high",  # type: ignore[arg-type]
        evidence=["app/config.py:3 hardcoded AWS key"],
        mitigation="rotate and move to a secret store",
        confidence="high",
    )


# ---------------------------------------------------------------------------
# rule_id_aliases — the model-layer bidirectional alias map
# ---------------------------------------------------------------------------


def test_aliases_bidirectional_for_registered_pair() -> None:
    assert LEGACY_ID in rule_id_aliases(STABLE_ID)
    assert STABLE_ID in rule_id_aliases(LEGACY_ID)


def test_aliases_exclude_the_query_itself() -> None:
    assert LEGACY_ID not in rule_id_aliases(LEGACY_ID)
    assert STABLE_ID not in rule_id_aliases(STABLE_ID)


def test_aliases_empty_for_unknown_id() -> None:
    assert rule_id_aliases("no-such-rule") == frozenset()
    assert rule_id_aliases("") == frozenset()


def test_aliases_cover_the_whole_shared_entry_group() -> None:
    # taint_sink_exec and taint_speculative_exec share the "exec" entry.
    aliases = rule_id_aliases("taint_sink_exec")
    assert "exec" in aliases
    assert "taint_speculative_exec" in aliases
    # Speculative dashed ids (declared in legacy_rule_ids) resolve through
    # the speculative- prefix, so they alias the shared entry too.
    assert "speculative-exec" in aliases
    assert "speculative-code-injection" in rule_id_aliases("taint_speculative_code_injection")


def test_aliases_resolve_for_speculative_ids() -> None:
    aliases = rule_id_aliases("speculative-hardcoded_secret_literals")
    assert LEGACY_ID in aliases
    assert STABLE_ID in aliases


# ---------------------------------------------------------------------------
# Cross-check against the kernel registry (tests may import reasoning/)
# ---------------------------------------------------------------------------


def test_every_registry_rule_legacy_ids_are_in_the_alias_map() -> None:
    """Every registry rule that has a taxonomy entry must expose every one
    of its ``legacy_rule_ids`` through the alias map — and vice versa. This
    pins the consumption-side alias data to the producer-side registry for
    the flip."""
    from attackmap.reasoning import REGISTRY

    for rule in REGISTRY.all_rules():
        rid = rule.meta.id
        if rid not in RULE_TAXONOMY:
            continue  # deliberately unregistered aggregates (AR046 contract)
        legacy = tuple(getattr(rule, "legacy_rule_ids", ()))
        assert legacy, f"{rid} is taxonomy-registered but declares no legacy_rule_ids"
        for old in legacy:
            assert old in rule_id_aliases(rid), f"{rid}: legacy id {old!r} missing from alias map"
            assert rid in rule_id_aliases(old), f"{old}: stable id {rid!r} missing from alias map"


# ---------------------------------------------------------------------------
# Suppressions — dual-id acceptance
# ---------------------------------------------------------------------------


def test_legacy_selector_suppresses_stable_id_finding() -> None:
    ss = SuppressionSet([Suppression(reason="fixtures only", rule=LEGACY_ID)])
    assert ss.match(_finding(STABLE_ID))


def test_stable_selector_suppresses_legacy_id_finding() -> None:
    ss = SuppressionSet([Suppression(reason="fixtures only", rule=STABLE_ID)])
    assert ss.match(_finding(LEGACY_ID))


def test_exact_id_match_still_works_both_forms() -> None:
    for rid in (LEGACY_ID, STABLE_ID):
        ss = SuppressionSet([Suppression(reason="x", rule=rid)])
        assert ss.match(_finding(rid))


def test_unrelated_selector_still_misses() -> None:
    ss = SuppressionSet([Suppression(reason="x", rule="route_exposed_admin")])
    assert not ss.match(_finding(LEGACY_ID))


def test_wildcard_selector_unchanged() -> None:
    ss = SuppressionSet([])
    assert ss._rule_ok(None, _finding(LEGACY_ID)) is True
    assert ss._rule_ok(None, _finding(STABLE_ID)) is True


def test_title_slug_fallback_unchanged() -> None:
    """The deprecated title-slug path still matches and still records the
    legacy-selector notice — alias matching must not disturb it."""
    title = "Hard-coded secret literals were found in source or config"
    slug = "hard-coded-secret-literals-were-found-in-source-or-config"
    finding = _finding(LEGACY_ID, title=title)
    ss = SuppressionSet([Suppression(reason="x", rule=slug)])
    assert ss.match(finding)
    assert ss.legacy_selectors == {slug: LEGACY_ID}


def test_alias_match_records_no_legacy_notice() -> None:
    """Bilingual ids are first-class during the cascade: an alias match is
    silent, unlike a deprecated title-slug match."""
    ss = SuppressionSet([Suppression(reason="x", rule=LEGACY_ID)])
    assert ss.match(_finding(STABLE_ID))
    assert ss.legacy_selectors == {}


def test_apply_suppressions_end_to_end_dual_id() -> None:
    from attackmap.output.suppress import apply_suppressions

    findings = [_finding(STABLE_ID)]
    for selector in (LEGACY_ID, STABLE_ID):
        ss = SuppressionSet([Suppression(reason="accepted", rule=selector)])
        outcome = apply_suppressions(findings, ss)
        assert len(outcome.suppressed) == 1
        assert outcome.suppressed[0].rule == STABLE_ID
        assert not outcome.active


# ---------------------------------------------------------------------------
# SARIF — taxonomy enrichment resolves for both id forms (ruleId untouched)
# ---------------------------------------------------------------------------


def _sarif_rule(rule_id: str) -> dict:
    finding = _finding(rule_id)
    log = build_sarif([finding])
    rules = log["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1
    return rules[0]


def test_sarif_taxonomy_emitted_for_legacy_id() -> None:
    rule = _sarif_rule(LEGACY_ID)
    assert rule["id"] == LEGACY_ID  # ruleId carries what the finding carries
    assert rule["properties"]["cwe"]
    assert rule["helpUri"].startswith("https://cwe.mitre.org/")
    assert rule["relationships"]


def test_sarif_taxonomy_emitted_for_stable_id() -> None:
    rule = _sarif_rule(STABLE_ID)
    assert rule["id"] == STABLE_ID
    assert rule["properties"]["cwe"]
    assert rule["helpUri"].startswith("https://cwe.mitre.org/")
    assert rule["relationships"]


def test_sarif_taxonomy_identical_across_id_forms() -> None:
    """Same entry object in the registry block → same enrichment, so the
    id flip alone cannot change the taxonomy a consumer sees."""
    legacy, stable = _sarif_rule(LEGACY_ID), _sarif_rule(STABLE_ID)
    assert legacy["properties"]["cwe"] == stable["properties"]["cwe"]
    assert legacy["helpUri"] == stable["helpUri"]


def test_sarif_result_ruleid_matches_finding_id_form() -> None:
    """Additive guarantee for the cutover: results keep the finding's id."""
    for rid in (LEGACY_ID, STABLE_ID):
        log = build_sarif([_finding(rid)])
        results = log["runs"][0]["results"]
        assert {r["ruleId"] for r in results} == {rid}
