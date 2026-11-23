"""AR046 rule-id/taxonomy unification tests.

The kernel contract is ``Finding.rule_id == meta.id``. Every registered rule
whose stable id replaces exactly one legacy (dashed) detector id must be
registered in ``RULE_TAXONOMY`` with exactly that entry's data, so the
taxonomy/ATT&CK enrichment that auto-attaches by rule id stays byte-identical
to what the legacy cascade emits. Rules with no single legacy entry (new
detectors, and the aggregate families whose per-kind CWEs travel on the
finding tags) must NOT get an invented entry.
"""

from __future__ import annotations

import pytest

from attackmap.model import Finding
from attackmap.model.taxonomy import RULE_TAXONOMY, taxonomy_for
from attackmap.reasoning import REGISTRY

pytestmark = [pytest.mark.unit]

# Prefixes of the rule families whose ids were registered from a single
# legacy entry (AR046): routes (AR041), secrets (AR043), taint (AR044).
REGISTERED_PREFIXES = ("route_", "hardcoded_secret_", "secret_env_", "debug_mode_", "taint_sink_", "taint_flow_", "taint_speculative_")
REGISTERED_EXACT = {"vulnerable_dependency"}

# Rules with no 1:1 legacy taxonomy entry, registered nowhere on purpose:
# new detectors and the aggregate families (their legacy ids stay keyed
# per-kind; the per-kind CWE tags travel on the findings' `tags`).
UNREGISTERED_IDS = frozenset(
    {
        "demo_weak_default_credentials",
        "same_file_datastore_edge",
        "same_file_external_edge",
        "same_module_datastore_edge",
        "same_module_external_edge",
        "workflow_security",
        "supply_chain_risk",
    }
)


def _is_registered(rule_id: str) -> bool:
    return rule_id.startswith(REGISTERED_PREFIXES) or rule_id in REGISTERED_EXACT


def test_registry_ids_are_fully_classified():
    """Every registry id must be on one side: registered-from-legacy or
    deliberately unregistered. A new rule must join one side explicitly."""
    ids = set(REGISTRY.ids())
    classified = {rid for rid in ids if _is_registered(rid)} | set(UNREGISTERED_IDS)
    assert ids == classified, f"unclassified registry ids: {sorted(ids - classified)}"


def test_registered_ids_match_their_single_legacy_entry():
    for rule in REGISTRY.all_rules():
        rid = rule.meta.id
        if not _is_registered(rid):
            continue
        legacy = tuple(getattr(rule, "legacy_rule_ids", ()))
        assert legacy, f"{rid} registered but declares no legacy_rule_ids"
        entries = {taxonomy_for(lid) for lid in legacy}
        assert len(entries) == 1, f"{rid}: legacy ids {legacy} resolve to {len(entries)} entries"
        assert RULE_TAXONOMY[rid] == entries.pop(), f"{rid} diverges from its legacy entry"


def test_unregistered_ids_stay_out_of_the_taxonomy():
    for rid in UNREGISTERED_IDS:
        assert rid not in RULE_TAXONOMY, f"{rid} must not carry an invented taxonomy entry"


@pytest.mark.parametrize("rule_id", sorted(REGISTRY.ids()))
def test_finding_enrichment_is_identical_across_the_id_change(rule_id: str):
    """A finding carrying the stable id gets the same taxonomy + ATT&CK the
    legacy cascade finding gets — the strategy-equivalence guarantee. Rules
    without a single legacy entry carry no taxonomy at all (aggregates keep
    their per-kind CWE tags on the finding tags)."""
    rule = REGISTRY.get(rule_id)
    legacy_ids = tuple(getattr(rule, "legacy_rule_ids", ()))
    new = Finding(title="probe", severity="low", mitigation="m", rule_id=rule_id)
    if not _is_registered(rule_id):
        assert new.taxonomy is None  # no invented aggregate entry
        return
    assert legacy_ids, f"{rule_id} registered but declares no legacy_rule_ids"
    for legacy_id in legacy_ids:
        old = Finding(title="probe", severity="low", mitigation="m", rule_id=legacy_id)
        assert new.taxonomy == old.taxonomy, f"{rule_id} vs {legacy_id}: taxonomy diverges"
        assert [(t.technique_id, t.name, t.tactic, t.url) for t in new.attack_techniques] == [
            (t.technique_id, t.name, t.tactic, t.url) for t in old.attack_techniques
        ], f"{rule_id} vs {legacy_id}: ATT&CK techniques diverge"


def test_route_and_secret_rules_carry_documented_legacy_mappings():
    # Spot-check the module-docstring mappings stay attached to the rules.
    assert REGISTRY.get("route_public_webhook").legacy_rule_ids == ("public-webhook",)
    assert REGISTRY.get("hardcoded_secret_literals").legacy_rule_ids == ("hardcoded-secret",)
    assert REGISTRY.get("debug_mode_exposure").legacy_rule_ids == ("debug-enabled",)
    assert REGISTRY.get("taint_flow_sql_execute").legacy_rule_ids == ("sql-injection",)
    assert REGISTRY.get("taint_speculative_eval").legacy_rule_ids == ("speculative-eval",)
