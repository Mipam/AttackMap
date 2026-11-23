"""Rule registry: every catalogued id has taxonomy, specs live in rules.py."""

from __future__ import annotations

from attackmap.model.taxonomy import taxonomy_for
from attackmap.model import taxonomy
from attackmap.reasoning.rule_specs import RULES, registry, spec_tables
from attackmap.reasoning.threat_model import rule_catalog


def test_registry_matches_rule_catalog() -> None:
    catalog = {rid: (title, sev) for rid, title, sev in rule_catalog()}
    # The spec-backed table covers the legacy catalog; the union catalog also
    # lists the registry's stable ids (their specs live in the rule metadata,
    # see test_rules_command_lists_the_registry_catalog).
    assert set(registry()) <= set(catalog)
    for rid, rule in RULES.items():
        title, sev = catalog[rid]
        assert rule.title == title
        assert rule.severity == sev
        assert rule.rule_id == rid


def test_every_registered_rule_has_taxonomy() -> None:
    for rid in registry():
        if rid in taxonomy.INFORMATIONAL_RULES:
            assert taxonomy_for(rid) is None
            continue
        assert taxonomy_for(rid) is not None, rid


def test_spec_tables_are_the_finding_dictionaries() -> None:
    tables = spec_tables()
    assert "eval" in tables["taint"]
    assert "sql_execute" in tables["flow"]
    assert "weak_cipher" in tables["crypto"]
    assert "csrf_disabled" in tables["web_hardening"]
    assert "xxe" in tables["code_weakness"]
    assert "script_injection" in tables["workflow"]
    assert "typosquat_candidate" in tables["supply_chain"]
    assert "auth_outlier" in tables["anomaly"]
