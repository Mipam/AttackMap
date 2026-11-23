"""AR046 rules-CLI tests: `attackmap rules list/show` backed by the kernel
REGISTRY (the sub-app that replaced the old cascade-catalog flat command)."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from attackmap.reasoning.rules import REGISTRY
from attackmap.surfaces.rules_cli import rules_app

pytestmark = [pytest.mark.unit]

runner = CliRunner()


def test_rules_list_json_matches_registry_in_id_order():
    result = runner.invoke(rules_app, ["list", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert [entry["id"] for entry in payload] == list(REGISTRY.ids())  # sorted by stable id
    for entry, rule in zip(payload, REGISTRY.all_rules(), strict=True):
        assert entry["title"] == rule.meta.title
        assert entry["cwe"] == rule.meta.cwe
        assert entry["severity"] == rule.meta.severity
        assert entry["confidence"] == rule.meta.confidence
        assert entry["rationale"] == rule.meta.rationale
        assert entry["tags"] == list(rule.meta.tags)


def test_rules_list_plain_text_lists_every_stable_id():
    result = runner.invoke(rules_app, ["list"])
    assert result.exit_code == 0
    for rule_id in REGISTRY.ids():
        assert rule_id in result.output


def test_rules_show_prints_meta_legacy_mapping_and_docstring():
    result = runner.invoke(rules_app, ["show", "route_public_webhook"])
    assert result.exit_code == 0
    assert "id: route_public_webhook" in result.output
    assert "CWE-345" in result.output
    assert "public-webhook" in result.output  # the legacy mapping is surfaced
    assert "webhook" in result.output.lower()  # the rule docstring (evidence expectations)


def test_rules_show_unknown_id_exits_non_zero_with_clear_message():
    result = runner.invoke(rules_app, ["show", "no_such_rule"])
    assert result.exit_code == 1
    assert "unknown rule id" in result.output
    assert "rules list" in result.output  # points at the catalog command
