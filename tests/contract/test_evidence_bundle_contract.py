"""Contract tests for AC-309: the AI boundary is versioned.

``EvidenceBundle`` has a schema version and compatibility gate; uncited
claims are rejected. Deterministic fixtures only — no live provider.
"""
import json

import pytest

from attackmap.ai.evidence_bundle import (
    BUNDLE_SCHEMA_VERSION,
    BundleSchemaError,
    EvidenceBundle,
    build_evidence_bundle,
    gate_bundle_schema_version,
    validate_bundle_citations,
)
from attackmap.models import AttackPath, Finding, ScanResult
from attackmap.output.review_prompts import render_review_prompts


def _bundle() -> EvidenceBundle:
    finding = Finding(
        title="eval of request data",
        severity="high",
        rule_id="eval_usage",
        evidence=["app.py:7 eval(request.args['x'])"],
        mitigation="Remove the eval call.",
        confidence="high",
        rationale="Rule rationale: request-derived data reaches eval at app.py:7.",
    )
    return build_evidence_bundle(
        ScanResult(root=".", files_scanned=1), [], [finding],
        [AttackPath(name="chain", steps=["s1"], impact="impact")],
        run_id="contract-run",
    )


def test_ac309_bundle_schema_version_constant_and_gate() -> None:
    assert type(BUNDLE_SCHEMA_VERSION) is int
    assert gate_bundle_schema_version(BUNDLE_SCHEMA_VERSION) == BUNDLE_SCHEMA_VERSION
    with pytest.raises(BundleSchemaError):
        gate_bundle_schema_version(BUNDLE_SCHEMA_VERSION + 1)
    with pytest.raises(BundleSchemaError):
        gate_bundle_schema_version(-1)


def test_ac309_bundle_serializes_as_json_and_roundtrips() -> None:
    bundle = _bundle()
    payload = json.loads(json.dumps(bundle.to_payload()))
    assert payload["schema_version"] == BUNDLE_SCHEMA_VERSION
    assert EvidenceBundle.from_payload(payload) == bundle


def test_ac309_prompts_are_built_from_the_bundle() -> None:
    bundle = _bundle()
    rendered = render_review_prompts(
        ScanResult(root=".", files_scanned=1), [],
        [Finding(title="eval of request data", severity="high", rule_id="eval_usage",
                 evidence=["app.py:7 eval(request.args['x'])"], mitigation="Remove eval.",
                 confidence="high",
                 rationale="Rule rationale: request-derived data reaches eval at app.py:7.")],
        [AttackPath(name="chain", steps=["s1"], impact="impact")],
        bundle=bundle,
    )
    pack = json.loads(rendered.evidence_json)
    # The pack's citable sections are exactly the bundle's projections.
    assert [item["id"] for item in pack["findings"]] == [f.id for f in bundle.findings]
    assert [item["id"] for item in pack["attack_paths"]] == [p.id for p in bundle.paths]
    assert pack["findings"][0]["rationale"] == bundle.findings[0].rationale
    assert pack["limitations"] == list(bundle.limitations)
    for citation_id in bundle.citation_ids():
        assert citation_id


def test_ac309_uncited_claim_fixture_is_rejected() -> None:
    bundle = _bundle()
    validation = validate_bundle_citations(
        "No authentication weaknesses exist anywhere in this service at all.", bundle
    )
    assert validation.rejected_claims, "uncited claim must be rejected"
    assert not validation.accepted
    grounded = validate_bundle_citations(
        "Weakness: eval of request data, confirmed statically (finding:1).", bundle
    )
    assert grounded.accepted
    assert grounded.rejected_claims == ()
