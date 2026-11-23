"""Deterministic tests for the versioned EvidenceBundle (AR067/AC-309).

All tests use synthetic fixtures and fake providers only — no LM Studio or
any live provider (AGENTS.md: live runs are reported separately).
"""
import json

import pytest

from attackmap.ai.evidence_bundle import (
    BUNDLE_SCHEMA_VERSION,
    SUPPORTED_BUNDLE_SCHEMA_VERSIONS,
    BundleSchemaError,
    EvidenceBundle,
    build_evidence_bundle,
    gate_bundle_schema_version,
    validate_bundle_citations,
)
from attackmap.models import AttackPath, Control, Finding, ScanResult
from attackmap.output.llm_review import generate_llm_review
from attackmap.output.review_prompts import render_review_prompts
from attackmap.output.security_overlay import SecurityOverlay


def _scan(**kwargs) -> ScanResult:
    base = {"root": ".", "files_scanned": 3, "languages": ["python"]}
    base.update(kwargs)
    return ScanResult(**base)


def _finding(**kwargs) -> Finding:
    base = {
        "title": "eval of request data",
        "severity": "high",
        "rule_id": "eval_usage",
        "evidence": ["app.py:7 eval(request.args['x'])"],
        "mitigation": "Remove the eval call.",
        "confidence": "high",
        "rationale": "Rule rationale: request-derived data reaches eval at app.py:7.",
    }
    base.update(kwargs)
    return Finding(**base)


def _overlay(controls) -> SecurityOverlay:
    return SecurityOverlay(assets=[], controls=controls, insights=[],
                           detection_opportunities=[], findings=[])


# --- build from the post-AR049 analysis result -------------------------------


def test_bundle_builds_from_synthetic_analysis_result() -> None:
    scan = _scan(limitations=["symlink out of tree skipped (#234)"])
    findings = [_finding(), _finding(title="second", rule_id="second_rule")]
    paths = [AttackPath(name="entry to eval", steps=[f"step {i}" for i in range(12)],
                        impact="remote code execution risk")]
    control = Control(id="auth-global", kind="authentication", name="Global auth middleware",
                      strength="strong", scope="global")
    bundle = build_evidence_bundle(scan, [], findings, paths,
                                   overlay=_overlay([control]), run_id="run-test")

    assert bundle.schema_version == BUNDLE_SCHEMA_VERSION == 1
    assert bundle.run_id == "run-test"
    # Stable citation ids, in pack order.
    assert [f.id for f in bundle.findings] == ["finding:1", "finding:2"]
    assert [p.id for p in bundle.paths] == ["path:1"]
    assert bundle.citation_ids() == ("finding:1", "finding:2", "path:1", "auth-global")
    # The bundle references AR049 rationale/evidence rather than re-deriving it.
    assert bundle.findings[0].rationale.startswith("Rule rationale:")
    assert bundle.findings[0].evidence == ("app.py:7 eval(request.args['x'])",)
    # Controls keep their own stable id and record verbatim.
    assert bundle.controls[0].id == "auth-global"
    assert bundle.controls[0].to_payload()["strength"] == "strong"
    # Path steps mirror the evidence-pack cap.
    assert len(bundle.paths[0].steps) == 8
    # Limitations carry the scan's own limitations plus the static projection note.
    assert "symlink out of tree skipped (#234)" in bundle.limitations
    assert any("static analysis projection" in note for note in bundle.limitations)


def test_bundle_caps_are_disclosed_in_limitations() -> None:
    findings = [_finding(title=f"finding {i}", rule_id=f"rule_{i}") for i in range(35)]
    bundle = build_evidence_bundle(_scan(), [], findings, [], run_id="r")
    assert len(bundle.findings) == 30
    assert any("30 of 35 findings" in note for note in bundle.limitations)


def test_bundle_run_id_is_deterministic_for_same_snapshot() -> None:
    scan = _scan()
    first = build_evidence_bundle(scan, [], [_finding()], [])
    second = build_evidence_bundle(scan, [], [_finding()], [])
    assert first.run_id == second.run_id and first.run_id


# --- compatibility gate (AR083 hook point) ---------------------------------


def test_gate_accepts_current_and_documented_versions() -> None:
    assert gate_bundle_schema_version(BUNDLE_SCHEMA_VERSION) == BUNDLE_SCHEMA_VERSION
    for version in SUPPORTED_BUNDLE_SCHEMA_VERSIONS:
        assert gate_bundle_schema_version(version) == version


def test_gate_rejects_newer_version_with_clear_error() -> None:
    with pytest.raises(BundleSchemaError, match="newer"):
        gate_bundle_schema_version(BUNDLE_SCHEMA_VERSION + 1)


def test_gate_rejects_unknown_and_malformed_versions() -> None:
    with pytest.raises(BundleSchemaError, match="unknown"):
        gate_bundle_schema_version(0)
    with pytest.raises(BundleSchemaError, match="integer"):
        gate_bundle_schema_version("1")
    with pytest.raises(BundleSchemaError, match="integer"):
        gate_bundle_schema_version(True)  # bool is an int subclass; rejected
    with pytest.raises(BundleSchemaError, match="integer"):
        gate_bundle_schema_version(None)


# --- serialization + gate on ingest ------------------------------------------


def test_payload_roundtrip_is_lossless_and_gated() -> None:
    scan = _scan(limitations=["analyzer timeout on vendor/"])
    bundle = build_evidence_bundle(scan, [], [_finding()], [], run_id="run-rt")
    payload = json.loads(json.dumps(bundle.to_payload()))
    assert payload["schema_version"] == BUNDLE_SCHEMA_VERSION
    assert EvidenceBundle.from_payload(payload) == bundle

    newer = dict(payload, schema_version=BUNDLE_SCHEMA_VERSION + 1)
    with pytest.raises(BundleSchemaError, match="newer"):
        EvidenceBundle.from_payload(newer)
    unknown = dict(payload, schema_version=0)
    with pytest.raises(BundleSchemaError, match="unknown"):
        EvidenceBundle.from_payload(unknown)


def test_bundle_constructor_enforces_the_gate() -> None:
    with pytest.raises(BundleSchemaError):
        EvidenceBundle(schema_version=99, run_id="x", findings=(), paths=(),
                       controls=(), limitations=())


# --- citation enforcement: uncited claims are rejected ------------------------


def test_uncited_claim_is_rejected_by_the_validator() -> None:
    bundle = build_evidence_bundle(_scan(), [], [_finding()], [], run_id="r")
    validation = validate_bundle_citations(
        "# Review\n\nThe application has no security problems whatsoever.", bundle
    )
    assert not validation.accepted
    assert validation.rejected_claims == (
        "The application has no security problems whatsoever.",
    )
    assert validation.reference_validity == "missing"


def test_cited_claim_is_accepted_and_unknown_id_is_rejected() -> None:
    bundle = build_evidence_bundle(_scan(), [], [_finding()], [], run_id="r")
    cited = validate_bundle_citations(
        "- Weakness: eval of request data (finding:1).", bundle
    )
    assert cited.accepted
    assert cited.valid_references == ("finding:1",)
    assert cited.rejected_claims == ()

    unknown = validate_bundle_citations(
        "- Weakness: eval of request data (finding:999).", bundle
    )
    assert not unknown.accepted
    assert unknown.invalid_references == ("finding:999",)
    assert unknown.rejected_claims  # cites no valid bundle id -> rejected


def test_non_claim_lines_are_never_rejected() -> None:
    bundle = build_evidence_bundle(_scan(), [], [_finding()], [], run_id="r")
    text = "\n".join([
        "# Defensive review",
        "> Evidence reference check: valid.",
        "```",
        "plain code fence content lives here",
        "```",
        "| table | row |",
        "## Strengths",
    ])
    assert validate_bundle_citations(text, bundle).accepted


# --- prompts consume the bundle ----------------------------------------------


def test_render_review_prompts_builds_pack_from_bundle() -> None:
    scan = _scan(limitations=["coverage partial"])
    args = (scan, [], [_finding()], [])
    implicit = render_review_prompts(*args)
    bundle = build_evidence_bundle(scan, [], [_finding()], [])
    explicit = render_review_prompts(*args, bundle=bundle)
    # Same projection either way: the prompt is built from the bundle.
    assert json.loads(explicit.evidence_json) == json.loads(implicit.evidence_json)

    pack = json.loads(explicit.evidence_json)
    assert pack["findings"][0]["rationale"].startswith("Rule rationale:")
    assert pack["findings"][0]["evidence"] == ["app.py:7 eval(request.args['x'])"]
    assert "coverage partial" in pack["limitations"]
    assert any("static analysis projection" in note for note in pack["limitations"])

    bounded = render_review_prompts(*args, bundle=bundle, max_evidence_chars=14000)
    bounded_pack = json.loads(bounded.evidence_json)
    assert bounded_pack["findings"][0] == pack["findings"][0]
    assert "limitations" in bounded_pack["context_selection"]["sections"]


def test_llm_review_enforces_bundle_citations_via_metadata(tmp_path) -> None:
    """Fake-provider flow: bundle enforcement metadata is attached and
    JSON-safe; the model markdown itself is never rewritten."""
    from types import SimpleNamespace

    from attackmap.ai.ai_budget import AiBudget

    original = "This deployment is completely safe and no findings matter."

    class FakeProvider:
        base_url = "http://127.0.0.1:1234/v1"

        def __init__(self):
            self.responses = self

        def with_options(self, **kwargs):
            return self

        def create(self, **kwargs):
            return SimpleNamespace(output_text=original, model="offline-fake",
                                   status="completed",
                                   usage=SimpleNamespace(input_tokens=2, output_tokens=3))

    ledger = AiBudget(max_calls=1, max_seconds=30, output_token_limit=64)
    result = generate_llm_review(
        ScanResult(root=str(tmp_path)), [], [_finding()], [],
        mode="review", provider="openai", backend="api", effort="high",
        max_tokens=64, openai_client=FakeProvider(), budget=ledger,
    )
    metadata = result.reference_validation
    assert metadata["bundle_schema_version"] == BUNDLE_SCHEMA_VERSION
    assert metadata["bundle_run_id"]
    assert metadata["bundle_citation_enforcement"] == "uncited_claims_rejected"
    assert metadata["uncited_claims"] == [original]
    # Existing validation behavior is preserved.
    assert metadata["claim_support"] == "not_assessed"
    assert result.markdown.endswith(original)
    # The metadata must survive a JSON round trip (pipeline persists it).
    json.loads(json.dumps(metadata))
