"""AR043 secret/config rule tests.

The rules in ``attackmap.reasoning.rules.secrets`` are a port of the legacy
cascade branches (``hardcoded-secret``, ``secret-env-reference`` and the
``debug_enabled`` config-exposure family). The cascade is still the active
producer, so every equivalence test here builds one fixture scan and compares
the rule's findings field-by-field against ``generate_findings`` output for
the legacy rule id. The negative fixtures ride the real extraction pass
(``iter_secret_matches``) to prove placeholders, high-entropy hashes and
integrity digests never become literal-secret hints in the first place.

Self-contained by design: no conftest, no shared harness, no disk fixtures.
"""

from __future__ import annotations

import base64

import pytest

from attackmap.extraction.scanner import iter_secret_matches
from attackmap.foundation.srcpaths import is_test_file
from attackmap.model import ScanResult, SecretHint, WebHardeningIssue
from attackmap.reasoning import REGISTRY, ReasoningContext
from attackmap.reasoning.rules.secrets import (
    DebugModeExposureRule,
    HardcodedSecretLiteralsRule,
    SecretEnvReferencesRule,
)
from attackmap.reasoning.threat_model import generate_findings

pytestmark = [pytest.mark.unit]

# --- fixtures -----------------------------------------------------------------

# Obvious fakes (placeholder words on purpose) used as raw secret material in
# the redaction-leak gate. Nothing provider-shaped or plausibly real.
RAW_SECRET_LITERALS = (
    "example-password-123-longer",
    "fake-token-abcdefgh1234567890",
    "example-key-9876543210abcdef",
    "example-password-123",
)

# sha256("test") — a published digest of a public corpus, i.e. a high-entropy
# NON-secret. Integrity digests are computed in-test from deterministic bytes.
SHA256_HEX_DIGEST = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"


def _literal_hint(**overrides) -> SecretHint:
    """A scanner-faithful literal-secret hint: masked display name, redacted
    snippet, confidence tiering like the real passes (provider shapes 1.0,
    config literal 0.9, keyword-proximity assignment 0.5)."""
    fields = dict(
        name="exam…",
        file="app/settings.py",
        line=12,
        kind="credential_assignment",
        confidence=0.5,
        evidence_text='ADMIN_PASSWORD = "***"',
    )
    fields.update(overrides)
    return SecretHint(**fields)


def _mixed_secret_scan() -> ScanResult:
    """The AR043 equivalence fixture: literal secrets at several confidence
    tiers, env references, a `.env.example` template, debug config exposure in
    two files at two severities, plus an unrelated web-hardening issue the
    ported rules must ignore."""
    return ScanResult(
        root="",
        secret_hints=[
            _literal_hint(name="exam…", file="app/settings.py", line=12, kind="credential_assignment", confidence=0.5),
            _literal_hint(name="fake…", file="app/pay.py", line=3, kind="config_literal", confidence=0.9, evidence_text='api_key = "***"'),
            SecretHint(name="API_KEY", file="app/client.py", line=14, kind="env_reference", evidence_text='os.getenv("API_KEY")'),
            SecretHint(name="JWT_SECRET", file=".env.example", line=2, kind="env_template", evidence_text="JWT_SECRET=${JWT_SECRET}"),
        ],
        web_hardening_issues=[
            WebHardeningIssue(kind="debug_enabled", file="app/settings.py", line=30, evidence_text="DEBUG = True", severity="medium"),
            WebHardeningIssue(kind="debug_enabled", file="app/main.py", line=7, evidence_text="app.run(debug=True)", severity="high"),
            WebHardeningIssue(kind="weak_csp", file="app/middleware.py", line=9, evidence_text="unsafe-inline", severity="medium"),
        ],
        scanned_files=["app/settings.py", "app/pay.py", "app/client.py", ".env.example", "app/main.py", "app/middleware.py"],
        files_scanned=6,
    )


def _legacy_finding(scan: ScanResult, legacy_rule_id: str):
    """The cascade's single finding for a legacy rule id on this scan."""
    matches = [f for f in generate_findings(scan, attack_surfaces=[]) if f.rule_id == legacy_rule_id]
    assert len(matches) == 1, f"legacy cascade produced {len(matches)} {legacy_rule_id!r} findings"
    return matches[0]


def _assert_identical(actual, legacy) -> None:
    """Every branch-owned field must match the cascade output exactly.

    ``rule_id`` differs by design (stable snake_case id, mapping documented in
    the module docstring) and ``score`` is attached by the cascade's shared
    post-pass over all findings, not by the ported branch — both are asserted
    separately, not silently skipped.
    """
    assert actual.title == legacy.title
    assert actual.severity == legacy.severity
    assert actual.confidence == legacy.confidence
    assert actual.evidence == legacy.evidence
    assert actual.mitigation == legacy.mitigation
    assert actual.tags == legacy.tags
    assert [(loc.file, loc.line) for loc in actual.locations] == [(loc.file, loc.line) for loc in legacy.locations]
    assert actual.taxonomy == legacy.taxonomy
    assert [(t.technique_id, t.name, t.tactic, t.url) for t in actual.attack_techniques] == [
        (t.technique_id, t.name, t.tactic, t.url) for t in legacy.attack_techniques
    ]
    assert actual.score is None  # scoring stays with the pipeline wiring
    assert actual.rule_id != legacy.rule_id  # new stable id; legacy id stays in the taxonomy registry


# --- equivalence with the legacy cascade ---------------------------------------


def test_hardcoded_literals_rule_matches_legacy_cascade():
    scan = _mixed_secret_scan()
    actual = HardcodedSecretLiteralsRule().evaluate(ReasoningContext.from_scan(scan))
    assert len(actual) == 1
    _assert_identical(actual[0], _legacy_finding(scan, "hardcoded-secret"))
    # The literal finding carries only literal-kind hints.
    assert actual[0].evidence == [
        "[credential_assignment] exam… in app/settings.py",
        "[config_literal] fake… in app/pay.py",
    ]


def test_env_references_rule_matches_legacy_cascade():
    scan = _mixed_secret_scan()
    actual = SecretEnvReferencesRule().evaluate(ReasoningContext.from_scan(scan))
    assert len(actual) == 1
    _assert_identical(actual[0], _legacy_finding(scan, "secret-env-reference"))
    assert actual[0].evidence == [
        "API_KEY in app/client.py",
        "JWT_SECRET in .env.example",
    ]


def test_debug_exposure_rule_matches_legacy_cascade():
    scan = _mixed_secret_scan()
    actual = DebugModeExposureRule().evaluate(ReasoningContext.from_scan(scan))
    assert len(actual) == 1
    _assert_identical(actual[0], _legacy_finding(scan, "debug-enabled"))
    # Aggregated severity is the strongest debug issue (high), and the
    # unrelated weak_csp issue is not part of this family's finding.
    assert actual[0].severity == "high"
    assert actual[0].evidence == [
        "app/settings.py:30 — DEBUG = True",
        "app/main.py:7 — app.run(debug=True)",
    ]


def test_hardcoded_confidence_tiers_down_on_weak_signals_only():
    # Keyword-proximity assignments (#252) alone are the weaker signal: the
    # legacy branch tiers the band to medium when no hint reaches 0.6.
    scan = ScanResult(
        root="",
        secret_hints=[_literal_hint()],
        scanned_files=["app/settings.py"],
        files_scanned=1,
    )
    actual = HardcodedSecretLiteralsRule().evaluate(ReasoningContext.from_scan(scan))
    assert len(actual) == 1
    _assert_identical(actual[0], _legacy_finding(scan, "hardcoded-secret"))
    assert actual[0].confidence == "medium"


# --- negative fixtures (ride the real extraction pass) -------------------------


def test_placeholders_and_templates_never_become_literal_hints():
    placeholder_content = "\n".join(
        [
            'API_KEY = "CHANGE_ME"',
            'DB_PASSWORD = "${VAULT_SECRET}"',
            'TOKEN = "your-token-here"',
        ]
    )
    # Extraction never emits a literal hint for placeholder / template values,
    # so there is nothing for the hardcoded rule to fire on.
    assert list(iter_secret_matches(placeholder_content)) == []

    # A `.env.example`-style template hint is a *name*, not a value (#39):
    # it belongs to the env-reference finding, never the literal one.
    scan = ScanResult(
        root="",
        secret_hints=[
            SecretHint(name="JWT_SECRET", file=".env.example", line=2, kind="env_template", evidence_text="JWT_SECRET=${JWT_SECRET}"),
        ],
        scanned_files=[".env.example"],
        files_scanned=1,
    )
    ctx = ReasoningContext.from_scan(scan)
    assert HardcodedSecretLiteralsRule().evaluate(ctx) == []
    env_findings = SecretEnvReferencesRule().evaluate(ctx)
    assert len(env_findings) == 1
    _assert_identical(env_findings[0], _legacy_finding(scan, "secret-env-reference"))


def test_high_entropy_hashes_and_integrity_digests_do_not_fire():
    sha384_body = base64.b64encode(bytes(range(48))).decode()
    sha512_body = base64.b64encode(bytes(range(64))).decode()
    content = "\n".join(
        [
            f'digest = "{SHA256_HEX_DIGEST}"',  # commit-SHA/hash shape: not a secret
            f'<script src="https://cdn.example/app.js" integrity="sha384-{sha384_body}"></script>',
            f'"integrity": "sha512-{sha512_body}"',  # lockfile integrity field
        ]
    )
    # High-entropy base64/hex that fingerprints public assets never becomes a
    # literal-secret hint, so the rule (and the cascade) stay silent.
    assert list(iter_secret_matches(content)) == []
    scan = ScanResult(root="", scanned_files=["web/index.html"], files_scanned=1)
    ctx = ReasoningContext.from_scan(scan)
    assert HardcodedSecretLiteralsRule().evaluate(ctx) == []
    assert DebugModeExposureRule().evaluate(ctx) == []
    assert SecretEnvReferencesRule().evaluate(ctx) == []
    assert not [f for f in generate_findings(scan, attack_surfaces=[]) if f.rule_id == "hardcoded-secret"]


def test_clean_scan_emits_no_findings():
    ctx = ReasoningContext()
    assert HardcodedSecretLiteralsRule().evaluate(ctx) == []
    assert SecretEnvReferencesRule().evaluate(ctx) == []
    assert DebugModeExposureRule().evaluate(ctx) == []


# --- low-quality-source behavior ------------------------------------------------


def test_low_quality_source_hints_follow_cascade_behavior():
    # The branch itself does not quality-gate: hints from test/vendored paths
    # that survived extraction (provider shapes still fire there) are reported
    # exactly like first-party ones. The fixture path must genuinely classify
    # as a test file so the case models a low-quality source.
    test_path = "tests/fixtures/credentials_example.py"
    assert is_test_file(test_path)
    scan = ScanResult(
        root="",
        secret_hints=[
            _literal_hint(name="fake…", file=test_path, line=5, kind="config_literal", confidence=0.9, evidence_text='api_key = "***"'),
        ],
        scanned_files=[test_path],
        files_scanned=1,
    )
    actual = HardcodedSecretLiteralsRule().evaluate(ReasoningContext.from_scan(scan))
    assert len(actual) == 1
    _assert_identical(actual[0], _legacy_finding(scan, "hardcoded-secret"))
    assert [(loc.file, loc.line) for loc in actual[0].locations] == [(test_path, 5)]


# --- evidence cap / locations semantics -----------------------------------------


def test_evidence_is_capped_but_locations_list_every_hint():
    scan = ScanResult(
        root="",
        secret_hints=[
            _literal_hint(file=f"app/mod_{i}.py", line=i + 1, evidence_text='ADMIN_PASSWORD = "***"') for i in range(12)
        ],
        scanned_files=[f"app/mod_{i}.py" for i in range(12)],
        files_scanned=12,
    )
    actual = HardcodedSecretLiteralsRule().evaluate(ReasoningContext.from_scan(scan))
    assert len(actual) == 1
    _assert_identical(actual[0], _legacy_finding(scan, "hardcoded-secret"))
    assert len(actual[0].evidence) == 10  # evidence capped, like every cascade branch
    assert len(actual[0].locations) == 12  # locations are never capped (#214)


def test_debug_evidence_overflow_line_matches_cascade():
    scan = ScanResult(
        root="",
        web_hardening_issues=[
            WebHardeningIssue(kind="debug_enabled", file=f"app/mod_{i}.py", line=i + 1, evidence_text="DEBUG = True", severity="medium")
            for i in range(12)
        ],
        scanned_files=[f"app/mod_{i}.py" for i in range(12)],
        files_scanned=12,
    )
    actual = DebugModeExposureRule().evaluate(ReasoningContext.from_scan(scan))
    assert len(actual) == 1
    _assert_identical(actual[0], _legacy_finding(scan, "debug-enabled"))
    assert actual[0].evidence[-1] == "+2 more occurrence(s)"
    assert len(actual[0].evidence) == 11
    assert len(actual[0].locations) == 12


# --- redaction gate (hard requirement) ------------------------------------------


def test_no_raw_secret_material_leaks_into_findings():
    # Build the hint evidence the way a scanned file would look BEFORE
    # redaction; SecretHint's model validator must mask it at construction.
    evidence_shapes = {
        "example-password-123-longer": 'ADMIN_PASSWORD = "example-password-123-longer"',
        "fake-token-abcdefgh1234567890": 'API_TOKEN = "fake-token-abcdefgh1234567890"',
        "example-key-9876543210abcdef": 'db_api_key = "example-key-9876543210abcdef"',
        "example-password-123": "postgres://app:example-password-123@db.internal/prod",
    }
    hints = [
        SecretHint(
            name="exam…",  # scanner stores only the masked display form
            file="app/leaky.py",
            line=line,
            kind="credential_assignment",
            confidence=0.5,
            evidence_text=snippet,
        )
        for line, snippet in enumerate(evidence_shapes.values(), start=10)
    ]
    for hint, (raw, _shape) in zip(hints, evidence_shapes.items(), strict=True):
        assert raw not in hint.evidence_text, f"raw secret material survived hint construction: {raw!r}"
        assert "***" in hint.evidence_text  # redaction actually transformed the snippet

    scan = ScanResult(
        root="",
        secret_hints=hints,
        web_hardening_issues=[
            WebHardeningIssue(kind="debug_enabled", file="app/leaky.py", line=99, evidence_text="DEBUG = True", severity="medium")
        ],
        scanned_files=["app/leaky.py"],
        files_scanned=1,
    )
    result = REGISTRY.evaluate_all(ReasoningContext.from_scan(scan))
    assert result.errors == []
    findings = [f for f in result.findings if f.rule_id in {HardcodedSecretLiteralsRule.meta.id, SecretEnvReferencesRule.meta.id, DebugModeExposureRule.meta.id}]
    assert len(findings) == 2  # literal finding + debug finding; no env-reference hints here
    for finding in findings:
        emitted_text = "\n".join(
            [finding.title, finding.mitigation, *finding.evidence, *(loc.file for loc in finding.locations)]
        )
        for raw in RAW_SECRET_LITERALS:
            assert raw not in emitted_text, f"raw secret material leaked into finding evidence: {raw!r}"


# --- registry contract -----------------------------------------------------------


def test_ar043_rules_register_with_stable_ids_and_attribution():
    expected = {rule.meta.id for rule in (HardcodedSecretLiteralsRule(), SecretEnvReferencesRule(), DebugModeExposureRule())}
    assert expected == {"hardcoded_secret_literals", "secret_env_references", "debug_mode_exposure"}
    for rule_id in expected:
        rule = REGISTRY.get(rule_id)
        assert rule is not None
        # RuleMeta validates the stable snake_case pattern at construction;
        # re-assert here so a docstring mapping and the ids can't drift apart.
        assert rule_id.replace("_", "").isalnum()
    # Findings carry rule_id == meta.id (attributable, suppressible).
    result = REGISTRY.evaluate_all(ReasoningContext.from_scan(_mixed_secret_scan()))
    assert result.errors == []
    emitted = {f.rule_id for f in result.findings}
    for rule_id in expected:
        assert rule_id in emitted
        for finding in result.findings:
            if finding.rule_id == rule_id:
                assert finding.title == REGISTRY.get(rule_id).meta.title
