"""AR040 rule-kernel tests: RuleMeta validation, Rule protocol, registry
determinism/isolation, and the narrow read-only ReasoningContext."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from attackmap.model import (
    AuthHint,
    CodeWeakness,
    DatabaseHint,
    ExternalCall,
    Finding,
    Route,
    ScanResult,
    SecretHint,
    TaintChain,
    WebHardeningIssue,
)
from attackmap.reasoning import (
    REGISTRY,
    ReasoningContext,
    Rule,
    RuleMeta,
    RuleRegistry,
    confidence_band,
)

# --- fixtures ----------------------------------------------------------------


def _make_finding(rule_id: str, title: str | None = None) -> Finding:
    return Finding(title=title or f"finding {rule_id}", severity="low", mitigation="fix it", rule_id=rule_id)


def _make_rule(rule_id: str, findings: list[Finding] | None = None, error: Exception | None = None):
    payload = list(findings or [])

    class _Rule:
        meta = RuleMeta(
            id=rule_id,
            title=f"Rule {rule_id}",
            cwe="CWE-000",
            severity="low",
            confidence=0.5,
            rationale="kernel test rule",
        )

        def evaluate(self, ctx: ReasoningContext) -> list[Finding]:
            if error is not None:
                raise error
            return list(payload)

    return _Rule()


def _scan() -> ScanResult:
    return ScanResult(
        root="C:/tmp/fake-repo",
        routes=[
            Route(path="/login", method="POST", file="app/web.py", auth="anonymous"),
            Route(path="/api/users", method="GET", file="app/api.py"),
        ],
        external_calls=[ExternalCall(target="https://payments.example", file="app/api.py", method="POST")],
        databases=[DatabaseHint(kind="postgres", file="app/db.py")],
        auth_hints=[AuthHint(hint="service_name: web", file="app/web.py")],
        secret_hints=[
            SecretHint(
                name="ADMIN_PASSWORD",
                file="app/config.py",
                line=12,
                kind="hardcoded",
                evidence_text="ADMIN_PASSWORD = '...'",
            )
        ],
        taint_chains=[
            TaintChain(
                route_path="/search",
                route_method="GET",
                route_file="app/web.py",
                sink_kind="sql_execute",
                sink_file="app/db.py",
                sink_line=30,
                hops=1,
            )
        ],
        code_weaknesses=[CodeWeakness(kind="xxe", file="app/xml.py")],
        web_hardening_issues=[WebHardeningIssue(kind="debug_enabled", file="app/settings.py")],
        scanned_files=["app/web.py", "app/api.py", "app/config.py", "index.ts"],
        files_scanned=4,
    )


# --- RuleMeta contract -------------------------------------------------------


def test_rule_meta_id_pattern_is_enforced():
    with pytest.raises(ValidationError):
        RuleMeta(id="Bad-Id", title="t", severity="low", confidence=0.5, rationale="r")
    with pytest.raises(ValidationError):
        RuleMeta(id="1starts_digit", title="t", severity="low", confidence=0.5, rationale="r")
    meta = RuleMeta(id="good_rule_2", title="t", severity="low", confidence=0.5, rationale="r")
    assert meta.id == "good_rule_2"


def test_rule_meta_rejects_bad_severity_and_confidence():
    with pytest.raises(ValidationError):
        RuleMeta(id="r", title="t", severity="critical", confidence=0.5, rationale="r")
    with pytest.raises(ValidationError):
        RuleMeta(id="r", title="t", severity="low", confidence=1.5, rationale="r")
    with pytest.raises(ValidationError):
        RuleMeta(id="r", title="t", severity="low", confidence=-0.1, rationale="r")


def test_rule_meta_rejects_empty_title_and_rationale():
    with pytest.raises(ValidationError):
        RuleMeta(id="r", title="", severity="low", confidence=0.5, rationale="r")
    with pytest.raises(ValidationError):
        RuleMeta(id="r", title="   ", severity="low", confidence=0.5, rationale="r")
    with pytest.raises(ValidationError):
        RuleMeta(id="r", title="t", severity="low", confidence=0.5, rationale="")


# --- registry: determinism, duplicates, lookup -------------------------------


def test_registration_is_deterministic_across_registries():
    first = RuleRegistry()
    first.register(_make_rule("beta_rule"))
    first.register(_make_rule("alpha_rule"))
    second = RuleRegistry()
    second.register(_make_rule("alpha_rule"))
    second.register(_make_rule("beta_rule"))
    assert [r.meta.id for r in first.all_rules()] == ["alpha_rule", "beta_rule"]
    assert [r.meta.id for r in second.all_rules()] == [r.meta.id for r in first.all_rules()]
    assert first.ids() == second.ids() == ("alpha_rule", "beta_rule")


def test_duplicate_id_is_rejected():
    registry = RuleRegistry()
    registry.register(_make_rule("dup_rule"))
    with pytest.raises(ValueError, match="dup_rule"):
        registry.register(_make_rule("dup_rule"))


def test_register_requires_rule_meta():
    registry = RuleRegistry()

    class NotARule:
        pass

    with pytest.raises(TypeError, match="RuleMeta"):
        registry.register(NotARule())  # type: ignore[arg-type]


def test_get_returns_none_for_unknown():
    assert RuleRegistry().get("nope") is None
    assert "nope" not in REGISTRY


# --- ReasoningContext: narrow, read-only snapshot ----------------------------


def test_context_from_scan_copies_narrow_slices():
    scan = _scan()
    ctx = ReasoningContext.from_scan(scan)
    assert len(ctx.routes) == 2
    assert len(ctx.external_calls) == 1
    assert len(ctx.databases) == 1
    assert len(ctx.auth_hints) == 1
    assert len(ctx.secret_hints) == 1
    assert len(ctx.taint_chains) == 1
    assert len(ctx.code_weaknesses) == 1
    assert len(ctx.web_hardening_issues) == 1
    assert ctx.scanned_files == ("app/web.py", "app/api.py", "app/config.py", "index.ts")
    assert ctx.files_scanned == 4
    assert ctx.root == scan.root
    # Collections are frozen tuples, never the mutable scan lists.
    assert isinstance(ctx.routes, tuple)


def test_context_never_exposes_scan_result():
    assert "scan" not in ReasoningContext.model_fields
    ctx = ReasoningContext.from_scan(_scan())
    assert not hasattr(ctx, "scan")
    assert not isinstance(ctx, ScanResult)


def test_context_snapshot_isolated_from_scan_mutation():
    scan = _scan()
    ctx = ReasoningContext.from_scan(scan)
    assert ctx.routes[0] is scan.routes[0]  # records shared by reference (AR022 convention)
    scan.routes.append(Route(path="/late", file="late.py"))
    scan.root = "somewhere-else"
    assert len(ctx.routes) == 2
    assert ctx.root == "C:/tmp/fake-repo"


def test_context_is_frozen():
    ctx = ReasoningContext.from_scan(_scan())
    with pytest.raises(ValidationError):
        ctx.routes = ()


def test_context_mappings_are_read_only():
    ctx = ReasoningContext(routes=(), source_texts={"a.py": "text"})
    with pytest.raises(TypeError):
        ctx.source_texts["b.py"] = "more"
    with pytest.raises(TypeError):
        ctx.routes_by_file["c.py"] = ()
    with pytest.raises(TypeError):
        ctx.calls_by_file["c.py"] = ()


def test_context_helper_lookups():
    ctx = ReasoningContext.from_scan(_scan())
    assert [r.path for r in ctx.routes_by_file["app/web.py"]] == ["/login"]
    assert [c.target for c in ctx.calls_by_file["app/api.py"]] == ["https://payments.example"]
    assert "app/web.py" not in ctx.calls_by_file
    assert ctx.files_by_suffix("py") == ("app/api.py", "app/config.py", "app/web.py")
    assert ctx.files_by_suffix(".TS") == ("index.ts",)
    assert ctx.files_by_suffix(".rs") == ()
    assert ctx.source_text("missing.py") is None  # from_scan never invents source text


def test_files_by_suffix_requires_enumerated_coverage():
    # scanned_files=None means coverage was never enumerated: no fabricated files.
    scan = _scan()
    scan.scanned_files = None
    ctx = ReasoningContext.from_scan(scan)
    assert ctx.scanned_files is None
    assert ctx.files_by_suffix("py") == ()


# --- evaluate_all: ordering + isolation --------------------------------------


def test_evaluate_all_orders_by_registry_id():
    registry = RuleRegistry()
    registry.register(_make_rule("beta_rule", [_make_finding("beta_rule")]))
    registry.register(_make_rule("alpha_rule", [_make_finding("alpha_rule", "alpha first")]))
    result = registry.evaluate_all(ReasoningContext())
    assert [f.rule_id for f in result.findings] == ["alpha_rule", "beta_rule"]
    assert result.findings[0].title == "alpha first"
    assert result.errors == []


def test_evaluate_all_isolates_failing_rules():
    registry = RuleRegistry()
    registry.register(_make_rule("alpha_rule", [_make_finding("alpha_rule")]))
    registry.register(_make_rule("boom_rule", error=RuntimeError("kaboom")))
    registry.register(_make_rule("zeta_rule", [_make_finding("zeta_rule")]))
    result = registry.evaluate_all(ReasoningContext())
    # The raising rule is skipped but reported; siblings still contribute.
    assert [f.rule_id for f in result.findings] == ["alpha_rule", "zeta_rule"]
    assert len(result.errors) == 1
    assert result.errors[0].rule_id == "boom_rule"
    assert result.errors[0].error_type == "RuntimeError"
    assert result.errors[0].message == "kaboom"


# --- seed rule end-to-end -----------------------------------------------------


def test_seed_rule_end_to_end():
    rule = REGISTRY.get("demo_weak_default_credentials")
    assert rule is not None
    assert "demo_weak_default_credentials" in REGISTRY
    ctx = ReasoningContext.from_scan(_scan())
    result = REGISTRY.evaluate_all(ctx)
    assert result.errors == []
    seed_findings = [f for f in result.findings if f.rule_id == "demo_weak_default_credentials"]
    assert len(seed_findings) == 1
    finding = seed_findings[0]
    # The finding's rule_id matches the registry entry (attributable, suppressible).
    assert finding.rule_id == rule.meta.id
    assert finding.title == rule.meta.title
    assert finding.severity == rule.meta.severity == "high"
    assert finding.confidence == "high"
    assert finding.locations[0].file == "app/config.py"
    assert finding.locations[0].line == 12
    assert finding.evidence == ["ADMIN_PASSWORD = '...'"]
    assert rule.meta.cwe == "CWE-798"


def test_seed_rule_ignores_env_references_and_unrelated_names():
    scan = _scan()
    scan.secret_hints.append(SecretHint(name="DEFAULT_API_KEY", file="env.py", kind="env_reference"))
    scan.secret_hints.append(SecretHint(name="STRIPE_KEY", file="pay.py", kind="hardcoded"))
    ctx = ReasoningContext.from_scan(scan)
    result = REGISTRY.evaluate_all(ctx)
    seed_findings = [f for f in result.findings if f.rule_id == "demo_weak_default_credentials"]
    assert len(seed_findings) == 1


# --- protocol conformance -----------------------------------------------------


def test_rule_protocol_conformance():
    class Conforming:
        meta = RuleMeta(id="conforming_rule", title="t", severity="low", confidence=0.5, rationale="r")

        def evaluate(self, ctx: ReasoningContext) -> list[Finding]:
            return []

    assert isinstance(Conforming(), Rule)

    class MissingEvaluate:
        meta = RuleMeta(id="missing_evaluate", title="t", severity="low", confidence=0.5, rationale="r")

    assert not isinstance(MissingEvaluate(), Rule)

    class MissingMeta:
        def evaluate(self, ctx: ReasoningContext) -> list[Finding]:
            return []

    assert not isinstance(MissingMeta(), Rule)


def test_confidence_band_mapping():
    assert confidence_band(0.9) == "high"
    assert confidence_band(0.8) == "high"
    assert confidence_band(0.5) == "medium"
    assert confidence_band(0.2) == "low"
