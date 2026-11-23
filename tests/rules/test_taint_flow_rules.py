"""AR044 taint/flow rule tests: per-sink-kind fixtures plus field-for-field
equivalence against the scan pipeline (``threat_model.generate_findings``).

The registry is the active producer now (owner decision 2026-11-23), so every
positive fixture is checked both ways: the rules must emit findings whose
fields (title, severity, confidence, mitigation, evidence, locations, tags,
ATT&CK techniques, SARIF codeFlows, taxonomy) are exactly what the pipeline
emits for the same chains. The exploitability fusion is deliberately not
ported (it needs full-scan slices outside ``ReasoningContext``), so it is
excluded from the comparison and asserted absent on rule findings.

AR046 unified the emitted rule id: findings carry ``rule_id=meta.id`` (the
kernel contract); the pipeline emits the same stable ids the rules emit, and
the equivalence helpers below key both sides by that stable id.

Self-contained: no conftest, no shared harness — fixtures are constructed
in-code.
"""

from __future__ import annotations

import pytest

from attackmap.model import Finding, Route, ScanResult, TaintChain, TaintFlowStep
from attackmap.reasoning import REGISTRY, ReasoningContext
from attackmap.reasoning.rules.taint_flow import (
    FLOW_SINK_RULES,
    SPECULATIVE_RULES,
    TAINT_SINK_RULES,
)
from attackmap.reasoning.taint import _confidence_for_hops
from attackmap.reasoning.threat_model import generate_findings

pytestmark = [pytest.mark.unit]

# Every taint rule id (AR047): the tests below that assert on the whole
# family's output are focused on all of them.
ALL_TAINT_RULE_IDS = tuple(
    rule.meta.id for rule in (*TAINT_SINK_RULES, *FLOW_SINK_RULES, *SPECULATIVE_RULES)
)

# --- fixtures ----------------------------------------------------------------


def _chain(**over: object) -> TaintChain:
    """A runtime-source taint chain; every field overridable per fixture."""
    fields: dict[str, object] = {
        "route_path": "/search",
        "route_method": "GET",
        "route_file": "app/web.py",
        "sink_kind": "eval",
        "sink_file": "svc/dynamic.py",
        "sink_line": 10,
        "hops": 1,
        "files": ["app/web.py", "svc/dynamic.py"],
        "evidence_text": "eval(expr)",
        "confidence": 0.6,
    }
    fields.update(over)
    return TaintChain(**fields)  # type: ignore[arg-type]


def _flow(*steps: tuple[int, str, str]) -> list[TaintFlowStep]:
    return [
        TaintFlowStep(file="svc/db.py", line=ln, kind=kind, evidence_text=text)
        for ln, kind, text in steps
    ]


def _scan(chains: list[TaintChain]) -> ScanResult:
    routes: list[Route] = []
    seen: set[tuple[str, str, str]] = set()
    for chain in chains:
        key = (chain.route_path, chain.route_method, chain.route_file)
        if key not in seen:
            seen.add(key)
            routes.append(Route(path=chain.route_path, method=chain.route_method, file=chain.route_file))
    return ScanResult(root="C:/tmp/fake-repo", routes=routes, taint_chains=chains)


def _rule_findings(scan: ScanResult) -> dict[str, Finding]:
    """The ported rules' findings keyed by the stable rule id they emit."""
    ctx = ReasoningContext.from_scan(scan)
    out: dict[str, Finding] = {}
    for rule in (*TAINT_SINK_RULES, *FLOW_SINK_RULES, *SPECULATIVE_RULES):
        for finding in rule.evaluate(ctx):
            assert finding.rule_id not in out, f"duplicate rule_id across rules: {finding.rule_id}"
            out[finding.rule_id] = finding
    return out


def _pipeline_taint_findings(scan: ScanResult) -> dict[str, Finding]:
    """The pipeline's taint-family findings keyed by the stable rule id."""
    return {
        finding.rule_id: finding
        for finding in generate_findings(scan)
        if "taint-chain" in finding.tags
    }


def _assert_equivalent(new: Finding, old: Finding, stable_id: str) -> None:
    """Field-for-field equivalence on every ported field. Both sides carry
    the stable ``rule_id`` (the kernel contract ``rule_id == meta.id``); the
    pipeline finding differs only by the shared post-passes (score attach,
    exploitability fusion) that the comparison deliberately excludes."""
    assert new.title == old.title
    assert new.severity == old.severity
    assert new.confidence == old.confidence
    assert new.mitigation == old.mitigation
    assert new.evidence == old.evidence
    assert new.tags == old.tags
    assert [(loc.file, loc.line) for loc in new.locations] == [
        (loc.file, loc.line) for loc in old.locations
    ]
    assert [(t.technique_id, t.name, t.tactic, t.url) for t in new.attack_techniques] == [
        (t.technique_id, t.name, t.tactic, t.url) for t in old.attack_techniques
    ]
    assert [
        [(step.file, step.line, step.kind) for step in flow] for flow in new.code_flows
    ] == [[(step.file, step.line, step.kind) for step in flow] for flow in old.code_flows]
    assert new.taxonomy == old.taxonomy  # identical enrichment (registered ids, AR046)
    assert new.rule_id == stable_id  # kernel contract: rule_id == meta.id


def _assert_matches_legacy(scan: ScanResult) -> None:
    """Every pipeline taint finding has an identical rule finding, and the
    rules emit nothing the pipeline doesn't."""
    pipeline = _pipeline_taint_findings(scan)
    ported = _rule_findings(scan)
    assert set(ported) == set(pipeline), (sorted(ported), sorted(pipeline))
    for rule_id in pipeline:
        _assert_equivalent(ported[rule_id], pipeline[rule_id], rule_id)
    for finding in ported.values():
        # The exploitability fusion (score_exploitability + attack surfaces)
        # needs full-scan slices outside ReasoningContext — deliberately not
        # ported (see module docstring); the wiring pass keeps applying it.
        assert finding.exploitability is None


# --- fixtures per sink kind (todo card step 3) --------------------------------


@pytest.mark.rule("taint_flow_sql_execute")
def test_sql_sink_traced_flow_matches_legacy():
    # SQL reach alone is not a finding: the chain needs a traced
    # request-derived source flowing into the query argument (#239).
    chain = _chain(
        sink_kind="sql_execute",
        sink_file="svc/db.py",
        sink_line=31,
        evidence_text="cursor.execute(query)",
        confidence=0.75,
        source_kind="query",
        source_line=30,
        flow=_flow((30, "source", 'query = request.args["q"]'), (31, "sink", "cursor.execute(query)")),
    )
    scan = _scan([chain])
    findings = _rule_findings(scan)
    assert list(findings) == ["taint_flow_sql_execute"]
    finding = findings["taint_flow_sql_execute"]
    assert finding.confidence == "high"  # chain confidence 0.75 clears the flow band
    assert finding.locations[0].file == "svc/db.py"
    assert any(step.kind == "source" for flow in finding.code_flows for step in flow)
    _assert_matches_legacy(scan)


@pytest.mark.rule("taint_sink_subprocess_shell")
def test_command_sink_finding_matches_legacy():
    chain = _chain(
        route_path="/run",
        route_method="POST",
        route_file="app/admin.py",
        sink_kind="subprocess_shell",
        sink_file="svc/runner.py",
        sink_line=12,
        hops=2,
        files=["app/admin.py", "svc/util.py", "svc/runner.py"],
        evidence_text="subprocess.run(cmd, shell=True)",
        confidence=0.5,
    )
    scan = _scan([chain])
    findings = _rule_findings(scan)
    assert list(findings) == ["taint_sink_subprocess_shell"]
    finding = findings["taint_sink_subprocess_shell"]
    assert finding.severity == "high"
    assert finding.confidence == "medium"  # reach band, preserved from the legacy block
    assert finding.locations[0].line == 12
    assert finding.locations[-1].file == "app/admin.py"
    _assert_matches_legacy(scan)


@pytest.mark.rule("taint_sink_ssti")
def test_template_sink_finding_matches_legacy():
    chain = _chain(
        route_path="/render",
        route_method="POST",
        route_file="app/pages.py",
        sink_kind="ssti",
        sink_file="svc/render.py",
        sink_line=8,
        evidence_text="Template(source).render()",
        confidence=0.6,
    )
    scan = _scan([chain])
    findings = _rule_findings(scan)
    assert list(findings) == ["taint_sink_ssti"]
    finding = findings["taint_sink_ssti"]
    assert finding.severity == "high"
    _assert_matches_legacy(scan)


@pytest.mark.rule("taint_flow_path_traversal")
def test_path_sink_finding_matches_legacy():
    # `dynamic_open` is the schema alias of `path_traversal` (#200): both raw
    # kinds aggregate into one path-traversal finding. The traced dynamic
    # open needs its source_kind; the request-gated send_file-style
    # path_traversal sink counts on reach alone (legacy `confirmed` check).
    traced_open = _chain(
        route_path="/files",
        route_method="GET",
        route_file="app/files.py",
        sink_kind="dynamic_open",
        sink_file="svc/files.py",
        sink_line=20,
        evidence_text="open(user_path)",
        confidence=0.8,
        source_kind="path_param",
        source_line=19,
        flow=_flow(
            (19, "source", "user_path = request.view_args['name']"), (20, "sink", "open(user_path)")
        ),
    )
    gated_send_file = _chain(
        route_path="/download",
        route_method="GET",
        route_file="app/downloads.py",
        sink_kind="path_traversal",
        sink_file="svc/downloads.py",
        sink_line=5,
        evidence_text="send_file(name)",
        confidence=0.65,
    )
    scan = _scan([traced_open, gated_send_file])
    findings = _rule_findings(scan)
    assert list(findings) == ["taint_flow_path_traversal"]
    finding = findings["taint_flow_path_traversal"]
    assert finding.confidence == "high"  # any chain >= 0.75 lifts the band
    # Only the traced chain contributes a `flow:` evidence line; the gated
    # send_file-style chain counts on reach alone.
    assert sum(line.startswith("flow:") for line in finding.evidence) == 1
    _assert_matches_legacy(scan)


@pytest.mark.rule("taint_flow_sql_execute")
def test_untraced_sql_chain_raises_no_finding():
    # The negative half of the SQL fixture: reachability without a traced
    # flow is over-linking for the trace-gated kinds, on both sides.
    chain = _chain(sink_kind="sql_execute", confidence=0.65)
    scan = _scan([chain])
    assert _rule_findings(scan) == {}
    assert _pipeline_taint_findings(scan) == {}


# --- negative and source-quality cases ----------------------------------------


@pytest.mark.rule(*ALL_TAINT_RULE_IDS)
def test_no_chains_produce_no_findings():
    assert _rule_findings(_scan([])) == {}


@pytest.mark.rule(*ALL_TAINT_RULE_IDS)
def test_low_quality_sources_are_down_ranked():
    # The legacy cascade never surfaces chains rooted under tests/,
    # fixtures/, examples/ — its scan-time index skips them — so the rules
    # skip such chains too (same policy segment list, see module docstring).
    chains = [
        _chain(route_file="tests/test_search.py"),  # low-quality route root
        _chain(route_file="fixtures/load.py", sink_file="fixtures/svc.py"),  # both ends
        _chain(sink_file="examples/demo/dynamic.py"),  # low-quality sink root
    ]
    scan = _scan(chains)
    assert _rule_findings(scan) == {}
    # Control: the same chains rooted in runtime sources do produce findings.
    assert set(_rule_findings(_scan([_chain(route_file="src/search.py")]))) == {"taint_sink_eval"}


@pytest.mark.rule(*ALL_TAINT_RULE_IDS)
def test_sanitized_chain_is_never_raised():
    # #137: a neutralized path isn't a probable exploit — evidence stays in
    # the scan, no rule raises (legacy `sanitized` gate).
    chain = _chain(sanitized=True, sanitizer_evidence="markupsafe.escape")
    scan = _scan([chain])
    assert _rule_findings(scan) == {}
    assert _pipeline_taint_findings(scan) == {}
    assert ReasoningContext.from_scan(scan).taint_chains == (chain,)  # kept as evidence


# --- speculative recall chains (#148a) -----------------------------------------


@pytest.mark.rule(*ALL_TAINT_RULE_IDS)
def test_speculative_chain_only_produces_the_speculative_finding():
    chain = _chain(sink_kind="exec", speculative=True, confidence=0.3)
    scan = _scan([chain])
    findings = _rule_findings(scan)
    assert list(findings) == ["taint_speculative_exec"]
    finding = findings["taint_speculative_exec"]
    assert finding.severity == "low"
    assert finding.confidence == "low"
    assert finding.tags == ["taint-chain", "speculative", "recall"]
    assert finding.evidence[0].startswith("SPECULATIVE (recall mode):")
    _assert_matches_legacy(scan)


@pytest.mark.rule(*ALL_TAINT_RULE_IDS)
def test_speculative_flow_kind_chain_produces_nothing():
    # Legacy bucketing: a speculative flow-kind chain hits the flow gate's
    # `continue` before the speculative bucket — no finding at all.
    chain = _chain(sink_kind="sql_execute", speculative=True, source_kind="query")
    scan = _scan([chain])
    assert _rule_findings(scan) == {}
    assert _pipeline_taint_findings(scan) == {}


# --- aggregation ----------------------------------------------------------------


@pytest.mark.rule(*ALL_TAINT_RULE_IDS)
def test_multiple_routes_aggregate_into_one_finding_per_kind():
    farther = _chain(
        route_path="/api/run",
        route_method="POST",
        route_file="app/api.py",
        sink_file="svc/other.py",
        sink_line=99,
        hops=2,
        files=["app/api.py", "svc/mid.py", "svc/other.py"],
        confidence=0.5,
    )
    closest = _chain(sink_file="svc/dynamic.py", sink_line=10, hops=0, files=["app/web.py"], confidence=0.65)
    scan = _scan([farther, closest])  # list order != top-chain order
    finding = _rule_findings(scan)["taint_sink_eval"]
    # Top chain = fewest hops (tie broken by confidence), overflow line, then
    # the traced-flow evidence lines (none: reach-only chains).
    assert "import path: app/web.py (0 hop(s))" in finding.evidence
    assert "+1 more route(s) reach a code eval sink" in finding.evidence
    assert [(loc.file, loc.line) for loc in finding.locations] == [
        ("svc/other.py", 99),
        ("svc/dynamic.py", 10),
        ("app/api.py", None),
        ("app/web.py", None),
    ]
    _assert_matches_legacy(scan)


# --- hop-count / confidence equivalence (todo card step 2) ----------------------


@pytest.mark.rule("taint_flow_sql_execute")
@pytest.mark.parametrize("hops", [0, 1, 2, 3, 4])
def test_hop_confidence_bands_match_the_legacy_mapping(hops: int):
    # The unchanged walk derives chain confidence from the hop count via
    # `_confidence_for_hops`, lifting a traced flow by +0.15 (capped 0.9) —
    # replicated verbatim here so the rule receives exactly the confidence
    # the analyzer would hand it. The flow family's band is then "high" iff
    # any chain confidence >= 0.75 (legacy literal), so the hop mapping
    # surfaces: hops <= 1 -> high, deeper hops taper back to medium.
    base = _confidence_for_hops(hops)
    traced_confidence = round(min(0.9, base + 0.15), 2)
    chain = _chain(
        sink_kind="sql_execute",
        hops=hops,
        files=["app/web.py", *["svc/mid.py"] * hops, "svc/db.py"] if hops else ["app/web.py"],
        confidence=traced_confidence,
        source_kind="query",
        source_line=30,
        flow=_flow((30, "source", "query"), (31, "sink", "cursor.execute(query)")),
    )
    scan = _scan([chain])
    finding = _rule_findings(scan)["taint_flow_sql_execute"]
    expected_band = "high" if traced_confidence >= 0.75 else "medium"
    assert finding.confidence == expected_band
    assert finding.confidence == _pipeline_taint_findings(scan)["taint_flow_sql_execute"].confidence
    # Pure reach confidence (no traced-flow lift) never clears the HIGH bar
    # on either side — the mapping's taper is preserved end-to-end.
    pure = _chain(sink_kind="sql_execute", hops=hops, confidence=base, source_kind="query")
    pure_scan = _scan([pure])
    pure_finding = _rule_findings(pure_scan)["taint_flow_sql_execute"]
    assert pure_finding.confidence == "medium"
    assert pure_finding.confidence == _pipeline_taint_findings(pure_scan)["taint_flow_sql_execute"].confidence


def test_confidence_for_hops_mapping_is_unchanged():
    # The port consumes the mapping; it must not have drifted.
    assert _confidence_for_hops(0) == 0.65
    assert _confidence_for_hops(1) == 0.60
    assert _confidence_for_hops(2) == 0.50
    assert _confidence_for_hops(9) == 0.50


# --- registry contract -----------------------------------------------------------


def test_all_taint_rules_are_registered_with_stable_ids():
    rules = (*TAINT_SINK_RULES, *FLOW_SINK_RULES, *SPECULATIVE_RULES)
    ids = [rule.meta.id for rule in rules]
    assert len(set(ids)) == len(ids)  # no duplicates within the family set
    for rule_id in ids:
        assert REGISTRY.get(rule_id) is not None  # registered
        assert rule_id.isidentifier()  # ^[a-z][a-z0-9_]*$ (RuleMeta enforces too)
    # Family prefix mapping, as recorded in the module docstring:
    assert all(rule.meta.id.startswith("taint_sink_") for rule in TAINT_SINK_RULES)
    assert all(rule.meta.id.startswith("taint_flow_") for rule in FLOW_SINK_RULES)
    assert all(rule.meta.id.startswith("taint_speculative_") for rule in SPECULATIVE_RULES)
    # Every meta carries the AC-201 identity fields with real content.
    for rule in rules:
        assert rule.meta.title
        assert rule.meta.rationale
        assert rule.meta.cwe.startswith("CWE-")
        assert 0.0 <= rule.meta.confidence <= 1.0


@pytest.mark.rule(*ALL_TAINT_RULE_IDS)
def test_registry_evaluate_all_matches_per_rule_evaluation():
    chains = [
        _chain(sink_kind="subprocess_shell", confidence=0.6),
        _chain(
            route_path="/files",
            route_method="GET",
            route_file="app/files.py",
            sink_kind="dynamic_open",
            sink_file="svc/files.py",
            confidence=0.8,
            source_kind="path_param",
        ),
        _chain(
            route_path="/admin",
            route_method="POST",
            route_file="app/admin.py",
            sink_kind="eval",
            speculative=True,
        ),
    ]
    scan = _scan(chains)
    result = REGISTRY.evaluate_all(ReasoningContext.from_scan(scan))
    # Rule isolation is the registry's contract; this family must contribute
    # no errors (other families' errors, if any, are their own tests' scope).
    assert not [error for error in result.errors if error.rule_id.startswith("taint_")]
    taint_ids = (
        "taint_flow_sql_execute",
        "taint_flow_path_traversal",
        "taint_speculative_eval",
        "taint_sink_subprocess_shell",
        "taint_sink_eval",
    )
    by_id = {
        finding.rule_id: finding
        for finding in result.findings
        if finding.rule_id in taint_ids or finding.rule_id.startswith("taint_speculative_")
    }
    assert by_id == _rule_findings(scan)
