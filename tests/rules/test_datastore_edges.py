"""AR042 datastore/edge rule tests.

Self-contained (no shared conftest/harness): fixtures build a `ScanResult`,
run the rules against `ReasoningContext.from_scan`, and — where the legacy
cascade branch is reachable from context-visible data — assert equivalence
with the old cascade's decisions and verbatim evidence strings
(`threat_model._same_file_datastore`, `_same_file_external`,
`_surface_evidence`, `_build_probable_chains`). The old cascade stays the
active producer; these rules must make the same calls it makes.
"""

from __future__ import annotations

import pytest

from attackmap.model import DatabaseHint, ExternalCall, Route, ScanResult
from attackmap.reasoning import REGISTRY, ReasoningContext
from attackmap.reasoning.analyzer import identify_attack_surfaces
from attackmap.reasoning.rules.datastore_edges import (
    SameFileDatastoreEdgeRule,
    SameFileExternalEdgeRule,
    SameModuleDatastoreEdgeRule,
    SameModuleExternalEdgeRule,
)
from attackmap.reasoning.threat_model import (
    _build_probable_chains,
    _file_module_key,
    _same_file_datastore,
    _same_file_external,
    _surface_evidence,
)

pytestmark = [pytest.mark.unit]

# --- fixtures ----------------------------------------------------------------


def _scan(
    routes: list[Route] | None = None,
    databases: list[DatabaseHint] | None = None,
    external_calls: list[ExternalCall] | None = None,
) -> ScanResult:
    routes = routes or []
    databases = databases or []
    external_calls = external_calls or []
    files = sorted({*(r.file for r in routes), *(d.file for d in databases), *(c.file for c in external_calls)})
    return ScanResult(
        root="C:/tmp/fake-repo",
        routes=routes,
        databases=databases,
        external_calls=external_calls,
        scanned_files=files,
        files_scanned=len(files),
    )


def _ctx(scan: ScanResult) -> ReasoningContext:
    return ReasoningContext.from_scan(scan)


def _ids(findings) -> list[str]:
    return [f.rule_id for f in findings]


# --- registration and metadata ------------------------------------------------


def test_all_four_edge_rules_are_registered() -> None:
    for rule_id in (
        "same_file_datastore_edge",
        "same_file_external_edge",
        "same_module_datastore_edge",
        "same_module_external_edge",
    ):
        rule = REGISTRY.get(rule_id)
        assert rule is not None, rule_id
        assert rule.meta.id == rule_id  # snake_case, stable, suppressible
        assert rule.meta.severity == "low"
        assert "ownership-unknown" in rule.meta.tags


def test_registry_evaluates_edges_without_errors() -> None:
    scan = _scan(
        routes=[Route(path="/orders", method="POST", file="app/orders.py")],
        databases=[DatabaseHint(kind="sqlite", file="app/orders.py")],
    )
    result = REGISTRY.evaluate_all(_ctx(scan))
    assert result.errors == []
    assert "same_file_datastore_edge" in _ids(result.findings)


# --- same-file datastore edge -------------------------------------------------


def test_same_file_datastore_fires_and_matches_cascade_decision() -> None:
    scan = _scan(
        routes=[Route(path="/orders", method="POST", file="app/orders.py", line=3)],
        databases=[DatabaseHint(kind="sqlite", file="app/orders.py", line=8)],
    )
    findings = SameFileDatastoreEdgeRule().evaluate(_ctx(scan))
    assert len(findings) == 1
    finding = findings[0]
    # Equivalence: the old cascade's helper makes the identical call on the
    # same scan, and its evidence line is the string we cite verbatim.
    surface = identify_attack_surfaces(scan)[0]
    assert _same_file_datastore(surface, scan) == ("sqlite", "app/orders.py")
    assert "data store in same file: sqlite (app/orders.py)" in _surface_evidence(surface, scan)
    assert finding.evidence == [
        "POST /orders in app/orders.py",
        "data store in same file: sqlite (app/orders.py)",
    ]
    assert finding.confidence == "medium"
    assert finding.locations[0].file == "app/orders.py"
    assert finding.locations[-1].line == 8
    assert finding.tags[-1] == "observed"


def test_same_file_datastore_is_silent_for_cross_file_and_declared_elsewhere() -> None:
    scan = _scan(
        routes=[Route(path="/api", method="GET", file="app/api.py")],
        databases=[DatabaseHint(kind="postgres", file="app/db.py"), DatabaseHint(kind="mysql", file="docker-compose.yml")],
    )
    assert SameFileDatastoreEdgeRule().evaluate(_ctx(scan)) == []


def test_same_file_declared_datastore_is_tagged_declared_only() -> None:
    scan = _scan(
        routes=[Route(path="/deploy", method="POST", file="infra/serverless.yml")],
        databases=[DatabaseHint(kind="aurora", file="infra/serverless.yml")],
    )
    findings = SameFileDatastoreEdgeRule().evaluate(_ctx(scan))
    assert len(findings) == 1
    assert findings[0].tags[-1] == "declared-only"
    assert "observed" not in findings[0].tags


def test_same_file_datastore_cites_at_most_ten_records_then_summary() -> None:
    file = "app/orders.py"
    scan = _scan(
        routes=[Route(path="/orders", method="POST", file=file)],
        databases=[
            DatabaseHint(kind=f"kind{i}", file=file, line=i + 1) for i in range(11)
        ],
    )
    findings = SameFileDatastoreEdgeRule().evaluate(_ctx(scan))
    assert len(findings) == 1
    evidence = findings[0].evidence
    assert len(evidence) == 12  # route label + 10 records + "+1 more"
    assert evidence[-1] == "+1 more"


# --- same-file external-call edge ---------------------------------------------


def test_same_file_external_fires_and_matches_cascade_decision() -> None:
    scan = _scan(
        routes=[Route(path="/proxy", method="GET", file="app/proxy.py")],
        external_calls=[ExternalCall(target="https://payments.example", file="app/proxy.py", line=12)],
    )
    findings = SameFileExternalEdgeRule().evaluate(_ctx(scan))
    assert len(findings) == 1
    surface = identify_attack_surfaces(scan)[0]
    assert _same_file_external(surface, scan) == ("https://payments.example", "app/proxy.py")
    assert "external call in same file: https://payments.example (app/proxy.py)" in _surface_evidence(surface, scan)
    assert findings[0].evidence == [
        "GET /proxy in app/proxy.py",
        "external call in same file: https://payments.example (app/proxy.py)",
    ]
    assert findings[0].tags[-1] == "observed"
    assert SameFileDatastoreEdgeRule().evaluate(_ctx(scan)) == []


# --- cross-file, same-module datastore edge ------------------------------------


def test_cross_file_same_module_datastore_matches_cascade_branch() -> None:
    scan = _scan(
        routes=[Route(path="/api", method="GET", file="app/api.py")],
        databases=[DatabaseHint(kind="postgres", file="app/db.py", line=4)],
    )
    assert _file_module_key("app/api.py") == _file_module_key("app/db.py")
    findings = SameModuleDatastoreEdgeRule().evaluate(_ctx(scan))
    assert len(findings) == 1
    # Equivalence: the legacy chain builder cites the identical record with
    # the identical evidence line for this route.
    chain = _build_probable_chains(scan)[0]
    assert "database hint in same module: postgres (app/db.py)" in chain.evidence
    assert findings[0].evidence == [
        "GET /api in app/api.py",
        "database hint in same module: postgres (app/db.py)",
    ]
    assert findings[0].confidence == "low"
    assert findings[0].locations[0].file == "app/api.py"
    assert findings[0].locations[-1].line == 4
    # Not a same-file co-location: the same-file rule stays quiet.
    assert SameFileDatastoreEdgeRule().evaluate(_ctx(scan)) == []


def test_module_match_is_first_wins_over_scan_order_like_the_cascade() -> None:
    scan = _scan(
        routes=[Route(path="/api", method="GET", file="app/api.py")],
        databases=[
            DatabaseHint(kind="redis", file="app/cache.py"),
            DatabaseHint(kind="postgres", file="app/db.py"),
        ],
    )
    findings = SameModuleDatastoreEdgeRule().evaluate(_ctx(scan))
    assert len(findings) == 1
    assert findings[0].evidence[-1] == "database hint in same module: redis (app/cache.py)"


def test_declared_config_datastore_in_module_is_tagged_declared_only() -> None:
    scan = _scan(
        routes=[Route(path="/api", method="GET", file="app/api.py")],
        databases=[DatabaseHint(kind="postgres", file="app/docker-compose.yml")],
    )
    findings = SameModuleDatastoreEdgeRule().evaluate(_ctx(scan))
    assert len(findings) == 1
    assert findings[0].tags[-1] == "declared-only"
    assert findings[0].evidence[-1] == "database hint in same module: postgres (app/docker-compose.yml)"


# --- same-module external edge and cascade elif priority -----------------------


def test_same_module_external_fires_when_no_datastore_answers() -> None:
    scan = _scan(
        routes=[Route(path="/api", method="GET", file="app/api.py")],
        external_calls=[ExternalCall(target="https://api.example", file="app/client.py")],
    )
    findings = SameModuleExternalEdgeRule().evaluate(_ctx(scan))
    assert len(findings) == 1
    chain = _build_probable_chains(scan)[0]
    assert "external call in same module: https://api.example (app/client.py)" in chain.evidence
    assert findings[0].evidence == [
        "GET /api in app/api.py",
        "external call in same module: https://api.example (app/client.py)",
    ]
    assert SameModuleDatastoreEdgeRule().evaluate(_ctx(scan)) == []


def test_external_edge_stays_quiet_where_datastore_branch_answers() -> None:
    # The cascade's `elif external_by_module` never runs once a same-module
    # datastore answered; the ported rule pair must keep that priority.
    scan = _scan(
        routes=[Route(path="/api", method="GET", file="app/api.py")],
        databases=[DatabaseHint(kind="postgres", file="app/db.py")],
        external_calls=[ExternalCall(target="https://api.example", file="app/client.py")],
    )
    chain = _build_probable_chains(scan)[0]
    assert any(e.startswith("database hint in same module:") for e in chain.evidence)
    assert not any(e.startswith("external call in same module:") for e in chain.evidence)
    assert len(SameModuleDatastoreEdgeRule().evaluate(_ctx(scan))) == 1
    assert SameModuleExternalEdgeRule().evaluate(_ctx(scan)) == []


def test_external_edge_silent_for_other_module_and_cascade_calls_it_elsewhere() -> None:
    scan = _scan(
        routes=[Route(path="/api", method="GET", file="app/api.py")],
        external_calls=[ExternalCall(target="https://api.example", file="lib/http.py")],
    )
    assert SameModuleExternalEdgeRule().evaluate(_ctx(scan)) == []
    chain = _build_probable_chains(scan)[0]
    assert "external call elsewhere in repo: https://api.example (lib/http.py)" in chain.evidence


# --- declared-only without any co-location: context, never an edge -------------


def test_declared_only_datastore_without_co_location_produces_no_edge() -> None:
    scan = _scan(
        routes=[Route(path="/api", method="GET", file="app/api.py")],
        databases=[DatabaseHint(kind="postgres", file="docker-compose.yml")],
    )
    empty_rules = [
        SameFileDatastoreEdgeRule(),
        SameFileExternalEdgeRule(),
        SameModuleDatastoreEdgeRule(),
        SameModuleExternalEdgeRule(),
    ]
    for rule in empty_rules:
        assert rule.evaluate(_ctx(scan)) == [], rule.meta.id
    # The cascade agrees: no same-file edge, and the record is classified
    # "elsewhere in repo" — its explicitly-not-an-edge tier.
    surface = identify_attack_surfaces(scan)[0]
    assert _same_file_datastore(surface, scan) is None
    assert _same_file_external(surface, scan) is None
    chain = _build_probable_chains(scan)[0]
    assert "database hint elsewhere in repo: postgres (docker-compose.yml)" in chain.evidence


# --- negative ------------------------------------------------------------------


def test_no_records_no_findings() -> None:
    scan = _scan(routes=[Route(path="/health", method="GET", file="app/health.py")])
    for rule in (
        SameFileDatastoreEdgeRule(),
        SameFileExternalEdgeRule(),
        SameModuleDatastoreEdgeRule(),
        SameModuleExternalEdgeRule(),
    ):
        assert rule.evaluate(_ctx(scan)) == [], rule.meta.id


def test_datastore_without_any_route_is_not_an_edge() -> None:
    scan = _scan(databases=[DatabaseHint(kind="sqlite", file="worker/store.py")])
    for rule in (
        SameFileDatastoreEdgeRule(),
        SameFileExternalEdgeRule(),
        SameModuleDatastoreEdgeRule(),
        SameModuleExternalEdgeRule(),
    ):
        assert rule.evaluate(_ctx(scan)) == [], rule.meta.id


# --- low-quality sources are down-ranked like the cascade ----------------------


def test_low_quality_route_sources_are_down_ranked() -> None:
    scan = _scan(
        routes=[
            Route(path="/orders", method="POST", file="tests/test_orders.py"),
            Route(path="/demo", method="POST", file="examples/demo/orders.py"),
        ],
        databases=[
            DatabaseHint(kind="sqlite", file="tests/test_orders.py"),
            DatabaseHint(kind="sqlite", file="examples/demo/orders.py"),
        ],
    )
    for rule in (
        SameFileDatastoreEdgeRule(),
        SameFileExternalEdgeRule(),
        SameModuleDatastoreEdgeRule(),
        SameModuleExternalEdgeRule(),
    ):
        assert rule.evaluate(_ctx(scan)) == [], rule.meta.id
    # The cascade down-ranks identically: no runtime routes, no chains.
    assert _build_probable_chains(scan) == []


def test_low_quality_records_are_not_cited_for_runtime_routes() -> None:
    # A production route whose module also contains a tests/ datastore: the
    # module keys differ ("app" vs "tests"), so nothing fires — and the
    # cascade files the record under "elsewhere in repo" too.
    scan = _scan(
        routes=[Route(path="/api", method="GET", file="app/api.py")],
        databases=[DatabaseHint(kind="sqlite", file="tests/test_store.py")],
    )
    for rule in (
        SameFileDatastoreEdgeRule(),
        SameModuleDatastoreEdgeRule(),
        SameModuleExternalEdgeRule(),
    ):
        assert rule.evaluate(_ctx(scan)) == [], rule.meta.id
    chain = _build_probable_chains(scan)[0]
    assert "database hint elsewhere in repo: sqlite (tests/test_store.py)" in chain.evidence


# --- determinism -----------------------------------------------------------------


def test_findings_are_deterministic_regardless_of_route_input_order() -> None:
    routes = [
        Route(path="/b", method="POST", file="app/beta.py"),
        Route(path="/a", method="GET", file="app/alpha.py"),
    ]
    databases = [DatabaseHint(kind="postgres", file="app/db.py")]
    forward = SameModuleDatastoreEdgeRule().evaluate(_ctx(_scan(routes=routes, databases=databases)))
    backward = SameModuleDatastoreEdgeRule().evaluate(
        _ctx(_scan(routes=list(reversed(routes)), databases=databases))
    )
    assert _ids(forward) == _ids(backward)
    assert [f.evidence for f in forward] == [f.evidence for f in backward]
    # Same-file edges are per route file, sorted, not input-ordered.
    forward_files = SameFileDatastoreEdgeRule().evaluate(
        _ctx(_scan(routes=routes, databases=[DatabaseHint(kind="sqlite", file="app/alpha.py")]))
    )
    assert len(forward_files) == 1
    assert forward_files[0].locations[0].file == "app/alpha.py"
