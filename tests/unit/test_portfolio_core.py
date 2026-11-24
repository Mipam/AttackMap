"""Unit tests for portfolio mode (AR081): repos.yaml loading, cross-repo
graph semantics, hotspot ranking and byte-stable artifact emission."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from attackmap.extraction.contracts import ContractLink
from attackmap.models import (
    DatabaseHint,
    DependencyHint,
    ExternalCall,
    Finding,
    FindingLocation,
    ScanResult,
    SecretHint,
)
from attackmap.orchestration.fleet import FleetRepoResult, FleetScan
from attackmap.orchestration.portfolio import (
    PortfolioError,
    _normalize_host,
    build_portfolio_graph,
    load_repos_yaml,
    portfolio_payload,
    rank_portfolio_hotspots,
    render_portfolio_summary,
    write_portfolio_artifacts,
)

FIXTURE_PORTFOLIO = Path(__file__).resolve().parents[1] / "fixtures" / "portfolio"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _scan(root: str, *, calls=(), databases=(), dependencies=(), secrets=()) -> ScanResult:
    scan = ScanResult(root=root)
    scan.external_calls = [ExternalCall(target=t, file=f, line=ln) for t, f, ln in calls]
    scan.databases = [DatabaseHint(kind=k, file=f, line=ln) for k, f, ln in databases]
    scan.dependencies = [
        DependencyHint(name=n, version=v, ecosystem=e, file=f, line=ln)
        for n, v, e, f, ln in dependencies
    ]
    scan.secret_hints = [SecretHint(name=n, file=f, line=ln) for n, f, ln in secrets]
    return scan


def _finding(title: str, severity: str, confidence: str, file: str, line: int) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        confidence=confidence,
        mitigation="fix it",
        locations=[FindingLocation(file=file, line=line)],
    )


def _fleet() -> FleetScan:
    """Three repos: shared host (a,b), shared db kind (b,c), shared dependency
    (a,b), shared secret (a,c); repo-c also has unique signals."""
    fleet = FleetScan()
    fleet.results = [
        FleetRepoResult(
            repo_id="repo-a",
            root="/repos/a",
            report_dir="/out/a",
            scan=_scan(
                "/repos/a",
                calls=[("https://api.example.com/v1", "a/client.py", 3)],
                databases=[("sqlite", "a/db.py", 2)],
                dependencies=[("requests", "2.31.0", "pypi", "a/requirements.txt", 1)],
                secrets=[("SHARED_TOKEN", "a/settings.py", 5)],
            ),
            findings=[_finding("a high", "high", "high", "a/app.py", 9)],
        ),
        FleetRepoResult(
            repo_id="repo-b",
            root="/repos/b",
            report_dir="/out/b",
            scan=_scan(
                "/repos/b",
                calls=[("http://user@api.example.com:8080/v2", "b/client.py", 7)],
                databases=[("postgresql", "b/db.py", 4)],
                dependencies=[
                    ("requests", "2.31.0", "pypi", "b/requirements.txt", 1),
                    ("fastapi", "0.110.0", "pypi", "b/requirements.txt", 2),
                ],
            ),
            findings=[_finding("b medium", "medium", "high", "b/app.py", 4)],
        ),
        FleetRepoResult(
            repo_id="repo-c",
            root="/repos/c",
            report_dir="/out/c",
            scan=_scan(
                "/repos/c",
                calls=[("https://metrics.internal/api", "c/main.py", 11)],
                databases=[("postgresql", "c/db.py", 1), ("redis", "c/cache.py", 2)],
                dependencies=[("httpx", "0.27.0", "pypi", "c/requirements.txt", 1)],
                secrets=[("SHARED_TOKEN", "c/settings.py", 3)],
            ),
            findings=[
                _finding("c high low-conf", "high", "low", "c/main.py", 8),
                _finding("c high low-conf", "high", "low", "c/main.py", 8),  # exact duplicate
            ],
        ),
    ]
    fleet.links = [
        ContractLink(
            client_repo="repo-a", server_repo="repo-b",
            client_target="https://b.internal/items", client_file="a/client.py", client_line=3,
            client_method="GET", destination="b.internal",
            server_route_path="/items", server_file="b/app.py", server_line=1,
            method="GET", path_template="items", resolution="observed",
        ),
        ContractLink(
            client_repo="repo-c", server_repo="repo-a",
            client_target="https://a.internal/orders", client_file="c/main.py", client_line=2,
            client_method="POST", destination="a.internal",
            server_route_path="/orders", server_file="a/app.py", server_line=12,
            method="POST", path_template="orders", resolution="candidate",
        ),
    ]
    return fleet


# ---------------------------------------------------------------------------
# repos.yaml loading
# ---------------------------------------------------------------------------

def test_load_repos_yaml_fixture(tmp_path: Path) -> None:
    repos = load_repos_yaml(FIXTURE_PORTFOLIO / "repos.yaml")
    assert [r.label for r in repos] == ["catalog", "billing", None]
    assert all(r.path.is_dir() for r in repos)
    assert repos[0].path.name == "catalog"


def test_load_repos_yaml_string_shorthand_and_relative_paths(tmp_path: Path) -> None:
    (tmp_path / "r1").mkdir()
    config = tmp_path / "repos.yaml"
    config.write_text("- path: r1\n- .\n", encoding="utf-8")
    repos = load_repos_yaml(config)
    assert [r.path for r in repos] == [(tmp_path / "r1").resolve(), tmp_path.resolve()]
    assert all(r.label is None for r in repos)


def test_load_repos_yaml_rejects_empty_and_bad_shapes(tmp_path: Path) -> None:
    bad = tmp_path / "repos.yaml"
    for text in ("", "repositories: []\n", "repositories:\n  - 42\n", "repositories: nope\n"):
        bad.write_text(text, encoding="utf-8")
        with pytest.raises(PortfolioError):
            load_repos_yaml(bad)
    with pytest.raises(PortfolioError):
        load_repos_yaml(tmp_path / "missing.yaml")


def test_load_repos_yaml_rejects_duplicate_labels_and_paths(tmp_path: Path) -> None:
    (tmp_path / "r1").mkdir()
    config = tmp_path / "repos.yaml"
    config.write_text(
        "repositories:\n  - path: r1\n    label: same\n  - path: r1\n    label: other\n",
        encoding="utf-8",
    )
    with pytest.raises(PortfolioError, match="same repository path"):
        load_repos_yaml(config)
    config.write_text(
        "repositories:\n  - path: r1\n    label: same\n  - path: .\n    label: same\n",
        encoding="utf-8",
    )
    with pytest.raises(PortfolioError, match="duplicate label"):
        load_repos_yaml(config)


# ---------------------------------------------------------------------------
# host normalization
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("target", "host"),
    [
        ("https://api.example.com/v1/items", "api.example.com"),
        ("http://user@api.example.com:8080/v2", "api.example.com"),
        ("api.example.com/v1", "api.example.com"),
        ("API.EXAMPLE.COM/v1", "api.example.com"),
        ("queue://celery/default", "celery"),
        ("", ""),
    ],
)
def test_normalize_host(target: str, host: str) -> None:
    assert _normalize_host(target) == host


# ---------------------------------------------------------------------------
# cross-repo graph
# ---------------------------------------------------------------------------

def test_graph_nodes_and_shared_only_connectors() -> None:
    graph = build_portfolio_graph(_fleet())
    by_id = {node["id"]: node for node in graph["nodes"]}
    assert {node["kind"] for node in graph["nodes"]} == {
        "repo", "external_host", "database", "dependency", "secret_marker",
    }
    assert sorted(by_id) == [
        "database:postgresql",
        "dependency:pypi:requests",
        "external_host:api.example.com",
        "repo:repo-a",
        "repo:repo-b",
        "repo:repo-c",
        "secret:SHARED_TOKEN",
    ]
    # sqlite / redis / fastapi / httpx / metrics.internal are single-repo: no node.
    for absent in ("database:sqlite", "database:redis", "dependency:pypi:fastapi",
                   "dependency:pypi:httpx", "external_host:metrics.internal"):
        assert absent not in by_id
    assert by_id["external_host:api.example.com"]["shared_by"] == ["repo-a", "repo-b"]
    # Repo nodes carry their analyzed path; connector nodes carry the value label.
    assert by_id["repo:repo-c"]["path"] == "/repos/c"
    assert by_id["secret:SHARED_TOKEN"]["label"] == "SHARED_TOKEN"


def test_graph_edges_grounded_and_observed() -> None:
    graph = build_portfolio_graph(_fleet())
    edges = {(e["kind"], e["source"], e["target"]): e for e in graph["edges"]}
    host_edge = edges[("calls_external_host", "repo:repo-b", "external_host:api.example.com")]
    assert host_edge["basis"] == "observed"
    assert host_edge["evidence"] == [{"repo": "repo-b", "file": "b/client.py", "line": 7}]
    # Scheme/credentials/port variants of the same host share one connector.
    assert ("calls_external_host", "repo:repo-a", "external_host:api.example.com") in edges
    assert ("uses_database", "repo:repo-c", "database:postgresql") in edges
    assert ("declares_dependency", "repo:repo-a", "dependency:pypi:requests") in edges
    assert ("references_secret", "repo:repo-c", "secret:SHARED_TOKEN") in edges
    # Service links: observed vs candidate (inferred) distinction preserved.
    observed = edges[("service_link", "repo:repo-a", "repo:repo-b")]
    assert observed["basis"] == "observed" and observed["resolution"] == "observed"
    candidate = edges[("service_link", "repo:repo-c", "repo:repo-a")]
    assert candidate["basis"] == "inferred" and candidate["resolution"] == "candidate"
    # Every edge cites both endpoint repos in its evidence.
    for edge in graph["edges"]:
        ev_repos = {site["repo"] for site in edge["evidence"]}
        assert ev_repos, edge


def test_graph_is_deterministic() -> None:
    assert build_portfolio_graph(_fleet()) == build_portfolio_graph(_fleet())


def test_graph_empty_fleet_has_repo_nodes_only() -> None:
    fleet = FleetScan()
    fleet.results = [FleetRepoResult(repo_id="solo", root="/r", report_dir="/o",
                                     scan=_scan("/r"), findings=[])]
    graph = build_portfolio_graph(fleet)
    assert graph["nodes"] == [{"id": "repo:solo", "kind": "repo", "label": "solo", "path": "/r"}]
    assert graph["edges"] == []


# ---------------------------------------------------------------------------
# hotspots
# ---------------------------------------------------------------------------

def test_hotspots_cross_repo_bonus_and_dedupe() -> None:
    fleet = _fleet()
    graph = build_portfolio_graph(fleet)
    hotspots = rank_portfolio_hotspots(fleet, graph)
    titles = [h["title"] for h in hotspots]
    # Exact duplicate finding inside one repo collapses; repo-c keeps 1 entry.
    assert titles.count("c high low-conf") == 1
    # Seam degrees: repo-a = 5 (host, dependency, secret, observed link a→b,
    # candidate link c→a), repo-b = 4 (host, database, dependency, link a→b),
    # repo-c = 3 (database, secret, candidate link c→a). The bonus is a
    # tie-adjacent exposure signal, not an override of severity: repo-a's
    # high/high (100 + 20) still leads; repo-b's medium/high (75 + 16) sits
    # above repo-c's high/low (50 + 12).
    assert hotspots[0]["repo"] == "repo-a"
    assert hotspots[0]["portfolio_score"] == hotspots[0]["score"] + 4 * hotspots[0]["cross_repo_degree"]
    by_key = {(h["repo"], h["title"]): h for h in hotspots}
    assert by_key[("repo-a", "a high")]["cross_repo_degree"] == 5
    assert by_key[("repo-b", "b medium")]["cross_repo_degree"] == 4
    assert by_key[("repo-c", "c high low-conf")]["cross_repo_degree"] == 3
    # Ranks are 1-based and dense after sorting.
    assert [h["rank"] for h in hotspots] == list(range(1, len(hotspots) + 1))
    for hotspot in hotspots:
        assert {"repo", "finding_id", "title", "severity", "confidence", "score",
                "cross_repo_degree", "portfolio_score", "locations", "rank"} <= set(hotspot)
        assert hotspot["locations"][0]["file"]


def test_hotspots_limit_is_respected() -> None:
    fleet = _fleet()
    for result in fleet.results:
        result.findings = [
            _finding(f"f{i}", "medium", "medium", "f.py", i + 1) for i in range(10)
        ]
    graph = build_portfolio_graph(fleet)
    assert len(rank_portfolio_hotspots(fleet, graph, limit=5)) == 5


# ---------------------------------------------------------------------------
# payload + artifacts
# ---------------------------------------------------------------------------

def test_payload_is_byte_stable() -> None:
    first = json.dumps(portfolio_payload(_fleet()), indent=2, sort_keys=True)
    second = json.dumps(portfolio_payload(_fleet()), indent=2, sort_keys=True)
    assert first == second
    payload = json.loads(first)
    assert payload["schema_version"] == 1
    assert payload["summary"] == {
        "repositories": 3, "failed": 0,
        "graph_nodes": len(payload["graph"]["nodes"]),
        "graph_edges": len(payload["graph"]["edges"]),
        "hotspots": len(payload["hotspots"]),
    }
    assert {repo["label"] for repo in payload["repositories"]} == {"repo-a", "repo-b", "repo-c"}


def test_payload_applies_labels() -> None:
    payload = portfolio_payload(_fleet(), labels={"repo-a": "catalog"})
    labels = {repo["repo_id"]: repo["label"] for repo in payload["repositories"]}
    assert labels == {"repo-a": "catalog", "repo-b": "repo-b", "repo-c": "repo-c"}


def test_write_artifacts_format_matrix(tmp_path: Path) -> None:
    payload = portfolio_payload(_fleet())
    written = write_portfolio_artifacts(tmp_path, payload, output_format="json")
    assert set(written) == {"portfolio.json"}
    assert not (tmp_path / "portfolio-summary.md").exists()
    parsed = json.loads((tmp_path / "portfolio.json").read_text(encoding="utf-8"))
    assert set(parsed["graph"]) == {"nodes", "edges"}
    assert parsed["hotspots"]

    written = write_portfolio_artifacts(tmp_path, payload, output_format="all")
    assert set(written) == {"portfolio.json", "portfolio-summary.md"}
    md = (tmp_path / "portfolio-summary.md").read_text(encoding="utf-8")
    assert "Cross-repo graph" in md and "Ranked hotspots" in md

    with pytest.raises(PortfolioError):
        write_portfolio_artifacts(tmp_path, payload, output_format="bogus")


def test_render_summary_handles_empty_graph() -> None:
    fleet = FleetScan()
    fleet.results = [FleetRepoResult(repo_id="solo", root="/r", report_dir="/o",
                                     scan=_scan("/r"), findings=[])]
    md = render_portfolio_summary(portfolio_payload(fleet))
    assert "No shared signals detected" in md
    assert "No findings" in md
