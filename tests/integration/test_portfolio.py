"""AC-402 integration verify: ``attackmap portfolio analyze repos.yaml`` on a
3-repo fixture emits a portfolio generation whose portfolio.json carries
``graph.nodes``, ``graph.edges`` and ranked ``hotspots``.

Runs the real CLI entry point as a subprocess (``python -m attackmap``), the
same argv shape an operator would use.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "portfolio"


def _run_portfolio(tmp_path: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    output = tmp_path / "portfolio-out"
    return subprocess.run(
        [sys.executable, "-m", "attackmap", "portfolio", "analyze",
         str(FIXTURE_DIR / "repos.yaml"), "--output", str(output), *extra],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
    )


def test_portfolio_analyze_three_repo_fixture(tmp_path: Path) -> None:
    """AC-402: portfolio.json exists with graph.nodes, graph.edges, hotspots."""
    result = _run_portfolio(tmp_path)
    assert result.returncode == 0, result.stderr[-2000:]
    portfolio_path = tmp_path / "portfolio-out" / "portfolio.json"
    assert portfolio_path.is_file(), result.stdout[-2000:]
    payload = json.loads(portfolio_path.read_text(encoding="utf-8"))

    # --- AC-402 assertions ------------------------------------------------
    assert isinstance(payload["graph"]["nodes"], list) and payload["graph"]["nodes"]
    assert isinstance(payload["graph"]["edges"], list) and payload["graph"]["edges"]
    assert isinstance(payload["hotspots"], list) and payload["hotspots"]

    # --- graph semantics on the fixture ------------------------------------
    node_ids = {node["id"] for node in payload["graph"]["nodes"]}
    assert {"repo:catalog", "repo:billing", "repo:notifier"} <= node_ids
    # Shared seams the fixture was built to exhibit:
    assert "external_host:api.example.com" in node_ids          # catalog + billing
    assert "dependency:pypi:requests" in node_ids               # catalog + billing
    assert "database:postgresql" in node_ids                    # billing + notifier
    assert "secret:SHARED_SERVICE_TOKEN" in node_ids            # all three
    # Unique signals stay out of the cross-repo graph:
    assert "external_host:metrics.internal" not in node_ids
    assert "database:sqlite" not in node_ids

    edges = {(e["kind"], e["source"], e["target"]): e for e in payload["graph"]["edges"]}
    shared_host = edges[("calls_external_host", "repo:catalog", "external_host:api.example.com")]
    assert shared_host["basis"] == "observed"
    assert shared_host["evidence"] == [
        {"repo": "catalog", "file": "app.py", "line": shared_host["evidence"][0]["line"]},
    ]
    assert isinstance(shared_host["evidence"][0]["line"], int)
    assert ("declares_dependency", "repo:billing", "dependency:pypi:requests") in edges
    assert ("uses_database", "repo:notifier", "database:postgresql") in edges
    assert ("references_secret", "repo:catalog", "secret:SHARED_SERVICE_TOKEN") in edges
    for edge in payload["graph"]["edges"]:
        assert edge["basis"] in {"observed", "inferred"}
        assert edge["evidence"]

    # --- ranked hotspots -----------------------------------------------------
    assert len(payload["hotspots"]) >= 3  # every fixture repo has ≥1 finding
    for rank, hotspot in enumerate(payload["hotspots"], start=1):
        assert hotspot["rank"] == rank
        assert hotspot["repo"] in {"catalog", "billing", "notifier"}
        assert hotspot["portfolio_score"] >= hotspot["score"]
    ranks = [hotspot["portfolio_score"] for hotspot in payload["hotspots"]]
    assert ranks == sorted(ranks, reverse=True)

    # --- per-repo generations are unchanged/normal ---------------------------
    for repo_id in ("catalog", "billing", "notifier"):
        repo_dir = tmp_path / "portfolio-out" / repo_id
        reports = list(repo_dir.glob("*/attackmap-report.json"))
        assert reports, f"no per-repo generation for {repo_id}"
    assert (tmp_path / "portfolio-out" / "portfolio-summary.md").is_file()


def test_portfolio_json_is_byte_stable(tmp_path: Path) -> None:
    """Identical inputs produce byte-identical portfolio.json (no run ids,
    timestamps or absolute generation paths inside the payload)."""
    first = _run_portfolio(tmp_path / "run1")
    second = _run_portfolio(tmp_path / "run2")
    assert first.returncode == 0 and second.returncode == 0
    one = (tmp_path / "run1" / "portfolio-out" / "portfolio.json").read_bytes()
    two = (tmp_path / "run2" / "portfolio-out" / "portfolio.json").read_bytes()
    assert one == two


def test_portfolio_analyze_json_format_skips_markdown(tmp_path: Path) -> None:
    result = _run_portfolio(tmp_path, "--format", "json")
    assert result.returncode == 0, result.stderr[-2000:]
    assert (tmp_path / "portfolio-out" / "portfolio.json").is_file()
    assert not (tmp_path / "portfolio-out" / "portfolio-summary.md").exists()


def test_portfolio_analyze_rejects_bad_config(tmp_path: Path) -> None:
    bad = tmp_path / "repos.yaml"
    bad.write_text("repositories: []\n", encoding="utf-8")
    output = tmp_path / "out"
    result = subprocess.run(
        [sys.executable, "-m", "attackmap", "portfolio", "analyze",
         str(bad), "--output", str(output)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    assert result.returncode != 0
    assert not (output / "portfolio.json").exists()
