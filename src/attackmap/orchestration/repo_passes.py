"""Whole-repo analysis passes over a merged scan result (AR030).

Lives in orchestration (AR031 layer map): these passes sequence the
reasoning-layer analyzers (taint, authz, anomalies) and the ai-band
dependency passes over an already-extracted result. ``extraction.scanner``
keeps per-file signal extraction only, so extraction no longer imports
reasoning or the output/ai band.

``attackmap.orchestration.analyzers`` re-exports ``run_repo_passes`` and
``scan_repo`` so the historical import sites and monkeypatch targets keep
working.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from attackmap.ai.sbom import analyze_sbom
from attackmap.ai.supply_chain import scan_supply_chain
from attackmap.extraction.run_budget import active_budget
from attackmap.extraction.scanner import scan_files
from attackmap.extraction.workflow_scanner import scan_workflows
from attackmap.foundation.errors import BudgetExpired
from attackmap.reasoning.anomalies import find_anomalies
from attackmap.reasoning.authz import analyze_authz
from attackmap.reasoning.taint import DEFAULT_RECALL, analyze_taint, recall_config

if TYPE_CHECKING:
    from attackmap.extraction.index import RepoIndex
    from attackmap.extraction.progress import ScanProgress
    from attackmap.sdk.models import ScanResult


def scan_repo(
    root: str | Path,
    suffixes: set[str] | None = None,
    progress: ScanProgress | None = None,
    recall: bool = False,
) -> ScanResult:
    """Per-file signal extraction plus the whole-repo passes, for callers that
    scan a repo directly. ``analyze_repository`` instead runs ``scan_files``
    per analyzer and ``run_repo_passes`` once on the merged result (#219)."""
    result = scan_files(root, suffixes=suffixes, progress=progress)
    run_repo_passes(result, Path(result.root), progress=progress, recall=recall)
    if progress is not None:
        progress.done()
    return result


def run_repo_passes(
    result: ScanResult,
    root_path: Path,
    progress: ScanProgress | None = None,
    recall: bool = False,
    index: RepoIndex | None = None,
) -> ScanResult:
    """Whole-repo passes over an assembled result — run once per scan, after
    every analyzer's per-file output is merged, so taint/authz/anomalies see
    the full route set (#219).

    AR007: a budget breach between passes stops the remaining passes; the
    caller's stage boundary publishes the partial result (AC-010).
    """
    try:
        _run_repo_passes(result, root_path, progress, recall, index)
    except BudgetExpired as exc:
        budget = active_budget()
        if budget is not None:
            result.limitations.append(
                f"elapsed-time budget of {budget.seconds}s expired during whole-repo passes; "
                "remaining passes were skipped - ANALYSIS IS PARTIAL."
            )
        exc.partial = result
        raise
    return result


def _run_repo_passes(
    result: ScanResult,
    root_path: Path,
    progress: ScanProgress | None,
    recall: bool,
    index: RepoIndex | None,
) -> None:
    """Taint pass runs after regular signal extraction — it needs the
    route list to know where to seed source flows from (#45). This is the
    slow tail on big monorepos (import-graph walk), so it gets its own
    progress stage."""
    if progress is not None:
        progress.stage("Taint / data-flow analysis")
    budget = active_budget()
    if budget is not None:
        budget.tick("run_repo_passes")
    result.taint_chains = result.taint_chains + analyze_taint(
        result, root_path, recall=recall_config() if recall else DEFAULT_RECALL, index=index
    )
    # SBOM inventory: direct-dep parse of manifest files (#48, slice 1).
    if progress is not None:
        progress.stage("Dependency inventory (SBOM)")
    if budget is not None:
        budget.tick("run_repo_passes")
    result.dependencies = result.dependencies + analyze_sbom(root_path)
    # Supply-chain risk beyond CVEs (#247): offline, over the same manifests.
    if progress is not None:
        progress.stage("Dependency supply-chain risk")
    if budget is not None:
        budget.tick("run_repo_passes")
    result.supply_chain_issues = result.supply_chain_issues + scan_supply_chain(
        root_path, result.dependencies
    )
    # CI workflow security (#142): parse .github/workflows for unpinned actions,
    # pull_request_target checkouts, secrets/injectable context in run steps,
    # over-broad permissions, and self-hosted runners on PR triggers.
    if progress is not None:
        progress.stage("CI workflow security")
    if budget is not None:
        budget.tick("run_repo_passes")
    result.workflow_issues = result.workflow_issues + scan_workflows(root_path)
    # BOLA/IDOR: routes with an id param reaching a datastore with no
    # ownership check nearby (#69). Runs after taint so it can reuse
    # sql_execute reachability.
    if progress is not None:
        progress.stage("Authorization (BOLA/IDOR)")
    if budget is not None:
        budget.tick("run_repo_passes")
    result.authz_candidates = result.authz_candidates + analyze_authz(result, root_path)
    # Anomaly / outlier pass (#78): the odd-one-out among sibling routes.
    # Runs last so the full route list is assembled into cohorts. It drives its
    # own determinate per-cohort progress (the slow tail on big route surfaces).
    if budget is not None:
        budget.tick("run_repo_passes")
    result.anomalies = result.anomalies + find_anomalies(result, root_path, progress=progress)
    # Pin the run to the content snapshot its per-file pass read (C33/AM047):
    # merged results are stamped here because per-analyzer stamps would not
    # survive merge_analyzer_results.
    if index is not None and index.snapshot is not None:
        result.scan_snapshot = index.snapshot.identity()
