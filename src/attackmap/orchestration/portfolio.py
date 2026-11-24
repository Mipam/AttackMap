"""Portfolio mode (AR081 / AC-402) — a cross-repo view over per-repo scans.

``attackmap portfolio analyze repos.yaml`` scans every listed repository
through the unchanged single-repository pipeline (reusing the fleet execution
path in ``orchestration.scan_service`` so per-repo generations and behavior
are identical to ``attackmap analyze <repo>``), then adds one portfolio
generation on top:

- **cross-repo graph** — nodes are repositories plus *connector* nodes for
  shared external hosts, database kinds, dependencies and secret markers;
  edges connect a repo to each connector it exhibits, plus direct
  client→server service links from the existing contract linker (#146b).
- **ranked hotspots** — every repo's findings, de-duplicated per repo and
  ordered by the centralized ranking policy (``reasoning.ranking``), with a
  deterministic cross-repo exposure bonus for findings whose repository sits
  on more shared seams.

Graph semantics (the defensible default, documented here):

- Node ``kind`` is one of ``repo``, ``external_host``, ``database``,
  ``dependency``, ``secret_marker``.
- A connector node exists only when **two or more repositories** exhibit the
  same signal value (same normalized external host, same database kind, same
  ``ecosystem:name`` dependency, same secret name). The portfolio graph is
  cross-repo by construction: a signal unique to one repo never becomes an
  edge, so the graph answers "what do these repos share?" rather than
  restating per-repo output.
- Every edge carries ``basis`` (``observed`` when grounded directly in an
  analyzer-emitted signal with file/line evidence; ``inferred`` when the
  reasoning is a heuristic lead — only contract-link *candidates* land here)
  and an ``evidence`` list of ``{repo, file, line}`` pointers back into the
  per-repo analyses. Nothing in the graph is invented: each edge is
  re-derivable from the per-repo reports.
- Host normalization strips scheme, credentials, path and port from
  ``ExternalCall.target`` so ``https://api.internal/x`` and
  ``http://user@api.internal:8080/y`` name the same connector.

Output is byte-stable for identical inputs: every list is sorted, keys are
emitted with ``sort_keys=True``, and no timestamps, run ids or absolute
report-generation paths are included.

Layering: orchestration may import ``reasoning`` (downward) and the
``output`` presentation band (lateral, rank >= 5). ``reasoning.ranking`` is
used read-only — the cross-repo adaptation lives here, in this module.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import yaml

from attackmap import __version__
from attackmap.foundation.application_errors import emit_text
from attackmap.foundation.errors import AttackMapError
from attackmap.foundation.fleet_resource_identity import fleet_repo_ids
from attackmap.foundation.safe_fs import ensure_output_dir, safe_write_text
from attackmap.model.findings import Finding
from attackmap.orchestration.fleet import FleetRepoResult, FleetScan
from attackmap.orchestration.run_spec import RunSpec
from attackmap.orchestration.scan_service import ScanRequest, ScanRequestError, execute_scan_request
from attackmap.output.report import OUTPUT_FORMATS
from attackmap.reasoning.finding_identity import finding_id
from attackmap.reasoning.ranking import compute_finding_score, finding_sort_key

PORTFOLIO_SCHEMA_VERSION = 1
PORTFOLIO_JSON_NAME = "portfolio.json"
PORTFOLIO_MD_NAME = "portfolio-summary.md"
# Per shared-seam exposure bonus added to a repo finding's base ranking score.
_CROSS_LINK_BONUS = 4
# Maximum number of hotspot entries in portfolio.json / the summary.
_HOTSPOT_LIMIT = 25

# Contract-link resolutions that positively identify a server repo. Candidates
# (unresolved destinations, C28) stay visible but are marked inferred.
_OBSERVED_LINK_RESOLUTIONS = frozenset({"observed", "observed_via_proxy"})


class PortfolioError(AttackMapError):
    """Configuration or execution error raised before/around portfolio runs."""

    code = "portfolio"


@dataclass(frozen=True)
class PortfolioRepo:
    """One repository entry from ``repos.yaml``."""

    path: Path
    label: str | None = None


# ---------------------------------------------------------------------------
# repos.yaml loading
# ---------------------------------------------------------------------------

def load_repos_yaml(config_path: str | Path) -> list[PortfolioRepo]:
    """Parse ``repos.yaml`` into validated repository entries.

    Accepted shapes::

        repositories:
          - ../repo-a                      # string shorthand: path only
          - path: ../repo-b
            label: billing                  # optional human label / repo id

    A bare top-level list of the same entry shapes is also accepted.
    Relative paths resolve against the config file's directory. Labels must
    be unique when given; unlabeled repos derive their id from the path.
    """
    path = Path(config_path)
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PortfolioError(f"Cannot read repos.yaml at {path}: {exc}") from exc
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise PortfolioError(f"repos.yaml at {path} is not valid YAML: {exc}") from exc

    if isinstance(data, list):
        entries: object = data
    elif isinstance(data, dict):
        entries = data.get("repositories")
        if entries is None:
            raise PortfolioError(
                f"repos.yaml at {path} must define a 'repositories' list (or be a list).")
    else:
        raise PortfolioError(f"repos.yaml at {path} must be a mapping or a list.")
    if not isinstance(entries, list) or not entries:
        raise PortfolioError(f"repos.yaml at {path} lists no repositories.")

    repos: list[PortfolioRepo] = []
    labels: set[str] = set()
    for index, entry in enumerate(entries):
        label: str | None = None
        if isinstance(entry, str):
            repo_path = entry
        elif isinstance(entry, dict) and isinstance(entry.get("path"), str):
            repo_path = entry["path"]
            raw_label = entry.get("label")
            if raw_label is not None:
                if not isinstance(raw_label, str) or not raw_label.strip():
                    raise PortfolioError(f"repos.yaml entry {index + 1}: label must be a non-empty string.")
                label = raw_label.strip()
        else:
            raise PortfolioError(
                f"repos.yaml entry {index + 1} must be a path string or a mapping with a 'path' key.")
        resolved = Path(repo_path)
        if not resolved.is_absolute():
            resolved = (path.parent / resolved).resolve()
        if label is not None:
            if label in labels:
                raise PortfolioError(f"repos.yaml: duplicate label {label!r}.")
            labels.add(label)
        repos.append(PortfolioRepo(path=resolved, label=label))

    if len({repo.path for repo in repos}) != len(repos):
        raise PortfolioError("repos.yaml lists the same repository path more than once.")
    return repos


# ---------------------------------------------------------------------------
# Cross-repo graph
# ---------------------------------------------------------------------------

def _normalize_host(target: str) -> str:
    """Reduce an ExternalCall target to a comparable host name (lowercased).

    ``https://user@api.internal:8443/v1`` and ``api.internal/v1`` both name
    ``api.internal``; scheme, credentials, port and path are stripped. Non-URL
    targets (e.g. ``queue://celery/default``) fall back to the authority or
    the first path segment so broker-style targets still compare stably.
    """
    text = (target or "").strip()
    if not text:
        return ""
    if "://" in text:
        parsed = urlparse(text)
        host = parsed.hostname or parsed.netloc
        if host:
            return host.lower()
        text = parsed.path or text
    return text.split("/", 1)[0].split(":", 1)[0].lower()


@dataclass(frozen=True)
class _Connector:
    """One shared signal value and the per-repo evidence behind it."""

    kind: str  # external_host | database | dependency | secret_marker
    node_id: str
    label: str
    # repo_id -> sorted tuple of (file, line) evidence sites
    by_repo: dict[str, tuple[tuple[str, int | None], ...]]


def _evidence_sites(signals: list) -> dict[str, tuple[tuple[str, int | None], ...]]:
    """Group analyzer signals by repo into sorted (file, line) evidence tuples."""
    sites: dict[str, set[tuple[str, int | None]]] = {}
    for repo_id, signal in signals:
        sites.setdefault(repo_id, set()).add((signal.file, signal.line))
    return {
        repo_id: tuple(sorted(repo_sites, key=lambda s: (s[0], s[1] or 0)))
        for repo_id, repo_sites in sorted(sites.items())
    }


def _collect_connectors(results: list[FleetRepoResult]) -> list[_Connector]:
    """Build connector candidates for the four shared-signal families.

    Only values exhibited by at least two repositories are kept — see the
    module docstring for the semantics.
    """
    hosts: dict[str, list[tuple[str, object]]] = {}
    databases: dict[str, list[tuple[str, object]]] = {}
    dependencies: dict[str, list[tuple[str, object]]] = {}
    secrets: dict[str, list[tuple[str, object]]] = {}
    for result in results:
        for call in result.scan.external_calls:
            host = _normalize_host(call.target)
            if host:
                hosts.setdefault(host, []).append((result.repo_id, call))
        for db_hint in result.scan.databases:
            kind = (db_hint.kind or "").strip().lower()
            if kind:
                databases.setdefault(kind, []).append((result.repo_id, db_hint))
        for dep in result.scan.dependencies:
            name = (dep.name or "").strip().lower()
            if name:
                key = f"{dep.ecosystem}:{name}"
                dependencies.setdefault(key, []).append((result.repo_id, dep))
        for secret_hint in result.scan.secret_hints:
            name = (secret_hint.name or "").strip()
            if name:
                secrets.setdefault(name, []).append((result.repo_id, secret_hint))

    connectors: list[_Connector] = []
    for host, signals in sorted(hosts.items()):
        if len({repo for repo, _ in signals}) >= 2:
            connectors.append(_Connector(
                kind="external_host", node_id=f"external_host:{host}", label=host,
                by_repo=_evidence_sites(signals)))
    for kind, signals in sorted(databases.items()):
        if len({repo for repo, _ in signals}) >= 2:
            connectors.append(_Connector(
                kind="database", node_id=f"database:{kind}", label=kind,
                by_repo=_evidence_sites(signals)))
    for key, signals in sorted(dependencies.items()):
        if len({repo for repo, _ in signals}) >= 2:
            connectors.append(_Connector(
                kind="dependency", node_id=f"dependency:{key}", label=key,
                by_repo=_evidence_sites(signals)))
    for name, signals in sorted(secrets.items()):
        if len({repo for repo, _ in signals}) >= 2:
            connectors.append(_Connector(
                kind="secret_marker", node_id=f"secret:{name}", label=name,
                by_repo=_evidence_sites(signals)))
    return connectors


def _service_link_edges(fleet: FleetScan) -> list[dict]:
    """Client→server contract links (#146b) as direct repo→repo edges.

    Observed resolutions are ``basis: observed``; unresolved candidates stay
    visible as ``basis: inferred`` leads (never asserted trust paths, C28).
    """
    edges: list[dict] = []
    for link in sorted(
        fleet.links,
        key=lambda lk: (
            lk.client_repo, lk.server_repo, lk.method or "",
            lk.path_template or "", lk.resolution or "",
        ),
    ):
        observed = link.resolution in _OBSERVED_LINK_RESOLUTIONS
        key = f"service_link:{link.client_repo}->{link.server_repo}:" \
            f"{link.method or ''}:{link.path_template or ''}"
        edges.append({
            "id": key,
            "kind": "service_link",
            "source": f"repo:{link.client_repo}",
            "target": f"repo:{link.server_repo}",
            "basis": "observed" if observed else "inferred",
            "resolution": link.resolution or "unknown",
            "label": f"{link.method or 'ANY'} /{link.path_template or ''}",
            "evidence": [
                {"repo": link.client_repo, "file": link.client_file, "line": link.client_line},
                {"repo": link.server_repo, "file": link.server_file, "line": link.server_line},
            ],
        })
    return edges


def build_portfolio_graph(fleet: FleetScan) -> dict:
    """The deterministic cross-repo graph: nodes, edges, per-edge evidence.

    Pure function of the fleet results, so it is unit-testable without a
    real scan; every list is sorted by construction.
    """
    results = sorted(fleet.results, key=lambda result: result.repo_id)
    nodes: list[dict] = []
    edges: list[dict] = []
    for result in results:
        nodes.append({
            "id": f"repo:{result.repo_id}",
            "kind": "repo",
            "label": result.repo_id,
            "path": result.root,
        })
    for connector in _collect_connectors(results):
        nodes.append({
            "id": connector.node_id,
            "kind": connector.kind,
            "label": connector.label,
            "shared_by": sorted(connector.by_repo),
        })
        for repo_id in sorted(connector.by_repo):
            edge_kind = {
                "external_host": "calls_external_host",
                "database": "uses_database",
                "dependency": "declares_dependency",
                "secret_marker": "references_secret",
            }[connector.kind]
            edges.append({
                "id": f"{edge_kind}:{repo_id}->{connector.node_id}",
                "kind": edge_kind,
                "source": f"repo:{repo_id}",
                "target": connector.node_id,
                "basis": "observed",
                "evidence": [
                    {"repo": repo_id, "file": file, "line": line}
                    for file, line in connector.by_repo[repo_id]
                ],
            })
    edges.extend(_service_link_edges(fleet))
    nodes.sort(key=lambda node: node["id"])
    edges.sort(key=lambda edge: edge["id"])
    return {"nodes": nodes, "edges": edges}


# ---------------------------------------------------------------------------
# Cross-repo ranked hotspots
# ---------------------------------------------------------------------------

def _repo_degrees(graph: dict) -> dict[str, int]:
    """Distinct shared seams per repo = incident connector + service-link edges."""
    degrees: dict[str, int] = {}
    for edge in graph["edges"]:
        for endpoint in (edge["source"], edge["target"]):
            if endpoint.startswith("repo:"):
                repo_id = endpoint[len("repo:"):]
                degrees[repo_id] = degrees.get(repo_id, 0) + 1
    return degrees


def rank_portfolio_hotspots(fleet: FleetScan, graph: dict,
                            limit: int = _HOTSPOT_LIMIT) -> list[dict]:
    """Rank findings across repos: central ranking policy plus a deterministic
    cross-repo exposure bonus per shared seam the finding's repository sits on.

    De-duplication is per (repo, finding id) — the same finding shape in two
    repositories is two real occurrences, not a duplicate. Ordering is total:
    ``(-portfolio_score, central sort key, repo, finding id)``.
    """
    degrees = _repo_degrees(graph)
    seen: set[tuple[str, str]] = set()
    candidates: list[tuple[Finding, str, str]] = []
    for result in sorted(fleet.results, key=lambda r: r.repo_id):
        for finding in result.findings:
            fid = finding_id(finding)
            key = (result.repo_id, fid)
            if key in seen:
                continue
            seen.add(key)
            candidates.append((finding, result.repo_id, fid))
    candidates.sort(key=lambda item: (*finding_sort_key(item[0]), item[1], item[2]))

    hotspots: list[dict] = []
    for finding, repo_id, fid in candidates:
        base = compute_finding_score(finding.severity, finding.confidence)
        degree = degrees.get(repo_id, 0)
        entry = {
            "repo": repo_id,
            "finding_id": fid,
            "title": finding.title,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "score": base,
            "cross_repo_degree": degree,
            "portfolio_score": base + _CROSS_LINK_BONUS * degree,
            "locations": [
                {"file": location.file, "line": location.line}
                for location in sorted(
                    finding.locations,
                    key=lambda loc: (loc.file or "", loc.line or 0),
                )
            ],
        }
        hotspots.append(entry)
    hotspots.sort(key=lambda entry: (
        -entry["portfolio_score"], -entry["score"],
        entry["repo"], entry["finding_id"],
    ))
    for rank, entry in enumerate(hotspots[:limit], start=1):
        entry["rank"] = rank
    return hotspots[:limit]


# ---------------------------------------------------------------------------
# Portfolio generation artifact
# ---------------------------------------------------------------------------

def portfolio_payload(fleet: FleetScan, labels: dict[str, str] | None = None) -> dict:
    """The byte-stable portfolio.json payload for a completed fleet run.

    ``labels`` maps repo_id → repos.yaml label (identity for display); absent
    ids fall back to the repo id itself.
    """
    labels = labels or {}
    graph = build_portfolio_graph(fleet)
    hotspots = rank_portfolio_hotspots(fleet, graph)
    repositories = []
    for result in sorted(fleet.results, key=lambda r: r.repo_id):
        counts = result.severity_counts()
        repositories.append({
            "repo_id": result.repo_id,
            "label": labels.get(result.repo_id, result.repo_id),
            "path": result.root,
            "output_dir": f"{result.repo_id}/",
            "findings": len(result.findings),
            "suppressed": result.suppressed_count,
            "high": counts["high"],
            "medium": counts["medium"],
            "low": counts["low"],
        })
    failed = sorted(
        ({"repo_id": f["repo_id"], "path": f["root"], "error": f["error"]} for f in fleet.failed),
        key=lambda f: (f["repo_id"], f["path"], f["error"]),
    )
    return {
        "schema_version": PORTFOLIO_SCHEMA_VERSION,
        "engine_version": __version__,
        "repositories": repositories,
        "failed": failed,
        "graph": graph,
        "hotspots": hotspots,
        "summary": {
            "repositories": len(repositories),
            "failed": len(failed),
            "graph_nodes": len(graph["nodes"]),
            "graph_edges": len(graph["edges"]),
            "hotspots": len(hotspots),
        },
    }


def render_portfolio_summary(payload: dict) -> str:
    """Human-readable portfolio summary (Markdown), written alongside portfolio.json."""
    lines: list[str] = ["# AttackMap portfolio summary", ""]
    summary = payload["summary"]
    lines.append(
        f"{summary['repositories']} repositories analyzed · "
        f"{summary['graph_edges']} cross-repo edge(s) · "
        f"{summary['hotspots']} ranked hotspot(s)."
    )
    lines.append("")
    if payload["failed"]:
        lines.append(f"**{len(payload['failed'])} repository scan(s) failed and are excluded:**")
        for failure in payload["failed"]:
            lines.append(f"- `{failure['repo_id']}` — {failure['error']}")
        lines.append("")

    lines.append("## Repositories")
    lines.append("")
    lines.append("| Repository | Label | HIGH | MED | LOW | Findings | Report |")
    lines.append("|---|---|---:|---:|---:|---:|---|")
    for repo in payload["repositories"]:
        lines.append(
            f"| `{repo['repo_id']}` | {repo['label']} | {repo['high']} | {repo['medium']} | "
            f"{repo['low']} | {repo['findings']} | [{repo['output_dir']}]({repo['output_dir']}) |"
        )
    lines.append("")

    lines.append("## Cross-repo graph")
    lines.append("")
    node_labels = {node["id"]: node["label"] for node in payload["graph"]["nodes"]}
    if payload["graph"]["edges"]:
        lines.append("| Edge | From | To | Basis | Evidence |")
        lines.append("|---|---|---|---|---|")
        for edge in payload["graph"]["edges"]:
            sites = ", ".join(
                f"`{site['repo']}`:{site['file']}" + (f":{site['line']}" if site["line"] else "")
                for site in edge["evidence"]
            )
            lines.append(
                f"| {edge['kind']} | {node_labels.get(edge['source'], edge['source'])} | "
                f"{node_labels.get(edge['target'], edge['target'])} | {edge['basis']} | {sites} |"
            )
    else:
        lines.append("_No shared signals detected across the analyzed repositories._")
    lines.append("")

    lines.append("## Ranked hotspots")
    lines.append("")
    if payload["hotspots"]:
        lines.append("| Rank | Repository | Severity | Score | Portfolio | Finding |")
        lines.append("|---:|---|---|---:|---:|---|")
        for hotspot in payload["hotspots"]:
            lines.append(
                f"| {hotspot['rank']} | `{hotspot['repo']}` | {hotspot['severity'].upper()} | "
                f"{hotspot['score']} | {hotspot['portfolio_score']} | {hotspot['title']} |"
            )
    else:
        lines.append("_No findings across the analyzed repositories._")
    lines.append("")
    return "\n".join(lines)


def write_portfolio_artifacts(output_dir: str | Path, payload: dict,
                              output_format: str = "all") -> dict[str, Path]:
    """Write ``portfolio.json`` (always) and ``portfolio-summary.md`` for
    markdown/all formats. ``output_format`` values come from
    ``output.report.OUTPUT_FORMATS`` (the single definition, reused here).
    """
    if output_format not in OUTPUT_FORMATS:
        raise PortfolioError(
            f"Unknown output format {output_format!r}; expected one of: {', '.join(OUTPUT_FORMATS)}.")
    out = ensure_output_dir(output_dir, mark=True)
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    safe_write_text(out, out / PORTFOLIO_JSON_NAME, text)
    written = {PORTFOLIO_JSON_NAME: out / PORTFOLIO_JSON_NAME}
    if output_format in {"all", "markdown"}:
        safe_write_text(out, out / PORTFOLIO_MD_NAME, render_portfolio_summary(payload) + "\n")
        written[PORTFOLIO_MD_NAME] = out / PORTFOLIO_MD_NAME
    return written


# ---------------------------------------------------------------------------
# Orchestration entry point
# ---------------------------------------------------------------------------

@dataclass
class PortfolioRun:
    """Terminal state of one portfolio run."""

    exit_code: int
    payload: dict
    written: dict[str, Path]
    fleet: FleetScan


def run_portfolio(
    repos: list[PortfolioRepo],
    output: str | Path,
    *,
    echo: Callable[..., None] = emit_text,
    output_format: str = "all",
    max_workers: int = 1,
) -> PortfolioRun:
    """Scan every repository (unchanged per-repo pipeline) and emit the
    portfolio generation into ``output``.

    Reuses :func:`execute_scan_request` with the multi-repo fleet path; the
    ``fleet_finished`` hook captures the assembled ``FleetScan`` without
    altering the scan itself. At least one repository must analyze
    successfully for a portfolio to be emitted.
    """
    if output_format not in OUTPUT_FORMATS:
        raise PortfolioError(
            f"Unknown output format {output_format!r}; expected one of: {', '.join(OUTPUT_FORMATS)}.")
    if not repos:
        raise PortfolioError("At least one repository is required.")
    for repo in repos:
        if not repo.path.is_dir():
            raise PortfolioError(f"Repository path does not exist or is not a directory: {repo.path}")

    captured: list[FleetScan] = []

    def capture(_output_root: Path, fleet: FleetScan) -> None:
        captured.append(fleet)

    repo_paths = [repo.path for repo in repos]
    repo_ids = fleet_repo_ids(repo_paths)
    labels = {
        repo_ids[index]: (repos[index].label or repo_ids[index])
        for index in range(len(repos))
    }
    spec = RunSpec(atomic_output=False, output_format="all")
    request = ScanRequest(
        repo_paths=repo_paths,
        output=Path(output),
        spec=spec,
        max_workers=max_workers,
        fleet_finished=capture,
    )
    try:
        summary = execute_scan_request(request)
    except ScanRequestError as exc:
        raise PortfolioError(str(exc)) from exc

    fleet = captured[0] if captured else FleetScan()
    if not fleet.results:
        detail = f" ({summary.error})" if summary.error else ""
        raise PortfolioError(f"No repository analyzed successfully{detail}; no portfolio emitted.")
    payload = portfolio_payload(fleet, labels)
    written = write_portfolio_artifacts(output, payload, output_format=output_format)
    return PortfolioRun(exit_code=summary.exit_code, payload=payload, written=written, fleet=fleet)
