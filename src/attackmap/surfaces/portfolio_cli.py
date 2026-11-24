"""``attackmap portfolio`` — the portfolio surface (AR081 / AC-402).

Scans every repository listed in a ``repos.yaml`` file through the standard
per-repo pipeline (identical generations to ``attackmap analyze <repo>``) and
emits one portfolio generation on top: ``portfolio.json`` (cross-repo graph +
ranked hotspots) and ``portfolio-summary.md``. The graph semantics and the
portfolio.json schema live in ``attackmap.orchestration.portfolio``.
"""

from __future__ import annotations

from pathlib import Path

import typer

from attackmap.orchestration.portfolio import (
    PortfolioError,
    load_repos_yaml,
    run_portfolio,
)
from attackmap.output.report import OUTPUT_FORMATS

portfolio_app = typer.Typer(help="Cross-repo portfolio analysis: shared seams, cross-repo graph, ranked hotspots.")


@portfolio_app.command("analyze")
def analyze(
    config: str = typer.Argument(
        ...,
        help="Path to repos.yaml: a 'repositories' list of repo paths, optionally with labels.",
    ),
    output: str = typer.Option(
        "portfolio", "--output", "-o",
        help="Directory for the portfolio generation and the per-repo report generations.",
    ),
    format: str = typer.Option(
        "all", "--format",
        help="Portfolio summary artifacts: 'all' (default), 'json' (portfolio.json only), "
        "or 'markdown' (portfolio-summary.md). portfolio.json is always written.",
    ),
    fleet_workers: int = typer.Option(
        1, "--fleet-workers",
        help="Maximum parallel repository scans. Default 1 (serial, in-process).",
    ),
) -> None:
    """Analyze a portfolio of repositories and emit the cross-repo view."""
    if format not in OUTPUT_FORMATS:
        raise typer.BadParameter(
            f"Unknown output format {format!r}; expected one of: {', '.join(OUTPUT_FORMATS)}.")
    try:
        repos = load_repos_yaml(config)
        run = run_portfolio(repos, Path(output), output_format=format, max_workers=fleet_workers)
    except PortfolioError as exc:
        raise typer.BadParameter(str(exc)) from exc

    summary = run.payload["summary"]
    typer.echo(
        f"Portfolio: {summary['repositories']} repositories, "
        f"{summary['graph_nodes']} graph node(s), {summary['graph_edges']} cross-repo edge(s), "
        f"{summary['hotspots']} ranked hotspot(s)."
    )
    typer.echo(f"Portfolio written to: {(Path(output) / 'portfolio.json').resolve()}")
    if run.exit_code:
        typer.echo("Note: one or more repository scans failed; see portfolio.json 'failed'.", err=True)
    raise typer.Exit(code=run.exit_code)
