"""``attackmap eval`` — detection-quality evaluation over a labelled corpus (AR048).

``attackmap eval rules --corpus corpus/reference.yaml [--json]`` scans every
fixture repository named by the corpus through the public ``analyze`` API,
normalizes the findings onto the stable registry rule ids and prints a
per-rule TP/FP/FN precision/recall report (JSON or a human table).

The comparison itself lives in the low-layer ``attackmap.eval`` package;
this module owns the orchestration (YAML parsing, scanning, legacy-id
normalization) that the pure package deliberately does not do. The scan
path still emits the legacy dashed rule ids — the cascade is the active
producer until the registry retirement wiring — so each finding's id is
mapped through the registered rules' ``legacy_rule_ids`` onto the snake_case
id the corpus expects; ids with no registered counterpart pass through
unchanged and read as false positives.
"""

from __future__ import annotations

import subprocess
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import typer

from attackmap.eval import (
    Expectation,
    LocatedFinding,
    compare,
    load_cases,
    render_table,
    report_dict,
)

__all__ = ["eval_app", "run_evaluation"]

eval_app = typer.Typer(
    help="Measure detection quality: per-rule precision/recall over a labelled reference corpus.",
)


def _legacy_id_map() -> dict[str, str]:
    """Legacy dashed cascade rule id -> stable registry rule id."""
    from attackmap.reasoning.rules import REGISTRY

    return {
        legacy: rule.meta.id
        for rule in REGISTRY.all_rules()
        for legacy in getattr(rule, "legacy_rule_ids", ())
    }


def _located(findings: Any, legacy_map: dict[str, str]) -> list[LocatedFinding]:
    """Pipeline findings normalized to comparison input, ids mapped onto the registry."""
    from attackmap.model.findings import finding_rule_id

    return [
        LocatedFinding(
            rule_id=legacy_map.get(finding_rule_id(finding), finding_rule_id(finding)),
            locations=tuple((location.file, location.line) for location in finding.locations),
        )
        for finding in findings
    ]


def _git_commit(corpus_dir: Path) -> str | None:
    """The commit the corpus is checked out at, or None outside a git work tree."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=corpus_dir,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    commit = result.stdout.strip()
    return commit if result.returncode == 0 and commit else None


def run_evaluation(
    corpus_path: Path,
    *,
    generated_at: str | None = None,
    progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Scan every corpus case and return the versioned report payload.

    Args:
        corpus_path: the labelled-corpus YAML (see `corpus/reference.yaml`).
        generated_at: report timestamp; injected by tests so two runs can be
            compared byte-for-byte. Defaults to the current UTC time.
        progress: optional sink for scan status lines (``progress=print``).

    Raises:
        FileNotFoundError: the corpus file or a fixture repo does not exist.
        ValueError: the corpus document fails schema validation.

    Scan outputs go to a temporary directory that is removed on return; the
    report carries only the comparison, never scan artifacts.
    """
    import yaml

    from attackmap import __version__
    from attackmap.orchestration.run_spec import RunSpec
    from attackmap.surfaces.api import analyze

    corpus_path = Path(corpus_path)
    if not corpus_path.is_file():
        raise FileNotFoundError(f"corpus not found: {corpus_path}")
    document = yaml.safe_load(corpus_path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"corpus document must be a mapping, got {type(document).__name__}")
    cases = load_cases(document)

    legacy_map = _legacy_id_map()
    findings: list[LocatedFinding] = []
    with tempfile.TemporaryDirectory(prefix="attackmap-eval-") as tmp:
        for case in cases:
            repo = (corpus_path.parent / case.repo).resolve()
            if not repo.is_dir():
                raise FileNotFoundError(f"case {case.name!r}: fixture repo not found: {repo}")
            result = analyze(
                RunSpec(
                    repos=(repo,),
                    output=Path(tmp) / case.name,
                    output_format="json",
                    no_progress=True,
                ),
                progress=progress,
            )
            findings.extend(_located(result.findings, legacy_map))

    expectations: list[Expectation] = [
        expectation for case in cases for expectation in case.expectations
    ]
    report = report_dict(
        compare(findings, expectations),
        tool_version=__version__,
        corpus_revision=document.get("corpus_revision"),
        corpus_commit=_git_commit(corpus_path.parent),
        generated_at=generated_at or datetime.now(UTC).isoformat(),
    )
    return report


@eval_app.command("rules")
def eval_rules(
    corpus: str = typer.Option(
        "corpus/reference.yaml",
        "--corpus",
        help="Path to the labelled reference corpus (see corpus/reference.yaml).",
    ),
    as_json: bool = typer.Option(
        False,
        "--json",
        help="Emit the versioned report as JSON (default: a human table).",
    ),
) -> None:
    """Measure per-rule precision/recall over the labelled reference corpus (AR048).

    A low score is a measurement, not a failure: the command exits 0 whenever
    the corpus could be evaluated.
    """
    import json

    try:
        # Silent run: scan status lines would pollute both the JSON output
        # and the aligned table.
        report = run_evaluation(Path(corpus))
    except FileNotFoundError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except ValueError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    if as_json:
        typer.echo(json.dumps(report, indent=2))
        return
    typer.echo(render_table(report))
