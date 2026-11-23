"""Public library API: ``analyze(RunSpec) -> AnalysisResult`` (AR062 / AC-304).

Third entry point beside the CLI and the desktop worker, and the one meant for
``import``::

    from pathlib import Path
    from attackmap import analyze, RunSpec

    result = analyze(RunSpec(repos=(Path("."),), output=Path("reports")))
    print(len(result.findings))

``analyze`` is the CLI's ``analyze`` command minus the process. It builds the
``ScanRequest`` the CLI builds and hands it to the same
``execute_scan_request``, so validation, analyzer selection, publication,
retention and the on-disk artifacts are the engine's own. The typed result is
read back from the report that run published: the same validated artifact
every other consumer reads. It differs from the CLI in three ways. It never
prompts (a missing analyzer is an error, not an install question), it raises
instead of exiting, and it does not print: the status lines the CLI writes to
its console go to the caller's ``progress`` callback, and to nowhere by
default.

Contract: ``analyze`` either returns a complete result or raises. A policy
gate (``fail_on_new_high`` / ``fail_on_new_suppression``) still returns the
complete analysis with ``exit_code == 1``; a run that stops early, publishes
nothing, or leaves repositories unscanned raises :class:`AnalysisFailed`.

Importing this module loads no engine code (the engine is imported by the
first ``analyze`` call), and nothing here imports the CLI or Typer.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from attackmap.foundation.errors import AttackMapError

if TYPE_CHECKING:  # annotations only: keep this module importable without the engine
    from attackmap.model import AttackPath, Finding
    from attackmap.orchestration.fleet import FleetScan
    from attackmap.orchestration.run_spec import RunSpec
    from attackmap.orchestration.scan_service import RunSummary

__all__ = ["AnalysisFailed", "AnalysisResult", "RepoResult", "analyze"]


@dataclass(frozen=True)
class RepoResult:
    """One repository's part of a run; a single-repository run has exactly one."""

    repo_id: str
    root: str  # the repository path as the caller gave it
    findings: tuple[Finding, ...] = field(repr=False)
    attack_paths: tuple[AttackPath, ...] = field(repr=False)
    limitations: tuple[str, ...] = field(repr=False)


@dataclass(frozen=True)
class AnalysisResult:
    """A completed analysis, as typed objects.

    ``findings``, ``attack_paths`` and ``limitations`` hold every repository's
    items in request order (the concatenation of ``repos``), suppressed
    findings excluded. ``generation_dir`` is the directory this run published:
    the immutable generation under the output root (the default), or the flat
    output directory itself when ``atomic_output=False``. For a fleet it is the
    fleet generation, which holds ``fleet-summary.json`` and one
    ``<repo_id>/`` directory per repository.
    """

    findings: tuple[Finding, ...] = field(repr=False)
    attack_paths: tuple[AttackPath, ...] = field(repr=False)
    limitations: tuple[str, ...] = field(repr=False)
    generation_dir: Path
    exit_code: int = 0  # 1 when a policy gate tripped; the analysis is still complete
    repos: tuple[RepoResult, ...] = field(default=(), repr=False)

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(repos={len(self.repos)}, findings={len(self.findings)}, "
            f"attack_paths={len(self.attack_paths)}, limitations={len(self.limitations)}, "
            f"generation_dir={str(self.generation_dir)!r}, exit_code={self.exit_code})"
        )


class AnalysisFailed(AttackMapError, RuntimeError):
    """A run ended without a complete published result.

    ``detail`` carries the engine's reason followed by the error lines the CLI
    would have printed; ``exit_code`` is the code the CLI would have exited
    with. Nothing is returned for a failed run: partial findings would read as
    a clean repository.
    """

    code = "analysis_failed"
    remediation = (
        "Read the error lines in the detail; run-manifest.json and diagnostics/ "
        "under the output directory hold the per-stage record."
    )

    def __init__(self, detail: str, *, exit_code: int = 1) -> None:
        super().__init__(detail)
        self.exit_code = exit_code


def analyze(spec: RunSpec, progress: Callable[[str], None] | None = None) -> AnalysisResult:
    """Run one scan in-process and return what it published.

    Args:
        spec: the whole run configuration. ``repos`` and ``output`` are
            required here; every other group means what the matching CLI flag
            means.
        progress: optional sink for the status lines the CLI prints, called
            with one ``str`` per line (``progress=print`` works). Omit it for
            a silent run. Lines the CLI marks as errors are also kept and
            reported by :class:`AnalysisFailed` if the run fails.

    Raises:
        ScanRequestError: the request cannot run (no ``repos`` or ``output``,
            an unknown analyzer, an unsafe output path, a feature the fleet
            refuses). Nothing was scanned.
        AnalysisFailed: the run started but ended without a complete result.

    One run at a time per thread: the engine keeps per-run state on the
    calling thread, exactly as the CLI does.
    """
    from attackmap.orchestration.scan_service import (
        ScanRequest,
        ScanRequestError,
        execute_scan_request,
    )

    repos = [Path(repo) for repo in spec.repos]
    if not repos:
        raise ScanRequestError("analyze() requires RunSpec.repos: name at least one repository.")
    if spec.output is None:
        raise ScanRequestError("analyze() requires RunSpec.output: name the report directory.")
    if not spec.atomic_output and spec.output_format == "markdown":
        raise ScanRequestError(
            "analyze() returns findings from the JSON report: use output_format 'all' or "
            "'json', or keep atomic_output on."
        )

    error_lines: list[str] = []

    def echo(message: object = "", *, err: bool = False, nl: bool = True) -> None:
        del nl  # a line without its newline is delivered like any other
        text = str(message)
        if err:
            error_lines.append(text)
        if progress is not None:
            progress(text)

    fleets: list[tuple[Path, FleetScan]] = []

    def fleet_finished(folder: Path, fleet: FleetScan) -> None:
        fleets.append((folder, fleet))

    summary = execute_scan_request(ScanRequest(
        repo_paths=repos,
        output=Path(spec.output),
        spec=spec,
        run_id=spec.run_id,
        output_format=spec.output_format,
        echo=echo,
        # Fleet coordination is request-level (AR025): execute_scan_request
        # rebuilds the spec's fleet group from these transport fields, so the
        # library mirrors the caller's group back onto the request.
        max_workers=spec.fleet.max_workers,
        fleet_supervised=spec.fleet.supervised,
        fleet_timeout_seconds=spec.fleet.timeout_seconds,
        fleet_input_byte_budget=spec.fleet.input_byte_budget,
        fleet_finished=fleet_finished,
    ))
    if len(repos) > 1:
        return _fleet_result(fleets, summary, error_lines)
    return _single_result(summary, repos[0], error_lines)


def _failure(summary: RunSummary, error_lines: list[str]) -> str:
    head = summary.error or f"analysis stopped with exit code {summary.exit_code}"
    return "\n".join([head, *error_lines])


def _single_result(
    summary: RunSummary, repo: Path, error_lines: list[str]
) -> AnalysisResult:
    from attackmap.orchestration.fleet import fleet_repo_ids

    report_path = summary.report_path
    if report_path is None:
        # The engine returned without publishing a validated generation
        # (controlled exit, abort, crash): there is no result to hand back.
        raise AnalysisFailed(_failure(summary, error_lines), exit_code=summary.exit_code)
    findings, attack_paths, limitations = _load_report(report_path)
    return _result(
        (RepoResult(repo_id=fleet_repo_ids([repo])[0], root=str(repo), findings=findings,
                    attack_paths=attack_paths, limitations=limitations),),
        report_path.parent,
        summary.exit_code,
    )


def _fleet_result(
    fleets: list[tuple[Path, FleetScan]], summary: RunSummary, error_lines: list[str]
) -> AnalysisResult:
    if not fleets:
        raise AnalysisFailed(_failure(summary, error_lines), exit_code=summary.exit_code)
    folder, fleet = fleets[0]
    failures = [f"{item['repo_id']}: {item['error']}" for item in fleet.failed]
    if failures or summary.exit_code:
        # Repositories that were not scanned make this an incomplete result.
        head = (f"{len(failures)} repository scan(s) failed and are not in this result"
                if failures else f"fleet analysis stopped with exit code {summary.exit_code}")
        raise AnalysisFailed("\n".join([head, *failures, *error_lines]), exit_code=summary.exit_code)
    return _result(
        tuple(
            RepoResult(repo_id=result.repo_id, root=result.root, findings=tuple(result.findings),
                       attack_paths=tuple(result.attack_paths),
                       limitations=tuple(result.scan.limitations))
            for result in fleet.results
        ),
        folder,
        summary.exit_code,
    )


def _result(repos: tuple[RepoResult, ...], generation_dir: Path, exit_code: int) -> AnalysisResult:
    return AnalysisResult(
        findings=tuple(finding for repo in repos for finding in repo.findings),
        attack_paths=tuple(path for repo in repos for path in repo.attack_paths),
        limitations=tuple(note for repo in repos for note in repo.limitations),
        generation_dir=generation_dir,
        exit_code=exit_code,
        repos=repos,
    )


def _load_report(
    report_path: Path,
) -> tuple[tuple[Finding, ...], tuple[AttackPath, ...], tuple[str, ...]]:
    """Re-validate the findings, attack paths and limitations a run published."""
    from attackmap.model import AttackPath, Finding, ScanResult

    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
        return (
            tuple(Finding.model_validate(item) for item in report["findings"]),
            tuple(AttackPath.model_validate(item) for item in report["attack_paths"]),
            tuple(ScanResult.model_validate(report["scan"]).limitations),
        )
    except (OSError, ValueError, KeyError, TypeError) as exc:  # pydantic's ValidationError is a ValueError
        raise AnalysisFailed(f"published report could not be read: {report_path} ({exc})") from exc
