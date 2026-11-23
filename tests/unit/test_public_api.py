"""AR062 public library API: ``attackmap.analyze`` (card + AC-304).

The AC-304 acceptance example — five lines from ``import`` to a typed
``AnalysisResult`` — runs here against a tiny fixture repository built in
``tmp_path``. Import-isolation and import-cost checks run in fresh
subprocesses: many other unit modules legitimately import the CLI, so a
``sys.modules`` assertion only means something in a clean interpreter.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

# Typed bindings come from the defining modules: the package-level names are
# PEP 562 lazy exports that mypy can only see as ``object``. The lazy package
# surface itself is exercised in ``test_public_names_lazy_resolution``.
from attackmap.orchestration.run_spec import RunSpec
from attackmap.orchestration.scan_service import ScanRequestError
from attackmap.surfaces.api import (
    AnalysisFailed,
    AnalysisResult,
    RepoResult,
    analyze,
)

_IMPORT_TIME_BOUND_SECONDS = 5.0


def _write_tiny_repo(root: Path) -> Path:
    """A two-file repository the engine's built-in analyzers recognize."""
    repo = root / "tiny-repo"
    src = repo / "src"
    src.mkdir(parents=True)
    (src / "app.py").write_text(
        "from flask import Flask\n"
        "\n"
        "app = Flask(__name__)\n"
        "\n"
        "\n"
        "@app.route('/run')\n"
        "def run():\n"
        "    return eval(request.args['cmd'])\n",
        encoding="utf-8",
    )
    (repo / "package.json").write_text(
        json.dumps({"name": "tiny-fixture", "version": "1.0.0"}),
        encoding="utf-8",
    )
    return repo


def test_ac304_five_line_example(tmp_path: Path) -> None:
    """The AC-304 example against a small fixture repo (not the repo root).

    AC-304's exact ``from attackmap import analyze, RunSpec`` line is what the
    lazy-resolution and import-isolation tests exercise; the five-line flow
    itself is the ``analyze(RunSpec(repos=..., output=...))`` call below.
    """
    repo = _write_tiny_repo(tmp_path)
    output = tmp_path / "reports"

    result = analyze(RunSpec(repos=(repo,), output=output))

    assert isinstance(result, AnalysisResult)
    assert isinstance(result.findings, tuple)
    assert isinstance(result.attack_paths, tuple)
    assert isinstance(result.limitations, tuple)
    assert len(result.findings) >= 1  # the fixture's eval sink is found
    assert result.exit_code == 0
    assert len(result.repos) == 1
    repo_result = result.repos[0]
    assert isinstance(repo_result, RepoResult)
    assert repo_result.findings == result.findings
    assert repo_result.root == str(repo)
    # The run published under the caller's output directory (AC-304 evidence).
    assert result.generation_dir.is_dir()
    assert result.generation_dir.is_relative_to(output)
    assert (result.generation_dir / "attackmap-report.json").is_file()
    assert (result.generation_dir / "findings.json").is_file()


def test_analyze_requires_repos_and_output(tmp_path: Path) -> None:
    """Validation failures raise before anything is scanned (module contract)."""
    with pytest.raises(ScanRequestError, match=r"requires RunSpec\.repos"):
        analyze(RunSpec(output=tmp_path / "out"))
    with pytest.raises(ScanRequestError, match=r"requires RunSpec\.output"):
        analyze(RunSpec(repos=(tmp_path,)))


def test_analyze_failure_raises_analysis_failed(tmp_path: Path, monkeypatch) -> None:
    """A run that publishes nothing raises AnalysisFailed, never a partial result."""

    def fake_execute(request):
        del request
        return type(
            "RunSummary",
            (),
            {"report_path": None, "exit_code": 2, "error": "engine aborted"},
        )()

    monkeypatch.setattr(
        "attackmap.orchestration.scan_service.execute_scan_request", fake_execute
    )
    with pytest.raises(AnalysisFailed) as exc_info:
        analyze(RunSpec(repos=(tmp_path,), output=tmp_path / "out"))
    assert exc_info.value.exit_code == 2
    assert "engine aborted" in str(exc_info.value)


def test_import_attackmap_loads_no_cli_or_typer() -> None:
    """``import attackmap`` pulls in neither the CLI surface nor Typer."""
    code = (
        "import sys\n"
        "import attackmap\n"
        "assert 'attackmap.surfaces.cli' not in sys.modules, 'CLI surface loaded'\n"
        "assert 'typer' not in sys.modules, 'typer loaded'\n"
        "print('import-isolation OK')\n"
    )
    completed = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stderr
    assert "import-isolation OK" in completed.stdout


def test_import_attackmap_time_is_small() -> None:
    """Fresh-interpreter import cost of the lazy package (report-only number)."""
    code = (
        "import time\n"
        "start = time.perf_counter()\n"
        "import attackmap\n"
        "print(f'{time.perf_counter() - start:.3f}')\n"
    )
    durations = []
    for _ in range(3):
        completed = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert completed.returncode == 0, completed.stderr
        durations.append(float(completed.stdout.strip()))
    median = sorted(durations)[1]
    print(f"import attackmap: {durations} s (median {median:.3f} s)")
    assert median < _IMPORT_TIME_BOUND_SECONDS


def test_public_names_lazy_resolution() -> None:
    """The lazy exports resolve on demand and cache (PEP 562)."""
    import attackmap

    assert "analyze" in attackmap.__all__
    # First access resolves through the PEP 562 hook to the canonical object...
    assert attackmap.RunSpec is RunSpec
    assert attackmap.AnalysisResult is AnalysisResult
    # ...and then caches it in module globals, skipping the hook afterwards.
    assert attackmap.analyze is analyze
    assert vars(attackmap)["analyze"] is analyze
    assert vars(attackmap)["RunSpec"] is RunSpec
    missing = "not_a_public_name"
    with pytest.raises(AttributeError):
        getattr(attackmap, missing)


def test_analyze_progress_callback_receives_lines(tmp_path: Path) -> None:
    """Status lines go to the caller's sink instead of the console."""
    repo = _write_tiny_repo(tmp_path)
    lines: list[str] = []
    result = analyze(RunSpec(repos=(repo,), output=tmp_path / "out"), progress=lines.append)
    assert result.exit_code == 0
    assert any(line.strip() for line in lines)
