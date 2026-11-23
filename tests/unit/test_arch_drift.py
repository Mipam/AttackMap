"""Unit tests for tools/arch_drift.py (AR088).

The tests never touch the real repository's history: they build a tiny
synthetic git repo under ``C:/tmp/attackmap-scratch/ar088`` with two commits
(a clean baseline, then a commit that introduces one import cycle, one broad
except, and one 91-line function) and drive the tool's CLI as a subprocess
against it.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRATCH = Path("C:/tmp/attackmap-scratch/ar088/test-arch-drift")
SYNTH = SCRATCH / "synth-repo"

METRIC_KEYS = {"import_cycles", "fan_in_max", "longest_function_lines", "broad_excepts"}


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True,
        encoding="utf-8", errors="replace",
    )
    assert result.returncode == 0, f"git {' '.join(args)}: {result.stderr}"
    return result.stdout


def _write(repo: Path, rel: str, content: str) -> None:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _commit(repo: Path, message: str) -> str:
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.name=drift-test", "-c", "user.email=drift@test",
         "commit", "-q", "-m", message)
    return _git(repo, "rev-parse", "HEAD").strip()


def _run_tool(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "tools.arch_drift", *args],
        cwd=REPO_ROOT, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=120,
    )


def _rmtree(path: Path) -> None:
    def onerror(func, p, _exc_info):  # git object files are read-only
        Path(p).chmod(0o666)
        func(p)

    shutil.rmtree(path, onerror=onerror)


@pytest.fixture(scope="module")
def synth_repo() -> dict:
    """Build the two-commit synthetic repo; return shas and the base dir."""
    if SYNTH.exists():
        _rmtree(SYNTH)
    SYNTH.mkdir(parents=True)
    try:
        _git(SYNTH, "init", "-q")
        _git(SYNTH, "config", "core.autocrlf", "false")

        _write(SYNTH, "src/demo/__init__.py", "")
        _write(SYNTH, "src/demo/c.py", "VALUE = 1\n")
        _write(SYNTH, "src/demo/a.py",
               "from . import c\n\n\ndef small():\n    return c.VALUE\n")
        _write(SYNTH, "src/demo/b.py",
               "from . import c\n\n\ndef small_b():\n    return c.VALUE\n")
        base = _commit(SYNTH, "clean baseline")

        # Second commit: one import cycle (a<->b), one broad except, one
        # 92-line function (def line + 90 assignment lines + return line).
        body = "\n".join(f"    x = {i}" for i in range(90))
        _write(SYNTH, "src/demo/a.py",
               "from . import b, c\n\n\ndef small():\n"
               "    try:\n        return b.small_b()\n"
               "    except Exception:\n        return c.VALUE\n\n\n"
               f"def long_fn():\n{body}\n    return x\n")
        _write(SYNTH, "src/demo/b.py",
               "from . import a, c\n\n\ndef small_b():\n    return a.small()\n")
        tip = _commit(SYNTH, "introduce drift")

        yield {"base": base, "tip": tip, "repo": SYNTH}
    finally:
        _rmtree(SYNTH)


def _tool_args(repo: Path, since: str, *extra: str) -> list[str]:
    return ["--repo", str(repo), "--since", since,
            "--root", "src/demo", "--package", "demo", *extra]


def test_json_report_has_four_metric_keys_and_expected_counts(synth_repo: dict) -> None:
    result = _run_tool(*_tool_args(synth_repo["repo"], synth_repo["base"], "--json"))
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)

    assert set(report["metric_keys"]) >= METRIC_KEYS
    assert len(report["samples"]) == 2
    for sample in report["samples"]:
        assert set(sample) >= METRIC_KEYS, sample

    base, tip = report["samples"]
    assert base["commit"] == synth_repo["base"]
    assert tip["commit"] == synth_repo["tip"]
    assert base["import_cycles"] == 0
    assert base["broad_excepts"] == 0
    assert tip["import_cycles"] == 1
    assert tip["broad_excepts"] == 1
    assert tip["longest_function_lines"] == 92
    assert tip["fan_in_max"] == 2  # a and b both import c

    assert report["trend"]["import_cycles"] == {"first": 0, "last": 1, "delta": 1}
    assert report["trend"]["broad_excepts"] == {"first": 0, "last": 1, "delta": 1}
    assert report["trend"]["longest_function_lines"]["delta"] == 90


def test_human_report_prints_trend_table(synth_repo: dict) -> None:
    result = _run_tool(*_tool_args(synth_repo["repo"], synth_repo["base"]))
    assert result.returncode == 0, result.stderr
    assert "architecture drift since" in result.stdout
    assert "trend (oldest measured -> newest)" in result.stdout
    assert "broad except handlers" in result.stdout


def test_since_commit_itself_is_measured(synth_repo: dict) -> None:
    result = _run_tool(*_tool_args(synth_repo["repo"], synth_repo["tip"], "--json"))
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert len(report["samples"]) == 1
    assert report["samples"][0]["import_cycles"] == 1


def test_invalid_since_fails_cleanly(synth_repo: dict) -> None:
    result = _run_tool(*_tool_args(synth_repo["repo"], "deadbeef"))
    assert result.returncode == 2
    assert "not a commit" in result.stderr


def test_since_head_yields_single_sample(synth_repo: dict) -> None:
    result = _run_tool(*_tool_args(synth_repo["repo"], synth_repo["tip"], "--json"))
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert len(report["samples"]) == 1
    assert report["samples"][0]["commit"] == synth_repo["tip"]
