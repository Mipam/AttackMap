"""Perf smoke tests (AR084 / AC-405): benchmark on a synthetic fixture.

Hermetic: the fixture is generated locally by ``tools/bench_analyzers.py`` under
the task scratch dir — no network, no LM Studio, no real git history. Each test
asserts the metrics exist, are sane, and stay under a bounded wall time so a
hang fails instead of blocking CI.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.perf

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRATCH = Path("C:/tmp/attackmap-scratch/ar084/test-fixtures")


def _load_bench() -> object:
    """Import tools/bench_analyzers.py by path (tools/ is not a package)."""
    spec = importlib.util.spec_from_file_location(
        "bench_analyzers", REPO_ROOT / "tools" / "bench_analyzers.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


bench = _load_bench()

BOUNDED_FULL_SCAN_S = 120.0
BOUNDED_PEAK_MEMORY_BYTES = 2 * 1024**3


def test_fixture_builds_expected_file_count(tmp_path: Path) -> None:
    repo = bench.build_fixture(tmp_path, 12)
    files = [p for p in repo.rglob("*") if p.is_file()]
    assert len(files) == 12
    assert any(p.suffix == ".py" for p in files)
    assert any(p.suffix == ".js" for p in files)


def test_benchmark_metrics_exist_and_are_sane() -> None:
    metrics = bench.measure(SCRATCH / "smoke", files=12, reps=2)

    assert metrics["files"] == 12
    assert metrics["reps"] == 2
    # Every gated metric exists and is strictly positive.
    for key in bench.GATED_METRICS:
        assert key in metrics, key
        assert metrics[key] > 0, key
    # Bounded upper wall time: a hang or pathological slowdown fails here
    # instead of blocking CI (suite timeout is the second net).
    assert metrics["full_scan_s"] < BOUNDED_FULL_SCAN_S
    assert metrics["analyzer_wall_s"] < metrics["full_scan_s"]
    assert 0.0 < metrics["incremental_vs_full_ratio"] < 1.0
    assert metrics["peak_memory_bytes"] < BOUNDED_PEAK_MEMORY_BYTES
    # The measured runs are equivalence-checked inside measure().
    assert metrics["equivalences_checked"] == 2


def test_benchmark_is_repeatable_on_same_fixture() -> None:
    first = bench.measure(SCRATCH / "repeat", files=8, reps=2)
    second = bench.measure(SCRATCH / "repeat", files=8, reps=2)
    for key in bench.GATED_METRICS:
        assert first[key] > 0 and second[key] > 0, key


def test_compare_reports_no_regression_for_identical_runs() -> None:
    metrics = bench.measure(SCRATCH / "compare", files=8, reps=2)
    assert bench.compare_metrics(metrics, dict(metrics)) == []
