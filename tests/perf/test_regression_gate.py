"""Perf regression-gate tests (AR084 / AC-405): the > 20% comparison rule.

The gate is exercised on synthetic, constructed metric dicts — no timing, no
fixtures, no flakiness. This is the only place the hard-fail rule runs; the
benchmark CLI itself defaults to record-and-warn.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.perf

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_bench() -> object:
    spec = importlib.util.spec_from_file_location(
        "bench_analyzers", REPO_ROOT / "tools" / "bench_analyzers.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


bench = _load_bench()

BASELINE = {
    "analyzer_wall_s": 1.0,
    "full_scan_s": 10.0,
    "incremental_scan_s": 0.5,
    "peak_memory_bytes": 100_000_000,
}


def _current(**overrides: float) -> dict[str, object]:
    current = dict(BASELINE)
    current.update(overrides)
    return current


def test_no_regression_when_within_20_percent() -> None:
    current = _current(
        analyzer_wall_s=BASELINE["analyzer_wall_s"] * 1.20,  # exactly 20%: not a regression
        full_scan_s=BASELINE["full_scan_s"] * 1.10,
        incremental_scan_s=BASELINE["incremental_scan_s"] * 0.9,
        peak_memory_bytes=BASELINE["peak_memory_bytes"],  # unchanged
    )
    assert bench.compare_metrics(BASELINE, current) == []


def test_regression_fails_above_20_percent() -> None:
    current = _current(full_scan_s=BASELINE["full_scan_s"] * 1.25)
    regressions = bench.compare_metrics(BASELINE, current)
    assert len(regressions) == 1
    assert "full_scan_s" in regressions[0]


def test_every_gated_metric_is_gated() -> None:
    for key in bench.GATED_METRICS:
        current = _current(**{key: BASELINE[key] * 1.5})
        regressions = bench.compare_metrics(BASELINE, current)
        assert len(regressions) == 1, key
        assert key in regressions[0], key


def test_improvement_and_exact_threshold_are_not_regressions() -> None:
    improved = _current(full_scan_s=BASELINE["full_scan_s"] * 0.5)
    assert bench.compare_metrics(BASELINE, improved) == []
    exact = _current(peak_memory_bytes=BASELINE["peak_memory_bytes"] * 1.20)
    assert bench.compare_metrics(BASELINE, exact) == []


def test_metrics_missing_from_either_side_are_skipped() -> None:
    sparse_baseline = {"full_scan_s": 10.0}  # other gated metrics absent
    current = _current(full_scan_s=30.0, analyzer_wall_s=99.0)
    regressions = bench.compare_metrics(sparse_baseline, current)
    assert regressions == ["full_scan_s: 30.0 regressed > 20% vs baseline 10.0"]


def test_zero_baseline_does_not_divide_or_flag() -> None:
    current = _current(analyzer_wall_s=1000.0)
    assert bench.compare_metrics({"analyzer_wall_s": 0.0}, current) == []
