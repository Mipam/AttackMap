"""Serial vs parallel analyzer equivalence (AR027, AC-107/AC-108).

AC-108: parallel execution must be deterministic. The same fixture repo is
scanned with ``workers=1`` and ``workers=4``; the normalized results —
routes with their winning source analyzer, the other signal families, the
analyzer-error list, files-scanned, and the analyzer ledger order — must be
identical. Merge order stays the resolved ``(priority, name)`` plan order in
both runs; completion order never reaches the merge.

Two duplicate-route plugins at different priorities make the ordering gate
explicit: merge is first-seen-wins by plan order, so the low-priority
plugin's route wins in BOTH runs. Under completion-order merging (the bug
this test forbids) the high-priority plugin would win whenever it finished
first.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from attackmap import analyzers as analyzers_mod
from attackmap.analyzer_host import HostLimits
from attackmap.analyzers import BuiltinPythonWebAnalyzer, analyze_repository
from attackmap.orchestration.run_spec import AnalyzerSelection, RunSpec, SchedulerSpec
from attackmap.pipeline import run_scan

APP = (
    "from flask import Flask\n"
    "app = Flask(__name__)\n\n"
    "@app.route('/users/<int:user_id>')\n"
    "def get_user(user_id):\n"
    "    return {'id': user_id}\n"
)


def _plugin_source(name: str, priority: int, payload: str) -> str:
    class_name = "".join(part.capitalize() for part in name.split("-")) + "Analyzer"
    return (
        "from types import SimpleNamespace\n"
        f"METADATA = SimpleNamespace(\n"
        f"    name={name!r}, display_name={name!r}, version='0.1.0',\n"
        f"    description='equivalence fixture', scope='tests only', targets=[], languages=[],\n"
        f"    priority={priority}, experimental=True, enabled_by_default=True,\n"
        f")\n"
        f"class {class_name}:\n"
        "    metadata = METADATA\n\n"
        "    @property\n"
        "    def name(self):\n"
        "        return self.metadata.name\n\n"
        "    def detect(self, root):\n"
        "        return True\n\n"
        "    def analyze(self, root):\n"
        f"        return {payload}\n"
    )


def _load_plugin(plugins: Path, file_name: str, class_name: str):
    module_name = f"parallel_eq_{Path(file_name).stem}"
    spec = importlib.util.spec_from_file_location(module_name, plugins / file_name)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module  # standard pattern; also lets the host locate the file
    spec.loader.exec_module(module)
    return getattr(module, class_name)()


@pytest.fixture()
def iso_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(APP, encoding="utf-8")
    return repo


@pytest.fixture()
def plugins(tmp_path: Path) -> list:
    folder = tmp_path / "plugins"
    folder.mkdir()
    # alpha (priority 10) must win the shared /dup route in plan order;
    # beta (priority 200) emits the same route and must lose the dedup.
    (folder / "alpha.py").write_text(_plugin_source("alpha", 10, (
        "{'routes': [{'path': '/dup', 'method': 'GET', 'file': 'shared.py'},\n"
        "            {'path': '/alpha', 'method': 'GET', 'file': 'plugin_a.py'}],\n"
        " 'auth_hints': [{'hint': 'token verified in alpha', 'file': 'plugin_a.py'}]}\n"
    )), encoding="utf-8")
    (folder / "beta.py").write_text(_plugin_source("beta", 200, (
        "{'routes': [{'path': '/dup', 'method': 'GET', 'file': 'shared.py'},\n"
        "            {'path': '/beta', 'method': 'GET', 'file': 'plugin_b.py'}]}\n"
    )), encoding="utf-8")
    (folder / "gamma.py").write_text(_plugin_source("gamma", 300, (
        "{'routes': [{'path': '/gamma', 'method': 'POST', 'file': 'plugin_g.py'}],\n"
        " 'auth_hints': [{'hint': 'admin check in gamma', 'file': 'plugin_g.py'}]}\n"
    )), encoding="utf-8")
    return [
        _load_plugin(folder, "alpha.py", "AlphaAnalyzer"),
        _load_plugin(folder, "beta.py", "BetaAnalyzer"),
        _load_plugin(folder, "gamma.py", "GammaAnalyzer"),
    ]


def _limits() -> HostLimits:
    return HostLimits(timeout_seconds=60.0, stream_bytes=8 * 1024 * 1024,
                      result_bytes=64 * 1024 * 1024, memory_bytes=0)


def _normalized(scan) -> dict:
    """Timing-free normalized fingerprint of a merged analyzer result."""
    ledger = scan.analyzer_run_ledger
    return {
        "routes": sorted(
            (r.path, r.method, r.file, r.source_analyzer) for r in scan.routes
        ),
        "auth_hints": sorted(
            (h.hint, h.file, h.source_analyzer) for h in scan.auth_hints
        ),
        "files_scanned": scan.files_scanned,
        "analyzer_errors": sorted(
            (e.analyzer, e.error_type) for e in scan.analyzer_errors
        ),
        "ledger_order": [(row.name, row.priority, row.execution, row.execution_mode)
                         for row in ledger.entries],
        "limitations": sorted(scan.limitations),
    }


def test_parallel_scheduler_engaged_only_above_serial(iso_repo: Path, plugins: list,
                                                      monkeypatch: pytest.MonkeyPatch):
    """Prove the wiring: workers=1 never schedules, workers=4 schedules the
    isolated group through the bounded pool."""
    calls: list[dict] = []
    real_run_group = analyzers_mod.run_group

    def spy(jobs, *, workers=1, on_start=None):
        calls.append({"workers": workers, "names": [name for name, _ in jobs]})
        return real_run_group(jobs, workers=workers, on_start=on_start)

    monkeypatch.setattr(analyzers_mod, "run_group", spy)
    analyzers = [BuiltinPythonWebAnalyzer(), *plugins]
    scan = analyze_repository(iso_repo, analyzers=analyzers, isolated_analyzers=True,
                              isolated_limits=_limits(), workers=1)
    assert calls == [], "workers=1 must keep the historical serial loop (no pool)"
    assert scan.analyzer_errors == []

    scan = analyze_repository(iso_repo, analyzers=analyzers, isolated_analyzers=True,
                              isolated_limits=_limits(), workers=4)
    assert len(calls) == 1 and calls[0]["workers"] == 4
    # Only the third-party group is scheduled; built-ins stay in-process.
    assert sorted(calls[0]["names"]) == ["alpha", "beta", "gamma"]
    assert scan.analyzer_errors == []
    modes = {row.name: row.execution_mode for row in scan.analyzer_run_ledger.entries}
    assert modes == {"alpha": "isolated", "beta": "isolated", "gamma": "isolated",
                     "python-web": "in_process"}


def test_analyze_repository_serial_parallel_equivalence(iso_repo: Path, plugins: list):
    analyzers = [BuiltinPythonWebAnalyzer(), *plugins]
    serial = analyze_repository(iso_repo, analyzers=analyzers, isolated_analyzers=True,
                                isolated_limits=_limits(), workers=1)
    parallel = analyze_repository(iso_repo, analyzers=analyzers, isolated_analyzers=True,
                                  isolated_limits=_limits(), workers=4)
    assert _normalized(serial) == _normalized(parallel)

    # The ordering gate itself: plan order (priority, name) decides the
    # duplicate-route winner in BOTH runs, not completion order.
    dup = {r.source_analyzer: r for r in serial.routes if r.path == "/dup"}
    assert set(dup) == {"alpha"}, "first-seen-wins by plan order"
    assert [row.name for row in serial.analyzer_run_ledger.entries] == \
           [row.name for row in parallel.analyzer_run_ledger.entries]
    assert [row.name for row in serial.analyzer_run_ledger.entries] == \
           ["alpha", "python-web", "beta", "gamma"]


def test_run_scan_serial_parallel_equivalence(iso_repo: Path, plugins: list, tmp_path: Path):
    """End to end through the pipeline: findings, routes and ledger order
    identical for RunSpec workers=1 vs workers=4 (AC-108 normalized form)."""
    analyzers = [BuiltinPythonWebAnalyzer(), *plugins]

    def _run(workers: int):
        spec = RunSpec(no_progress=True, analyzer=AnalyzerSelection(isolated=True),
                       scheduler=SchedulerSpec(workers=workers))
        return run_scan(spec, repo_path=iso_repo, output=tmp_path / f"out-{workers}",
                        analyzers=analyzers)

    serial = _run(1)
    parallel = _run(4)
    assert serial.exit_code == 0 and parallel.exit_code == 0

    assert [f.model_dump(mode="json") for f in serial.findings] == \
           [f.model_dump(mode="json") for f in parallel.findings]
    assert sorted((r.path, r.method, r.file, r.source_analyzer)
                  for r in serial.scan.routes) == \
           sorted((r.path, r.method, r.file, r.source_analyzer)
                  for r in parallel.scan.routes)
    assert _normalized(serial.scan) == _normalized(parallel.scan)
