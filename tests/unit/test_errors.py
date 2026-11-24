"""AR012 / AC-012 — typed error taxonomy export and no-swallow handler checks.

Complements ``test_error_taxonomy.py`` (which covers the class semantics):
this file pins the canonical ``attackmap.errors`` export path, the leaf-module
(no import-cycle) shape, and the raised-and-caught paths in the modules the
AR012 lease touched — including the no-swallow rule (a handler that catches
without recording is a failure).
"""

from __future__ import annotations

import ast
import builtins
import inspect
import logging
import re
import time
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar

import pytest

import attackmap.errors as errors
import attackmap.foundation.errors as foundation_errors
from attackmap.extraction import analyzer_host
from attackmap.orchestration import analyzers, pipeline, scan_service
from attackmap.surfaces.ui import server
from attackmap.surfaces.ui.api import artifacts as ui_artifacts
from attackmap.surfaces.ui.api import scans as ui_scans

TAXONOMY = [
    errors.AttackMapError,
    errors.AnalyzerLoadError,
    errors.AnalyzerRuntimeError,
    errors.UntrustedAnalyzerError,
    errors.BudgetExpired,
    errors.UnsupportedInFleet,
    errors.ArtifactIntegrityError,
    errors.FleetAdmissionError,
]


def test_taxonomy_is_exported_from_canonical_path():
    for cls in TAXONOMY:
        assert cls.__name__ in errors.__all__
        assert getattr(foundation_errors, cls.__name__) is cls
        assert cls.code and isinstance(cls.code, str)
        assert cls.remediation and isinstance(cls.remediation, str)


def test_every_error_carries_code_detail_and_remediation():
    exc = errors.AttackMapError("detail text", code="c", remediation="do x")
    assert exc.code == "c" and exc.detail == "detail text" and exc.remediation == "do x"
    assert errors.BudgetExpired("stage").code == "budget_expired"
    assert errors.UnsupportedInFleet("feature", "reason").detail
    assert errors.FleetAdmissionError("bad fleet request").code == "fleet_admission"
    assert errors.ArtifactIntegrityError("bad checksum").code == "artifact_integrity"


def test_errors_module_is_an_import_cycle_leaf():
    """errors.py may only import __future__ and attackmap.foundation.* so any
    layer can import it (this is what keeps the architecture cycle gate green)."""
    source_file = Path(inspect.getsourcefile(errors) or "")
    tree = ast.parse(source_file.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            raise AssertionError(f"errors.py must not use plain imports: {ast.dump(node)}")
        if isinstance(node, ast.ImportFrom):
            assert node.module in {"__future__", "attackmap.foundation.errors"}, node.module


def test_discover_installed_analyzers_records_entry_points_failure(monkeypatch, caplog):
    """The entry_points() catch: breakage is recorded in the discovery
    catalog (or re-raised without a catalog) — never swallowed."""

    def _boom():
        raise RuntimeError("broken metadata")

    from attackmap.orchestration.analyzer_catalog import AnalyzerDiscoveryCollector

    monkeypatch.setattr(analyzers, "entry_points", _boom)
    collector = AnalyzerDiscoveryCollector(trusted_only=False)
    found = analyzers.discover_installed_analyzers(catalog=collector)
    assert found == []
    assert collector.errors, "handler must record the failure in the catalog"
    assert collector.errors[0]["stage"] == "entry_points"
    # Without a catalog the same failure propagates instead of vanishing.
    with pytest.raises(RuntimeError):
        analyzers.discover_installed_analyzers()


def test_load_failure_of_entry_point_is_recorded_not_swallowed(monkeypatch, caplog):
    def _boom():
        raise ImportError("cannot import plugin")

    ep = SimpleNamespace(name="broken-plugin", load=_boom)
    with caplog.at_level(logging.WARNING, logger="attackmap.orchestration.analyzers"):
        assert analyzers._load_discovered_analyzer(ep) is None
    assert any("Failed to load analyzer entry point" in r.message for r in caplog.records)


def test_slot_analyzer_keeps_loading_and_records_origin_failure(caplog):
    """A slotted analyzer cannot retain discovery-origin attributes; the
    narrow catch must keep it loadable and log the dropped origin."""

    class SlottedAnalyzer:
        __slots__ = ()
        name = "slotted-analyzer"
        metadata: ClassVar[dict] = {"name": "slotted-analyzer"}

        def analyze(self, root):
            return None

    ep = SimpleNamespace(name="slotted-analyzer", load=lambda: SlottedAnalyzer())
    with caplog.at_level(logging.DEBUG, logger="attackmap.orchestration.analyzers"):
        loaded = analyzers._load_discovered_analyzer(ep)
    assert loaded is not None
    assert any("Could not retain discovery origin" in r.message for r in caplog.records)


def test_analyzer_applicability_records_detect_failure():
    class BadDetect:
        name = "bad-detect"

        def detect(self, root):
            raise ValueError("no detect")

    ok, error_type = analyzers._analyzer_applicability(BadDetect(), Path("."))
    assert ok is False and error_type == "ValueError"


def test_analyzer_host_invalid_result_is_a_named_partial(tmp_path):
    """The narrowed ValidationError catch still classifies a malformed worker
    result as a named partial-coverage outcome (analyzer_errors record)."""
    (tmp_path / analyzer_host._RESULT_FILE).write_text("{}", encoding="utf-8")
    outcome = analyzer_host._classify("worker-analyzer", tmp_path, {"code": 0, "tail": ""}, 0, 1024)
    assert outcome.error_type == analyzer_host.HOST_INVALID_OUTPUT
    assert "partial coverage" in (outcome.limitation or "")


def test_worker_loader_records_every_attempt():
    """The worker's loader fallback chain must surface all load attempts in
    the raised error even when every loader fails."""
    args = SimpleNamespace(
        entry_point=None, entry_point_value=None, distribution=None,
        distribution_version=None, analyzer_module="no.such.module",
        analyzer_file=None, analyzer_attr=None,
    )
    with pytest.raises(RuntimeError) as err:
        analyzer_host._load_analyzer(args)
    assert "module: ModuleNotFoundError" in str(err.value)


def test_ui_refresh_missing_records_failure(monkeypatch, caplog):
    """_refresh_missing used to swallow silently; the failure must be logged
    (recorded) while the GUI keeps working with an empty suggestion list."""

    def _boom(repo):
        raise RuntimeError("suggest backend broken")

    monkeypatch.setattr("attackmap.surfaces.suggest.detect_ecosystems", _boom)
    app = server.LoopbackApp()
    app.repos = [Path(".")]
    with caplog.at_level(logging.WARNING, logger="attackmap.surfaces.ui.server"):
        server._refresh_missing(app)
    assert app.missing == []
    assert any("Missing-analyzer suggestions failed" in r.message for r in caplog.records)


def test_ui_cancel_failure_is_surfaced_as_app_error():
    """The cancel cleanup catch converts a runner.cancel() failure into a
    visible app.error instead of a silent False."""
    from attackmap.surfaces.ui.run_state import GuiRunState

    class BrokenRunner:
        def cancel(self):
            raise RuntimeError("cancel blew up")

    app = server.LoopbackApp()
    app._run_state = GuiRunState.RUNNING
    app.runner = BrokenRunner()
    server._request_scan_cancel(app)
    # The cleanup runs on a daemon thread; wait for it to record the error.
    for _ in range(200):
        if app.error is not None:
            break
        time.sleep(0.01)
    assert "Cancellation could not verify" in (app.error or "")


def test_ui_pick_folders_without_tkinter_is_recorded(monkeypatch, caplog):
    """No-tkinter hosts must get an empty list plus a debug record, not a
    silent swallow."""
    real_import = builtins.__import__

    def _no_tk(name, *args, **kwargs):
        if name == "tkinter" or name.startswith("tkinter."):
            raise ImportError("No module named 'tkinter'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _no_tk)
    # AR063: _pick_folders moved to the api package with the handlers.
    with caplog.at_level(logging.DEBUG, logger="attackmap.surfaces.ui.api.scans"):
        assert server._pick_folders() == []
    assert any("tkinter is unavailable" in r.message for r in caplog.records)


def test_no_new_broad_except_in_lease_files():
    """Static tripwire for the AR012 lease: every remaining
    ``except Exception``/``except BaseException`` must be one of the
    reviewed, record-or-reraise handlers counted here. Any new broad catch
    fails this test until it is individually justified and counted.

    Reviewed handlers (each records a limitation/analyzer_error/failure list
    or cleans up and re-raises — none swallow):
      analyzers.py 7  — entry_points->catalog.errors; load/init/metadata ->
                        catalog.failed + warning; install wrap (re-raise as
                        ValueError); analysis loop -> ledger + AnalyzerError;
                        detect() -> warning + error_type
      analyzer_host.py 4 — loader fallback chain (every attempt appended and
                        surfaced in the raised RuntimeError); worker crash ->
                        status.json error record + non-zero exit
      scan_service.py 7 — RunSummary.error record; _FleetRepoError wrap
                        (recorded downstream); fleet.failed records x2;
                        3x BaseException supervisor/reservation guards that
                        always re-raise after cleanup
      server.py 0     — handlers extracted to the ui/api package in AR063
                        (the 3 reviewed catches moved, none added):
      api/scans.py 2  — cancel failure -> app.error; refresh_missing warning
      api/artifacts.py 1 — PDF export -> HTTP 400 error body
      pipeline.py 5   — BaseException cleanup guards: diagnostics/event
                        records written, always re-raised
    """
    reviewed = {
        "analyzers.py": 7,
        "analyzer_host.py": 4,
        "scan_service.py": 7,
        "server.py": 0,
        "scans.py": 2,
        "artifacts.py": 1,
        "pipeline.py": 5,
        "errors.py": 0,
    }
    modules = [
        analyzers, analyzer_host, scan_service, server, ui_scans, ui_artifacts,
        pipeline, errors,
    ]
    for module in modules:
        path = Path(inspect.getsourcefile(module) or "")
        count = len(re.findall(r"except (?:Base)?Exception\b", path.read_text(encoding="utf-8")))
        assert count == reviewed[path.name], (path.name, count)
