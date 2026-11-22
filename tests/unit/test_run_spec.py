"""RunSpec configuration carrier (AR024, AC-105): frozen groups and adapters.

RunSpec is a passive, immutable mirror of one scan's configuration. These
tests lock the adapter field mapping (ScanRequest / CLI flags / GUI ScanConfig
→ spec groups), the frozen-ness of every group, and the carrier threading
through ``execute_scan_request`` → ``run_scan`` — without running a real scan.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import ClassVar

import pytest

from attackmap.fleet import FleetScan
from attackmap.orchestration.run_spec import (
    AiSpec,
    AnalyzerSelection,
    BudgetSpec,
    FeatureFlags,
    FleetSpec,
    RunSpec,
)
from attackmap.pipeline import AnalyzeOptions, RunState, ScanAiLimits
from attackmap.scan_service import ScanRequest, _run_fleet_serial, execute_scan_request
from attackmap.ui.config import ScanConfig

# AC-105's contract verify (`pytest -m contract -k runspec`) and the unit leg
# both select this module; every test name carries the "runspec" stem.
pytestmark = [pytest.mark.unit, pytest.mark.contract]


@pytest.mark.parametrize(
    ("instance", "attr", "value"),
    [
        (RunSpec(), "output_format", "json"),
        (AnalyzerSelection(), "modules", ("x",)),
        (FeatureFlags(), "recall", True),
        (BudgetSpec(), "time_budget_seconds", 60),
        (AiSpec(), "enabled", True),
        (FleetSpec(), "max_workers", 2),
    ],
)
def test_runspec_frozen_groups(instance, attr, value):
    with pytest.raises(FrozenInstanceError):
        setattr(instance, attr, value)


def test_runspec_default_scan_request_maps_to_default_spec():
    request = ScanRequest(repo_paths=[Path("repo")], output=Path("reports"))
    assert RunSpec.from_scan_request(request) == RunSpec()


def test_runspec_from_scan_request_round_trip():
    class _Analyzer:
        name = "node-atproto"

    request = ScanRequest(
        repo_paths=[Path("repo")],
        output=Path("reports"),
        output_format="json",
        modules=["node-atproto"],
        analyzers=[_Analyzer()],
        analyzer_profile_id="node-atproto@1.0",
        install_missing=True,
        recall=True,
        cve=True,
        no_suppress=False,
        suppress_file="sup.yaml",
        suppress_from_ref="main",
        allow_pr_suppressions=True,
        strict_suppressions=True,
        strict_analyzers=True,
        isolated_analyzers=True,
        allow_untrusted_analyzers=True,
        incremental=True,
        time_budget_seconds=90,
        progress_format="json",
        no_progress=True,
        secrets_history=5,
        run_id="run-1",
        baseline="base.json",
        diff_output="diff.md",
        fail_on_new_high=True,
        fail_on_new_suppression=True,
        pr_comment="pr.md",
        llm=True,
        llm_provider="openai",
        llm_model="gpt-5-codex",
        llm_effort="high",
        llm_backend="api",
        llm_speed="fast",
        hunt=True,
        verify=True,
        verify_votes=5,
        hunt_lenses=2,
        hunt_rounds=3,
        hunt_budget=100,
        remediate=True,
        triage=True,
        ai_limits=ScanAiLimits(max_calls=9, output_token_limit=1000, timeout_seconds=120),
        max_workers=4,
        fleet_supervised=True,
        fleet_timeout_seconds=300,
        fleet_input_byte_budget=1024,
    )
    spec = RunSpec.from_scan_request(request)
    assert spec == RunSpec(
        analyzer=AnalyzerSelection(
            modules=("node-atproto",),
            analyzers=("node-atproto",),
            profile_id="node-atproto@1.0",
            install_missing=True,
            allow_untrusted=True,
            strict=True,
            isolated=True,
        ),
        features=FeatureFlags(
            recall=True,
            cve=True,
            incremental=True,
            suppress_file="sup.yaml",
            suppress_from_ref="main",
            allow_pr_suppressions=True,
            strict_suppressions=True,
            secrets_history=5,
        ),
        budget=BudgetSpec(time_budget_seconds=90),
        ai=AiSpec(
            enabled=True,
            provider="openai",
            model="gpt-5-codex",
            effort="high",
            backend="api",
            speed="fast",
            hunt=True,
            verify=True,
            verify_votes=5,
            hunt_lenses=2,
            hunt_rounds=3,
            hunt_budget=100,
            remediate=True,
            triage=True,
            max_calls=9,
            output_tokens=1000,
            timeout_seconds=120,
        ),
        fleet=FleetSpec(max_workers=4, supervised=True, timeout_seconds=300, input_byte_budget=1024),
        output_format="json",
        progress_format="json",
        no_progress=True,
        atomic_output=True,
        run_id="run-1",
        baseline="base.json",
        diff_output="diff.md",
        fail_on_new_high=True,
        fail_on_new_suppression=True,
        pr_comment="pr.md",
    )


def test_runspec_from_cli_flags():
    spec = RunSpec.from_cli({
        "module": ["node-atproto", "php-laminas"],
        "analyzer_profile": None,  # None values keep defaults
        "install_missing": True,
        "recall": True,
        "cve": True,
        "secrets_history": 7,
        "time_budget_seconds": 120,
        "llm": True,
        "llm_provider": "openai",
        "llm_model": "gpt-5-codex",
        "hunt": True,
        "verify": True,
        "verify_votes": 5,
        "ai_max_calls": 16,
        "fleet_workers": 3,
        "format": "json",
        "no_progress": True,
        "run_id": "cli-1",
        "baseline": "base.json",
        "fail_on_new_high": True,
    })
    assert spec.analyzer == AnalyzerSelection(
        modules=("node-atproto", "php-laminas"), install_missing=True)
    assert spec.features.recall and spec.features.cve
    assert spec.features.secrets_history == 7
    assert spec.budget == BudgetSpec(time_budget_seconds=120)
    assert spec.ai.enabled and spec.ai.hunt and spec.ai.verify
    assert spec.ai.provider == "openai" and spec.ai.model == "gpt-5-codex"
    assert spec.ai.verify_votes == 5 and spec.ai.max_calls == 16
    assert spec.fleet.max_workers == 3
    assert spec.output_format == "json" and spec.no_progress
    assert spec.run_id == "cli-1" and spec.baseline == "base.json"
    assert spec.fail_on_new_high


def test_runspec_from_cli_rejects_unknown_flag():
    with pytest.raises(ValueError, match="Unknown CLI option for RunSpec: 'nonsense'"):
        RunSpec.from_cli({"nonsense": 1})


def test_runspec_from_gui_config():
    config = ScanConfig(
        repos=[Path("repo")],
        output=Path("reports"),
        run_cve=True,
        modules=["auto", "node-atproto"],
        llm_mode="huntVerify",
        provider="claude",
        model="claude-opus-4-8",
        effort="high",
        fast=True,
        recall=True,
        no_suppress=True,
        suppress_file=Path("sup.yaml"),
        jury={"verifyVotes": 5, "lenses": 2},
        baseline=Path("base.json"),
        diff_output=Path("diff.md"),
        fail_on_new_high=True,
        pr_comment=Path("pr.md"),
        run_id="gui-1",
    )
    spec = RunSpec.from_gui(config)
    assert spec.analyzer.modules == ("node-atproto",)  # "auto" is dropped, like cli_args
    assert spec.features.cve and spec.features.recall and spec.features.no_suppress
    assert spec.features.suppress_file == "sup.yaml"
    assert spec.ai.hunt and spec.ai.verify
    assert spec.ai.verify_votes == 5 and spec.ai.hunt_lenses == 2 and spec.ai.hunt_rounds == 1
    assert spec.ai.hunt_budget == 0  # jury defaults mirror JURY_DEFAULTS
    assert spec.ai.model == "claude-opus-4-8" and spec.ai.effort == "high"
    assert spec.ai.speed == "fast"
    assert spec.baseline == "base.json" and spec.diff_output == "diff.md"
    assert spec.fail_on_new_high and spec.pr_comment == "pr.md"
    assert spec.run_id == "gui-1"
    # The GUI argv always requests --format all --progress-format json.
    assert spec.output_format == "all" and spec.progress_format == "json"


def test_runspec_gui_non_ai_mode_disables_ai():
    config = ScanConfig(repos=[Path("repo")], output=Path("reports"), llm_mode="none",
                        provider="openai")
    spec = RunSpec.from_gui(config)
    assert not spec.ai.enabled and not spec.ai.hunt and not spec.ai.verify
    assert not spec.ai.remediate and not spec.ai.triage
    assert spec.ai.provider == "openai"  # the configured provider is still mirrored


class _FakeState:
    exit_code = 0
    scan = object()
    findings: ClassVar[list] = []
    paths: ClassVar[list] = []
    suppressed: ClassVar[list] = []


def test_runspec_carrier_field_on_run_state():
    options = AnalyzeOptions(repo_path=Path("repo"), output=Path("reports"))
    assert RunState(options=options).run_spec is None
    assert RunState(options=options, run_spec=RunSpec(run_id="r")).run_spec == RunSpec(run_id="r")


def test_runspec_threads_through_execute_scan_request(monkeypatch):
    from attackmap import scan_service

    captured: dict = {}
    monkeypatch.setattr(scan_service, "ensure_output_dir", lambda path, mark=False: path)

    def _fake_run_scan(options):
        captured["run_spec"] = options.run_spec
        return _FakeState()

    monkeypatch.setattr(scan_service, "run_scan", _fake_run_scan)
    request = ScanRequest(repo_paths=[Path("repo")], output=Path("reports"),
                          run_id="carrier-1", atomic_output=False)
    assert getattr(request, "run_spec", None) is None  # built by execute_scan_request
    summary = execute_scan_request(request)
    assert summary.exit_code == 0
    assert isinstance(request.run_spec, RunSpec)
    assert request.run_spec.run_id == "carrier-1"
    assert captured["run_spec"] is request.run_spec  # reached run_scan via AnalyzeOptions


def test_runspec_threads_through_fleet_serial(monkeypatch):
    from attackmap import scan_service

    captured: dict = {}
    request = ScanRequest(repo_paths=[Path("r1"), Path("r2")], output=Path("out"),
                          atomic_output=False, echo=lambda *args, **kwargs: None)

    def _fake_run_scan(options):
        captured.setdefault("specs", []).append(options.run_spec)
        return _FakeState()

    monkeypatch.setattr(scan_service, "run_scan", _fake_run_scan)
    fleet = FleetScan()
    request.run_spec = RunSpec(run_id="fleet-1")
    _run_fleet_serial(request, [], fleet, Path("out"))
    assert captured["specs"] == [request.run_spec, request.run_spec]
