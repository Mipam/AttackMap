"""RunSpec as the only run configuration (AR024/AR025, AC-105/AC-106).

Locks the adapter field mapping (transport ScanRequest / CLI flags / GUI
ScanConfig → spec groups), the frozen-ness of every group, the carrier
threading through ``execute_scan_request`` → ``run_scan``, and the AR025
transport contract: ``ScanRequest`` stays small and feature-free.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from dataclasses import fields as dataclass_fields
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
from attackmap.pipeline import RunState
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


def test_runspec_from_scan_request_mirrors_transport_only():
    """AR025: the request carries transport; from_scan_request mirrors it."""
    request = ScanRequest(
        repo_paths=[Path("repo")],
        output=Path("reports"),
        output_format="json",
        run_id="run-1",
        max_workers=4,
        fleet_supervised=True,
        fleet_timeout_seconds=300,
        fleet_input_byte_budget=1024,
        analyzers=[_NamedAnalyzer()],
    )
    spec = RunSpec.from_scan_request(request)
    assert spec == RunSpec(
        analyzer=AnalyzerSelection(analyzers=("node-atproto",)),
        fleet=FleetSpec(max_workers=4, supervised=True, timeout_seconds=300, input_byte_budget=1024),
        output_format="json",
        run_id="run-1",
    )


def test_runspec_scan_request_stays_small_and_feature_free():
    """AC-105 (AR025 step 3): transport only — ≤ 20 fields, no feature flags."""
    feature_flag_names = {
        "recall", "cve", "incremental", "no_suppress", "suppress_file", "suppress_from_ref",
        "allow_pr_suppressions", "strict_suppressions", "strict_analyzers", "isolated_analyzers",
        "allow_untrusted_analyzers", "secrets_history", "llm", "llm_provider", "llm_model",
        "llm_effort", "llm_backend", "llm_speed", "desktop_ai_mode", "hunt", "verify",
        "verify_votes", "hunt_lenses", "hunt_rounds", "hunt_budget", "remediate", "triage",
        "ai_limits", "time_budget_seconds", "baseline", "diff_output", "fail_on_new_high",
        "fail_on_new_suppression", "pr_comment", "progress_format", "no_progress",
    }
    names = [item.name for item in dataclass_fields(ScanRequest)]
    assert len(names) <= 20
    assert not set(names) & feature_flag_names


def test_runspec_from_cli_flags_round_trip():
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
        "llm_effort": "high",
        "llm_backend": "api",
        "llm_speed": "fast",
        "hunt": True,
        "verify": True,
        "verify_votes": 5,
        "hunt_lenses": 2,
        "hunt_rounds": 3,
        "hunt_budget": 100,
        "remediate": True,
        "triage": True,
        "ai_max_calls": 16,
        "ai_output_tokens": 1000,
        "ai_timeout_seconds": 120,
        "fleet_workers": 3,
        "format": "json",
        "progress_format": "json",
        "no_progress": True,
        "atomic_output": False,
        "run_id": "cli-1",
        "baseline": "base.json",
        "diff_output": "diff.md",
        "fail_on_new_high": True,
        "fail_on_new_suppression": True,
        "pr_comment": "pr.md",
        "no_suppress": True,
        "suppress_file": "sup.yaml",
        "suppress_from_ref": "main",
        "allow_pr_suppressions": True,
        "strict_suppressions": True,
        "strict_analyzers": True,
        "isolated_analyzers": True,
        "allow_untrusted_analyzers": True,
        "incremental": True,
    })
    assert spec == RunSpec(
        analyzer=AnalyzerSelection(
            modules=("node-atproto", "php-laminas"),
            install_missing=True,
            allow_untrusted=True,
            strict=True,
            isolated=True,
        ),
        features=FeatureFlags(
            recall=True,
            cve=True,
            incremental=True,
            no_suppress=True,
            suppress_file="sup.yaml",
            suppress_from_ref="main",
            allow_pr_suppressions=True,
            strict_suppressions=True,
            secrets_history=7,
        ),
        budget=BudgetSpec(time_budget_seconds=120),
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
            max_calls=16,
            output_tokens=1000,
            timeout_seconds=120,
        ),
        fleet=FleetSpec(max_workers=3),
        output_format="json",
        progress_format="json",
        no_progress=True,
        atomic_output=False,
        run_id="cli-1",
        baseline="base.json",
        diff_output="diff.md",
        fail_on_new_high=True,
        fail_on_new_suppression=True,
        pr_comment="pr.md",
    )


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


class _NamedAnalyzer:
    name = "node-atproto"


class _FakeState:
    exit_code = 0
    scan = object()
    findings: ClassVar[list] = []
    paths: ClassVar[list] = []
    suppressed: ClassVar[list] = []


def test_runspec_carrier_field_on_run_state():
    assert RunState(spec=RunSpec()).spec == RunSpec()


def test_runspec_no_feature_flag_env_writes():
    """AC-106/AR026: no ``os.environ[...] = ...`` writes anywhere in the engine.

    Feature configuration travels on RunSpec (and fleet worker argv), never
    through ambient environment mutation; documented env *reads* stay.
    """
    import ast

    root = Path(__file__).resolve().parents[2] / "src" / "attackmap"
    offenders: list[str] = []
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                targets = node.targets
            elif isinstance(node, (ast.AugAssign, ast.AnnAssign)):
                targets = [node.target]
            else:
                continue
            for target in targets:
                if (isinstance(target, ast.Subscript)
                        and isinstance(target.value, ast.Attribute)
                        and target.value.attr == "environ"
                        and isinstance(target.value.value, ast.Name)
                        and target.value.value.id == "os"):
                    offenders.append(f"{path.relative_to(root.parent.parent)}:{node.lineno}")
    assert offenders == []


def test_runspec_threads_through_execute_scan_request(monkeypatch):
    from attackmap import scan_service

    captured: dict = {}
    monkeypatch.setattr(scan_service, "ensure_output_dir", lambda path, mark=False: path)

    def _fake_run_scan(spec, **kwargs):
        captured["spec"] = spec
        captured["kwargs"] = kwargs
        return _FakeState()

    monkeypatch.setattr(scan_service, "run_scan", _fake_run_scan)
    request = ScanRequest(repo_paths=[Path("repo")], output=Path("reports"),
                          run_id="carrier-1",
                          spec=RunSpec(run_id="carrier-1", atomic_output=False))
    summary = execute_scan_request(request)
    assert summary.exit_code == 0
    assert isinstance(request.spec, RunSpec)
    assert request.spec.run_id == "carrier-1"
    assert captured["spec"] is request.spec
    assert captured["kwargs"]["repo_path"] == Path("repo")
    assert captured["kwargs"]["output"] == Path("reports")


def test_runspec_threads_through_fleet_serial(monkeypatch):
    from attackmap import scan_service

    captured: dict = {}
    request = ScanRequest(repo_paths=[Path("r1"), Path("r2")], output=Path("out"),
                          echo=lambda *args, **kwargs: None)

    def _fake_run_scan(spec, **kwargs):
        captured.setdefault("specs", []).append(spec)
        return _FakeState()

    monkeypatch.setattr(scan_service, "run_scan", _fake_run_scan)
    fleet = FleetScan()
    request.spec = RunSpec(run_id="fleet-1")
    _run_fleet_serial(request, [], fleet, Path("out"))
    assert captured["specs"] == [RunSpec(run_id="fleet-1"), RunSpec(run_id="fleet-1")]


def test_runspec_pipeline_run_scan_reads_spec_groups(monkeypatch):
    """AR025: the pipeline consumes spec groups (spot-check the AI gate)."""
    from attackmap import pipeline

    calls: dict = {}

    def _fake_published(spec, **kwargs):
        calls["spec"] = spec
        calls["kwargs"] = kwargs
        return RunState(spec=spec)

    monkeypatch.setattr(pipeline, "_run_scan_published", _fake_published)
    monkeypatch.setattr(pipeline, "AiBudget", lambda **kwargs: pytest.fail("Budget without AI"))
    spec = RunSpec()  # no AI features: no budget scope is created
    assert pipeline.run_scan(spec, repo_path=Path("repo"), output=Path("out")).spec is spec
    assert calls["kwargs"]["repo_path"] == Path("repo")
