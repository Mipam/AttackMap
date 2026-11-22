"""Per-feature fleet admission and worker wiring (AR069, AC-310).

Every ScanRequest feature either works in a fleet worker child (wired onto
the child's own argv, or re-scoped per child) or is refused at admission with
a typed :class:`UnsupportedInFleet` naming the feature and the reason. This
module pins the admission decision; ``tests/integration/test_fleet_parity.py``
pins the end-to-end behavior over real fleet runs.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from attackmap.foundation.errors import UnsupportedInFleet
from attackmap.models import ScanResult
from attackmap.orchestration import scan_service
from attackmap.orchestration.fleet import FleetScan
from attackmap.orchestration.pipeline import RunState
from attackmap.orchestration.run_spec import AiSpec, FeatureFlags, RunSpec
from attackmap.orchestration.scan_service import (
    ScanRequest,
    _fleet_feature_admission,
    execute_scan_request,
)


def _fleet_request(tmp_path: Path, spec: RunSpec | None = None) -> ScanRequest:
    repos = [tmp_path / "alpha", tmp_path / "beta"]
    for repo in repos:
        repo.mkdir(exist_ok=True)
    return ScanRequest(repo_paths=repos, output=tmp_path / "out", spec=spec)


# The supported matrix mirrors scan_service._fleet_feature_admission's
# docstring: features wired through the per-repo child argv (or re-scoped
# per child), with the budget-gated AiSpec traveling intact.
SUPPORTED_SPECS: dict[str, RunSpec] = {
    "llm": RunSpec(ai=AiSpec(enabled=True)),
    "hunt": RunSpec(ai=AiSpec(hunt=True)),
    "remediate": RunSpec(ai=AiSpec(remediate=True)),
    "triage": RunSpec(ai=AiSpec(triage=True)),
    "baseline": RunSpec(baseline="baseline.json"),
    "pr_comment": RunSpec(pr_comment="pr-comment-shared.md"),
    "secrets_history": RunSpec(features=FeatureFlags(secrets_history=5)),
}

REFUSED_SPECS: dict[str, RunSpec] = {
    "--diff-output": RunSpec(diff_output="diff.md"),
    "--fail-on-new-high": RunSpec(fail_on_new_high=True),
    "--fail-on-new-suppression": RunSpec(fail_on_new_suppression=True),
}


@pytest.mark.parametrize("feature", sorted(SUPPORTED_SPECS))
def test_supported_features_pass_fleet_admission(tmp_path: Path, feature: str) -> None:
    assert _fleet_feature_admission(_fleet_request(tmp_path, SUPPORTED_SPECS[feature])) == []


@pytest.mark.parametrize("feature", sorted(REFUSED_SPECS))
def test_refused_features_raise_typed_admission_error(tmp_path: Path, feature: str) -> None:
    refusals = _fleet_feature_admission(_fleet_request(tmp_path, REFUSED_SPECS[feature]))
    assert len(refusals) == 1
    refusal = refusals[0]
    assert isinstance(refusal, UnsupportedInFleet)
    assert refusal.feature == feature
    assert refusal.reason
    assert refusal.feature in str(refusal)
    assert refusal.code == "unsupported_in_fleet"


@pytest.mark.parametrize("feature", sorted(REFUSED_SPECS))
def test_refusal_happens_before_any_repository_is_scanned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, feature: str,
) -> None:
    def unexpected(request, analyzers):
        raise AssertionError("fleet dispatch ran past a typed admission refusal")

    monkeypatch.setattr(scan_service, "_run_fleet", unexpected)
    with pytest.raises(UnsupportedInFleet):
        execute_scan_request(_fleet_request(tmp_path, REFUSED_SPECS[feature]))


@pytest.mark.parametrize("feature", sorted(SUPPORTED_SPECS))
def test_supported_features_reach_fleet_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, feature: str,
) -> None:
    dispatched: list[ScanRequest] = []

    def fake_run_fleet(request, analyzers):
        dispatched.append(request)
        return scan_service.RunSummary(exit_code=0)

    monkeypatch.setattr(scan_service, "_run_fleet", fake_run_fleet)
    summary = execute_scan_request(_fleet_request(tmp_path, SUPPORTED_SPECS[feature]))
    assert summary.exit_code == 0
    assert len(dispatched) == 1


# ---------------------------------------------------------------------------
# child worker argv wiring (parallel workers)
# ---------------------------------------------------------------------------


def _argv_tokens(request: ScanRequest, repo_out: Path) -> list[str]:
    return scan_service._run_fleet_repo_argv(request, request.repo_paths[0], repo_out, [])


@pytest.mark.parametrize("feature,flag", [
    ("llm", "--llm"), ("hunt", "--hunt"), ("remediate", "--remediate"),
    ("triage", "--triage"),
])
def test_ai_switches_reach_child_argv(tmp_path: Path, feature: str, flag: str) -> None:
    request = _fleet_request(tmp_path, SUPPORTED_SPECS[feature])
    assert flag in _argv_tokens(request, tmp_path / "child-out")


def test_full_ai_spec_reaches_child_argv(tmp_path: Path) -> None:
    spec = RunSpec(ai=AiSpec(enabled=True, provider="openai", model="m-1", effort="high",
                             backend="api", speed="fast", hunt=True, verify=True,
                             verify_votes=5, hunt_lenses=2, hunt_rounds=3, hunt_budget=42,
                             max_calls=1, output_tokens=9, timeout_seconds=7))
    argv = _argv_tokens(_fleet_request(tmp_path, spec), tmp_path / "child-out")
    for expected in ["--llm", "--llm-provider", "openai", "--llm-model", "m-1",
                     "--llm-effort", "high", "--llm-backend", "api", "--llm-speed", "fast",
                     "--hunt", "--verify", "--verify-votes", "5", "--hunt-lenses", "2",
                     "--hunt-rounds", "3", "--hunt-budget", "42",
                     "--ai-max-calls", "1", "--ai-output-tokens", "9",
                     "--ai-timeout-seconds", "7"]:
        assert expected in argv


def test_baseline_and_secrets_history_reach_child_argv(tmp_path: Path) -> None:
    spec = RunSpec(baseline="baseline.json", features=FeatureFlags(secrets_history=5))
    argv = _argv_tokens(_fleet_request(tmp_path, spec), tmp_path / "child-out")
    assert argv[argv.index("--baseline") + 1] == "baseline.json"
    assert argv[argv.index("--secrets-history") + 1] == "5"


def test_pr_comment_is_rescoped_to_child_output(tmp_path: Path) -> None:
    request = _fleet_request(tmp_path, SUPPORTED_SPECS["pr_comment"])
    argv = _argv_tokens(request, tmp_path / "child-out")
    assert argv[argv.index("--pr-comment") + 1] == str(tmp_path / "child-out" / "pr-comment.md")
    # The requested shared path is never what a child receives.
    assert "pr-comment-shared.md" not in argv


def test_child_ai_defaults_stay_off_the_argv(tmp_path: Path) -> None:
    """No feature flags leak onto a plain fleet child's argv."""
    argv = _argv_tokens(_fleet_request(tmp_path, RunSpec()), tmp_path / "child-out")
    for absent in ("--llm", "--hunt", "--verify", "--remediate", "--triage",
                   "--baseline", "--pr-comment", "--secrets-history"):
        assert absent not in argv


# ---------------------------------------------------------------------------
# serial (in-process) workers keep the same per-child scoping
# ---------------------------------------------------------------------------


def _capture_serial_specs(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, spec: RunSpec):
    captured: list[RunSpec] = []

    def fake_run_scan(run_spec, *, repo_path, output, analyzers=None, echo=None):
        captured.append(run_spec)
        state = RunState(spec=run_spec)
        state.scan = ScanResult(root=str(repo_path), files_scanned=1)
        return state

    monkeypatch.setattr(scan_service, "run_scan", fake_run_scan)
    request = _fleet_request(tmp_path, spec)
    fleet = FleetScan()
    scan_service._run_fleet_serial(request, [], fleet, tmp_path / "out")
    assert [row.repo_id for row in fleet.results] == ["alpha", "beta"]
    return captured


def test_serial_pr_comment_is_scoped_per_child(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    captured = _capture_serial_specs(monkeypatch, tmp_path, SUPPORTED_SPECS["pr_comment"])
    assert [row.pr_comment for row in captured] == [
        str(tmp_path / "out" / "alpha" / "pr-comment.md"),
        str(tmp_path / "out" / "beta" / "pr-comment.md"),
    ]


def test_serial_baseline_passes_through_shared_read_only_input(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    captured = _capture_serial_specs(monkeypatch, tmp_path, SUPPORTED_SPECS["baseline"])
    assert all(row.baseline == "baseline.json" for row in captured)


def test_serial_secrets_history_passes_through(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    captured = _capture_serial_specs(
        monkeypatch, tmp_path, SUPPORTED_SPECS["secrets_history"])
    assert all(row.features.secrets_history == 5 for row in captured)


def test_serial_spec_without_pr_comment_is_untouched(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    captured = _capture_serial_specs(monkeypatch, tmp_path, RunSpec(no_progress=True))
    assert all(row.pr_comment is None for row in captured)


def test_serial_and_parallel_pr_comment_layout_matches(tmp_path: Path) -> None:
    """The documented per-child layout is identical in both worker modes."""
    request = _fleet_request(tmp_path, SUPPORTED_SPECS["pr_comment"])
    argv = _argv_tokens(request, tmp_path / "out" / "alpha")
    assert argv[argv.index("--pr-comment") + 1] == str(
        tmp_path / "out" / "alpha" / "pr-comment.md")


def test_unsupported_in_fleet_keeps_single_argument_compatibility() -> None:
    exc = UnsupportedInFleet("legacy detail only")
    assert exc.feature == "legacy detail only"
    assert exc.reason is None
    assert isinstance(exc, RuntimeError)
