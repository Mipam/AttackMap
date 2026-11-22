import json
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import attackmap.pipeline as pipeline
from attackmap.ai_budget import AiBudget, budget_scope, current_budget
from attackmap.artifact_publisher import current_generation, validate_generation
from attackmap.cli import app
from attackmap.llm_review import generate_llm_review
from attackmap.models import ScanResult
from attackmap.orchestration.run_spec import AiSpec, RunSpec
from attackmap.pipeline import run_scan
from attackmap.scan_service import ScanRequest


class FakeSdk:
    def __init__(self, missing_usage=False):
        self.responses = self
        self.calls = []
        self.missing_usage = missing_usage

    def with_options(self, **kwargs):
        return self

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(output_text="Synthetic review", model="fake", status="completed",
            usage=None if self.missing_usage else SimpleNamespace(input_tokens=2, output_tokens=1))


@pytest.fixture
def setup_scan(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setattr(pipeline, "resolve_run_analyzers", lambda *args, **kwargs: [])
    monkeypatch.setattr(pipeline, "analyze_repository", lambda *args, **kwargs: ScanResult(root=str(repo)))

    def scan(**kwargs):
        """Build the spec, run it quietly; returns (state, output directory)."""
        output = tmp_path / "reports"
        spec = RunSpec(no_progress=True, **kwargs)
        state = run_scan(spec, repo_path=repo, output=output,
                         echo=lambda *args, **kwargs2: None)
        return state, output

    return scan


@pytest.mark.parametrize("second", ["hunt", "remediate", "triage"])
def test_one_provider_attempt_shared_across_features(setup_scan, monkeypatch, second):
    client = FakeSdk()
    def sdk(*args, **kwargs):
        return generate_llm_review(*args, **kwargs, openai_client=client)
    monkeypatch.setattr(pipeline, "generate_llm_review", sdk)
    extra = {second: True}
    if second == "hunt":
        extra.update(verify=True, verify_votes=3, hunt_lenses=2, hunt_rounds=2)
    _state, output = setup_scan(ai=AiSpec(enabled=True, provider="openai", backend="api",
                                          max_calls=1, **extra))
    assert _state.exit_code == 0
    assert len(client.calls) == 1
    folder = current_generation(output)
    validate_generation(folder)
    allowance = json.loads((folder / "run-manifest.json").read_text())["ai_allowance"]
    assert allowance["max_calls"] == allowance["calls_reserved"] == 1
    assert allowance["usage_status"] == "reported"
    assert current_budget() is None


def test_unknown_usage_retains_reservation_and_manifest_before_hash_commit(setup_scan, monkeypatch):
    client = FakeSdk(missing_usage=True)
    monkeypatch.setattr(pipeline, "generate_llm_review", lambda *args, **kwargs:
        generate_llm_review(*args, **kwargs, openai_client=client))
    _state, output = setup_scan(ai=AiSpec(enabled=True, remediate=True, provider="openai",
                                          backend="api", output_tokens=5))
    folder = current_generation(output)
    validate_generation(folder)
    allowance = json.loads((folder / "run-manifest.json").read_text())["ai_allowance"]
    assert len(client.calls) == 1
    assert allowance["unknown_output_usage_calls"] == 1
    assert allowance["output_tokens_charged_or_reserved"] == 5
    assert allowance["usage_status"] == "partial_or_unknown"


def test_external_ledger_inherited_and_deadline_blocks_all_dispatch(setup_scan, monkeypatch):
    client = FakeSdk()
    seen = []
    def sdk(*args, **kwargs):
        seen.append(current_budget())
        return generate_llm_review(*args, **kwargs, openai_client=client)
    monkeypatch.setattr(pipeline, "generate_llm_review", sdk)
    now = [0.0]
    ledger = AiBudget(max_calls=1, max_seconds=1, output_token_limit=5, clock=lambda: now[0])
    now[0] = 2.0
    with budget_scope(ledger):
        setup_scan(ai=AiSpec(enabled=True, hunt=True, remediate=True, triage=True,
                             provider="openai", backend="api"))
        assert current_budget() is ledger
    assert seen and all(value is ledger for value in seen)
    assert not client.calls


def test_no_ai_does_not_create_budget_or_sdk_side_effects(setup_scan, monkeypatch):
    monkeypatch.setattr(pipeline, "AiBudget", lambda **kwargs: pytest.fail("Budget created without AI"))
    monkeypatch.setattr(pipeline, "generate_llm_review", lambda *args, **kwargs: pytest.fail("Provider called without AI"))
    _state, output = setup_scan()
    manifest = json.loads((current_generation(output) / "run-manifest.json").read_text())
    assert "ai_allowance" not in manifest


@pytest.mark.parametrize("kwargs", [{"max_calls": True}, {"max_calls": 0}, {"output_tokens": 0}, {"timeout_seconds": 0}])
def test_typed_limit_validation(tmp_path, kwargs):
    from attackmap.pipeline import AnalysisConfigurationError
    with pytest.raises(AnalysisConfigurationError, match="must be an integer from 1 to"):
        run_scan(RunSpec(ai=AiSpec(enabled=True, **kwargs)), repo_path=tmp_path,
                 output=tmp_path / "out")


def test_cli_whole_allowance_flags_help_and_validation(tmp_path):
    runner = CliRunner()
    help_result = runner.invoke(app, ["analyze", "--help"])
    assert help_result.exit_code == 0
    assert "--ai-max-calls" in help_result.output and "OUTPUT-token" in help_result.output
    assert all(word in help_result.output for word in ("hidden", "reasoning", "billing", "input"))
    bad = runner.invoke(app, ["analyze", str(tmp_path), "--ai-max-calls", "0"])
    assert bad.exit_code != 0


def test_cli_provider_backend_fails_closed_before_dispatch(setup_scan, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Subscription CLI dispatched despite strict output cap")
    monkeypatch.setattr(pipeline, "generate_llm_review", lambda *args, **kwargs:
        generate_llm_review(*args, **kwargs, codex_runner=forbidden))
    _state, output = setup_scan(ai=AiSpec(enabled=True, provider="openai", backend="cli"))
    folder = current_generation(output)
    validate_generation(folder)
    allowance = json.loads((folder / "run-manifest.json").read_text())["ai_allowance"]
    assert allowance["calls_reserved"] == 0


def test_cli_flags_reach_typed_scan_request(tmp_path, monkeypatch):
    import attackmap.cli as cli
    received = []
    def execute(request):
        received.append(request)
        return SimpleNamespace(exit_code=0)
    monkeypatch.setattr(cli, "execute_scan_request", execute)
    result = CliRunner().invoke(app, ["analyze", str(tmp_path), "--llm", "--ai-max-calls", "1",
        "--ai-output-tokens", "9", "--ai-timeout-seconds", "7"])
    assert result.exit_code == 0, result.output
    ai = received[0].spec.ai
    assert (ai.max_calls, ai.output_tokens, ai.timeout_seconds) == (1, 9, 7)
    assert ai.enabled


def test_requested_limits_reach_serial_and_parallel_child_cli(tmp_path, monkeypatch):
    import attackmap.cli as cli
    from attackmap.scan_service import _run_fleet_repo_argv
    request = ScanRequest(repo_paths=[tmp_path], output=tmp_path / "out",
                          spec=RunSpec(ai=AiSpec(max_calls=1, output_tokens=9, timeout_seconds=7)))
    argv = _run_fleet_repo_argv(request, tmp_path, request.output, [])
    assert argv[argv.index("--ai-max-calls") + 1] == "1"
    assert argv[argv.index("--ai-output-tokens") + 1] == "9"
    assert argv[argv.index("--ai-timeout-seconds") + 1] == "7"
    received = []
    monkeypatch.setattr(cli, "execute_scan_request", lambda child: (received.append(child), SimpleNamespace(exit_code=0))[1])
    result = CliRunner().invoke(app, argv[argv.index("analyze"):])
    assert result.exit_code == 0, result.output
    child_ai = received[0].spec.ai
    assert (child_ai.max_calls, child_ai.output_tokens, child_ai.timeout_seconds) == (1, 9, 7)


def test_fleet_ai_remains_explicitly_unsupported(tmp_path):
    from attackmap.scan_service import _fleet_incompatible_flags
    request = ScanRequest(repo_paths=[tmp_path, tmp_path / "other"], output=tmp_path / "out",
                          spec=RunSpec(ai=AiSpec(enabled=True, hunt=True, remediate=True, triage=True)))
    assert {"--llm", "--hunt", "--remediate", "--triage"} <= set(_fleet_incompatible_flags(request))
