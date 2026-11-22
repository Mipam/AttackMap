"""Secure-by-default analyzer trust (AR006, AC-009).

A run that would load a non-official analyzer fails with a typed error unless
the caller opts in via ``--allow-untrusted-analyzers`` or the env variable;
the error names the analyzer and the exact flag.
"""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from attackmap.orchestration import analyzers as registry
from attackmap.orchestration.analyzers import (
    ALLOW_UNTRUSTED_ENV,
    ANALYZER_ENTRYPOINT_GROUP,
    AnalyzerMetadata,
    AnalyzerResult,
)
from attackmap.surfaces.cli import app

runner = CliRunner()

_APP = (
    "from flask import Flask\n"
    "app = Flask(__name__)\n"
    "@app.route('/u/<int:i>')\n"
    "def u(i):\n"
    "    return {'id': i}\n"
)


class _ThirdPartyAnalyzer:
    metadata = AnalyzerMetadata(
        name="third-party-x",
        description="a non-official analyzer",
        scope="trust test",
        ecosystems=("python",),
    )

    @property
    def name(self) -> str:
        return "third-party-x"

    def detect(self, root: Path) -> bool:
        return True

    def analyze(self, root: str | Path) -> AnalyzerResult:
        return AnalyzerResult(root=str(root))


class _FakeEntryPoint:
    name = "third-party-x"
    value = "example:ThirdPartyAnalyzer"

    def load(self):
        return _ThirdPartyAnalyzer


class _FakeEntryPoints:
    def select(self, *, group: str):
        if group != ANALYZER_ENTRYPOINT_GROUP:
            return []
        return [_FakeEntryPoint()]


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "app.py").write_text(_APP, encoding="utf-8")
    return repo


def _install(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(registry, "entry_points", lambda: _FakeEntryPoints())
    for env in (ALLOW_UNTRUSTED_ENV, registry.TRUSTED_ONLY_ENV):
        monkeypatch.delenv(env, raising=False)


def test_run_refuses_untrusted_analyzer_and_names_the_flag(monkeypatch, tmp_path) -> None:
    _install(monkeypatch, tmp_path)
    out = tmp_path / "out-refused"
    result = runner.invoke(app, ["analyze", str(_repo(tmp_path)), "-o", str(out), "--no-progress"])
    assert result.exit_code != 0
    flat = " ".join(str(result.output).split())
    assert "UntrustedAnalyzerError" in flat
    assert "third-party-x" in flat
    assert "--allow-untrusted-analyzers" in flat
    assert ALLOW_UNTRUSTED_ENV in flat


def test_run_loads_untrusted_analyzer_with_flag(monkeypatch, tmp_path) -> None:
    _install(monkeypatch, tmp_path)
    out = tmp_path / "out-allowed"
    result = runner.invoke(
        app, ["analyze", str(_repo(tmp_path)), "-o", str(out), "--no-progress",
              "--allow-untrusted-analyzers"])
    assert result.exit_code == 0, result.output


def test_run_loads_untrusted_analyzer_with_env(monkeypatch, tmp_path) -> None:
    _install(monkeypatch, tmp_path)
    monkeypatch.setenv(ALLOW_UNTRUSTED_ENV, "1")
    out = tmp_path / "out-env"
    result = runner.invoke(app, ["analyze", str(_repo(tmp_path)), "-o", str(out), "--no-progress"])
    assert result.exit_code == 0, result.output


def test_legacy_trusted_env_is_a_noop(monkeypatch, tmp_path) -> None:
    """ATTACKMAP_TRUSTED_ANALYZERS_ONLY used to enable refusal; default refuses."""
    _install(monkeypatch, tmp_path)
    monkeypatch.setenv(registry.TRUSTED_ONLY_ENV, "1")
    out = tmp_path / "out-legacy"
    result = runner.invoke(app, ["analyze", str(_repo(tmp_path)), "-o", str(out), "--no-progress"])
    assert result.exit_code != 0
    assert "UntrustedAnalyzerError" in str(result.output)
