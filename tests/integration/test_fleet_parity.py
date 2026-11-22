"""Feature x fleet-mode parity over real fleet runs (AR069, AC-310).

Every documented ScanRequest feature either works in a fleet worker child —
proven here against real serial (max_workers=1, in-process) and parallel
(max_workers=2, subprocess) runs — or raises a typed ``UnsupportedInFleet``
at admission before any repository is scanned. LLM parity additionally runs a
real fleet child against a loopback OpenAI-compatible endpoint and asserts the
child's own report records the AI output produced under its own allowance.
"""

from __future__ import annotations

import json
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from attackmap.artifact_publisher import current_generation
from attackmap.errors import UnsupportedInFleet
from attackmap.orchestration.run_spec import AiSpec, FeatureFlags, RunSpec
from attackmap.scan_service import ScanRequest, execute_scan_request

_APP = "from flask import Flask\napp = Flask(__name__)\n"
_ALPHA_SECRET = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYzQ9xLmP4tR"
_BETA_SECRET = "hvs." + "CAESIJ7xQ2mZpLr8" + "KvTy3NwHb5Ud9FgA" + "sEo1Wc6Ri4Xj0Mn"
_LLM_MARKER = "Fleet parity child LLM review output"


def _app_repo(root: Path, name: str) -> Path:
    repo = root / name
    repo.mkdir(parents=True, exist_ok=True)
    (repo / "app.py").write_text(_APP, encoding="utf-8")
    return repo


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "commit.gpgsign=false", "-c", "user.email=t@t", "-c", "user.name=t",
         "-c", "core.autocrlf=false", *args],
        cwd=repo, check=True, capture_output=True,
    )


def _history_repo(root: Path, name: str, assignment: str, replacement: str) -> Path:
    """A git repo whose history holds a secret that a later commit removed."""
    repo = _app_repo(root, name)
    _git(repo, "init", "-q")
    (repo / "settings.py").write_text(assignment, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "add settings")
    (repo / "settings.py").write_text(replacement, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "move token to env")
    return repo


def _child_dirs(output: Path, repo_ids: list[str]) -> list[Path]:
    """Per-child output directories for the published fleet generation."""
    generation = current_generation(output)
    if generation is not None:
        return [generation / repo_id for repo_id in repo_ids]
    return [output / repo_id for repo_id in repo_ids]


# ---------------------------------------------------------------------------
# supported features: serial x parallel with per-child evidence
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("workers", [1, 2])
def test_fleet_parity_baseline_pr_comment_and_history_are_child_scoped(
    tmp_path: Path, workers: int,
) -> None:
    # Each repo's history carries a DISTINCT secret, so a child report can
    # only contain its own hit — per-child git history isolation, proven.
    repos = [
        _history_repo(tmp_path, "alpha",
                      f'aws_secret_access_key = "{_ALPHA_SECRET}"\n',
                      'aws_secret_access_key = os.environ["AWS_SECRET_ACCESS_KEY"]\n'),
        _history_repo(tmp_path, "beta", f'VAULT = "{_BETA_SECRET}"\n',
                      'VAULT = os.environ["VAULT_TOKEN"]\n'),
    ]
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"findings": []}), encoding="utf-8")
    shared_comment = tmp_path / "pr-comment-shared.md"
    output = tmp_path / "out"
    spec = RunSpec(
        no_progress=True,
        baseline=str(baseline),
        pr_comment=str(shared_comment),
        features=FeatureFlags(secrets_history=10),
    )
    summary = execute_scan_request(
        ScanRequest(repo_paths=repos, output=output, spec=spec, max_workers=workers))
    assert summary.exit_code == 0, summary.error

    children = _child_dirs(output, ["alpha", "beta"])
    for child in children:
        # baseline: each child writes its own diff inside its own output dir.
        diff = child / "attackmap-diff.md"
        assert diff.is_file(), f"missing per-child diff in {child}"
        assert "# AttackMap diff" in diff.read_text(encoding="utf-8")
        # pr_comment: re-scoped per child; the requested shared path is never written.
        comment = child / "pr-comment.md"
        assert comment.is_file(), f"missing per-child PR comment in {child}"
        assert not shared_comment.exists()
    # secrets_history: each child's own report embeds only its own history hit.
    reports = [json.loads((child / "attackmap-report.json").read_text(encoding="utf-8"))
               for child in children]
    by_name = {repo.name: report for repo, report in zip(repos, reports, strict=True)}
    alpha_hits = by_name["alpha"]["scan"].get("secret_history", [])
    beta_hits = by_name["beta"]["scan"].get("secret_history", [])
    assert len(alpha_hits) == 1 and alpha_hits[0]["name"].startswith("wJal")
    assert len(beta_hits) == 1 and beta_hits[0]["name"].startswith("hvs")


# ---------------------------------------------------------------------------
# llm/hunt/remediate/triage: a real fleet child produces real AI output
# ---------------------------------------------------------------------------


class _ResponsesHandler(BaseHTTPRequestHandler):
    """Minimal loopback OpenAI Responses endpoint for fleet child workers."""

    def do_POST(self):
        length = int(self.headers.get("content-length", "0") or 0)
        self.rfile.read(length)
        body = json.dumps({
            "id": "resp_fleet_parity", "object": "response", "created_at": 0,
            "model": "fleet-parity-model", "status": "completed",
            "output": [{"type": "message", "id": "msg_fleet_parity", "role": "assistant",
                        "status": "completed",
                        "content": [{"type": "output_text", "text": _LLM_MARKER,
                                     "annotations": []}]}],
            "usage": {"input_tokens": 11, "output_tokens": 7},
        }).encode("utf-8")
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:  # keep test output quiet
        pass


def test_fleet_parity_llm_child_records_ai_output_under_its_own_allowance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ResponsesHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("OPENAI_BASE_URL", f"http://127.0.0.1:{server.server_address[1]}/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-fleet-parity-local")
    try:
        repos = [_app_repo(tmp_path, "alpha"), _app_repo(tmp_path, "beta")]
        output = tmp_path / "out"
        spec = RunSpec(no_progress=True, ai=AiSpec(
            enabled=True, provider="openai", model="fleet-parity-model",
            max_calls=2, output_tokens=512, timeout_seconds=60))
        summary = execute_scan_request(
            ScanRequest(repo_paths=repos, output=output, spec=spec, max_workers=2))
        assert summary.exit_code == 0, summary.error
    finally:
        server.shutdown()
        server.server_close()

    for child in _child_dirs(output, ["alpha", "beta"]):
        review = child / "defensive-review-llm.md"
        assert review.is_file(), f"child {child} recorded no AI output"
        assert _LLM_MARKER in review.read_text(encoding="utf-8")
        meta = json.loads((child / "defensive-review-llm.meta.json").read_text(encoding="utf-8"))
        assert meta["backend"] == "api"
        assert meta["model"] == "fleet-parity-model"
        assert meta["usage"].get("input_tokens") == 11
        assert meta["usage"].get("output_tokens") == 7


# ---------------------------------------------------------------------------
# refused features: typed admission refusal, nothing scanned
# ---------------------------------------------------------------------------


_REFUSED_SPECS: dict[str, RunSpec] = {
    "--diff-output": RunSpec(diff_output="shared-diff.md"),
    "--fail-on-new-high": RunSpec(fail_on_new_high=True),
    "--fail-on-new-suppression": RunSpec(fail_on_new_suppression=True),
}


@pytest.mark.parametrize("feature", sorted(_REFUSED_SPECS))
def test_fleet_parity_typed_refusal_scans_nothing(tmp_path: Path, feature: str) -> None:
    repos = [_app_repo(tmp_path, "alpha"), _app_repo(tmp_path, "beta")]
    with pytest.raises(UnsupportedInFleet) as refusal:
        execute_scan_request(ScanRequest(
            repo_paths=repos, output=tmp_path / "out", spec=_REFUSED_SPECS[feature]))
    assert refusal.value.feature == feature
    assert refusal.value.reason
    assert not (tmp_path / "out" / "fleet-summary.md").exists()
    assert not (tmp_path / "out" / "fleet-summary.json").exists()
