"""AR083 `attackmap explain-run`: renders a generation's events.jsonl.

AC-404: the published events.jsonl carries run_id, trace_id, stage timings
and skip reasons, and `explain-run` renders them. Deterministic — the
end-to-end test scans a tiny fixture repo; no network, no LM Studio.
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from attackmap.orchestration.pipeline import run_scan
from attackmap.orchestration.run_spec import RunSpec
from attackmap.surfaces.cli import app

pytestmark = [pytest.mark.unit]

runner = CliRunner()

_APP = (
    "from flask import Flask, request\n"
    "app = Flask(__name__)\n\n"
    "@app.route('/users/<int:user_id>')\n"
    "def get_user(user_id):\n"
    "    return {'id': user_id}\n"
)


def _repo(tmp_path):
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "app.py").write_text(_APP, encoding="utf-8")
    return repo


def _records(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def _write_generation(base, generation, records) -> None:
    folder = base / generation
    folder.mkdir(parents=True)
    (folder / "events.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in records), encoding="utf-8")


def test_explain_run_json_reports_trace_id_stages_and_metrics(tmp_path):
    """End-to-end: a real published generation explains itself (AC-404)."""
    base = tmp_path / "reports"
    state = run_scan(RunSpec(no_progress=True), repo_path=_repo(tmp_path), output=base)
    assert state.exit_code == 0
    pointer = json.loads((base / "current-generation.json").read_text(encoding="utf-8"))
    generation = pointer["generation"]
    events_path = base / generation / "events.jsonl"
    rows = _records(events_path)

    # events.jsonl: every record carries run_id + trace_id; stage timings and
    # the additive metrics record are present; everything else is additive-only
    # (stage/analyzer records keep exactly the pre-AR083 key set).
    legacy_keys = {"ts", "run_id", "trace_id", "stage", "event", "status", "ms", "detail"}
    metrics_rows = [r for r in rows if r["event"] == "metrics"]
    assert len(metrics_rows) == 1
    for row in rows:
        assert row["run_id"] == generation
        assert row["trace_id"]
        if row["event"] == "metrics":
            assert row["stage"] == "run_summary"
            assert row["files"] > 0
            assert row["analyzer_ms"], "expected per-analyzer timings"
            assert row["stage_ms"]["scan_and_merge"]["count"] >= 1
        else:
            assert set(row) <= legacy_keys, f"non-additive keys in {row}"
    assert state.trace_id and state.trace_id != generation

    result = runner.invoke(app, ["explain-run", generation, "--output", str(base), "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["run_id"] == generation
    assert payload["trace_id"] == state.trace_id
    stage_names = {row["stage"] for row in payload["stages"]}
    assert {"select_analyzers", "scan_and_merge", "translate", "publish"} <= stage_names
    assert payload["totals"]["files"] > 0
    assert payload["totals"]["analyzer_ms_total"] > 0
    assert payload["skips"] == []
    assert payload["metrics"]["signals"] >= 0


def test_explain_run_human_output_lists_stages_skips_and_totals(tmp_path):
    base = tmp_path / "reports"
    records = [
        {"ts": "t0", "run_id": "g1", "trace_id": "t1", "stage": "select_analyzers",
         "event": "stage", "status": "start"},
        {"ts": "t1", "run_id": "g1", "trace_id": "t1", "stage": "select_analyzers",
         "event": "stage", "status": "end", "ms": 3},
        {"ts": "t2", "run_id": "g1", "trace_id": "t1", "stage": "cve",
         "event": "stage", "status": "skip", "detail": "time budget of 600s expired"},
        {"ts": "t3", "run_id": "g1", "trace_id": "t1", "stage": "run_summary",
         "event": "metrics", "status": "ok", "files": 5, "signals": 2, "budget_skips": [],
         "analyzer_ms": {}, "stage_ms": {}},
    ]
    _write_generation(base, "g1", records)

    result = runner.invoke(app, ["explain-run", "g1", "--output", str(base)])
    assert result.exit_code == 0, result.output
    assert "run g1" in result.output
    assert "trace_id: t1" in result.output
    assert "select_analyzers: end (3 ms)" in result.output
    assert "cve: time budget of 600s expired" in result.output
    assert "files=5 signals=2 budget_skips=1" in result.output


def test_explain_run_resolves_current_pointer(tmp_path):
    base = tmp_path / "reports"
    records = [{"ts": "t", "run_id": "cur", "trace_id": "tr", "stage": "publish",
                "event": "stage", "status": "end", "ms": 1}]
    _write_generation(base, "cur", records)
    (base / "current-generation.json").write_text(
        json.dumps({"generation": "cur"}), encoding="utf-8")

    result = runner.invoke(app, ["explain-run", "current", "--output", str(base), "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["run_id"] == "cur"


def test_explain_run_accepts_generation_directory_path(tmp_path):
    base = tmp_path / "reports"
    records = [{"ts": "t", "run_id": "by-path", "trace_id": "tr", "stage": "publish",
                "event": "stage", "status": "end", "ms": 1}]
    folder = base / "by-path"
    folder.mkdir(parents=True)
    (folder / "events.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")

    result = runner.invoke(app, ["explain-run", str(folder), "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["generation"] == "by-path"


def test_explain_run_missing_generation_exits_2(tmp_path):
    result = runner.invoke(app, ["explain-run", "nope", "--output", str(tmp_path)])
    assert result.exit_code == 2
    assert "no events.jsonl" in result.output
