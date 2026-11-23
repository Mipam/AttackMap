"""AR061 derived SQLite index: rebuild determinism (AC-302) and the
missing/corrupt/foreign-index filesystem fallback (AC-303)."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest
from typer.testing import CliRunner

from attackmap.foundation.artifact_manifest import write_artifact_manifest
from attackmap.foundation.safe_fs import safe_write_text
from attackmap.orchestration.derived_index import sqlite as sqlite_mod
from attackmap.orchestration.derived_index.query import load_rows, trends_payload
from attackmap.orchestration.derived_index.rebuild import collect_rows, rebuild_index
from attackmap.orchestration.derived_index.sqlite import (
    dump_tables,
    index_path,
    open_fresh_index,
)
from attackmap.surfaces.cli import app

_RUN_ID_A = "20261101T000000-aaa111"
_RUN_ID_B = "20261102T000000-bbb222"

_FINDING = {
    "id": "F-1",
    "title": "Hard-coded secret",
    "severity": "high",
    "confidence": "high",
    "identity_scheme": "rule",
    "rule_id": "hardcoded-secret",
    "entity_id": "src/app.py:3",
    "score": 42,
    "exploitability": 80,
    "exploitability_tier": "critical",
    "tags": ["secret-exposure"],
    "taxonomy": {"cwe": ["CWE-798"]},
    "mitigation": "rotate the key",
    "evidence": ["api_key = 'AKIA...'"],
    "locations": [{"file": "src/app.py", "line": 3, "fingerprint": "fp-1"}],
}

_SUPPRESSED = {
    "id": "F-2",
    "title": "Test-only finding",
    "severity": "low",
    "confidence": "medium",
    "rule": "rule=debug-route",
    "reason": "test fixture",
    "suppressed_by": ["baseline-file"],
    "mitigation": "none",
    "evidence": ["only reachable in tests"],
    "locations": [{"file": "tests/conftest.py", "line": 9}],
}

_ROUTES = [
    {"path": "/api/items", "method": "GET", "file": "src/routes.py", "line": 12,
     "auth": "required", "guards": ["[Authorize]"]},
    {"path": "/health", "method": "GET", "file": "src/health.py", "auth": "anonymous"},
]


def _write_generation(base: Path, run_id: str, *, findings=(), suppressed=(), routes=()) -> Path:
    """A real, manifest-checked generation (same writer the pipeline uses)."""
    folder = base / run_id
    folder.mkdir(parents=True, exist_ok=True)
    data = {
        "scan": {"root": "fixture-repository", "files_scanned": 2, "routes": list(routes)},
        "findings": list(findings),
        "attack_paths": [],
        "attack_surfaces": [],
        "exploitability": [],
        "suppressed_findings": list(suppressed),
    }
    safe_write_text(folder, folder / "attackmap-report.json", json.dumps(data))
    safe_write_text(folder, folder / "run-manifest.json", json.dumps({"stages": []}))
    write_artifact_manifest(folder, run_id, "1.0", "fixture-repository", "fixture", [], 0,
                            "succeeded", data)
    return folder


def _base(tmp_path: Path) -> Path:
    base = tmp_path / "out"
    base.mkdir()
    _write_generation(base, _RUN_ID_A, findings=[_FINDING], suppressed=[_SUPPRESSED],
                      routes=_ROUTES)
    _write_generation(base, _RUN_ID_B, findings=[dict(_FINDING, id="F-3",
                                                      severity="medium",
                                                      rule_id="weak-crypto")])
    return base


def _payload(base: Path) -> dict:
    loaded = load_rows(base)
    return trends_payload(loaded.rows, source=loaded.source, reason=loaded.reason)


# --- rebuild: rows are verbatim copies of the generations ------------------------


def test_collect_rows_copies_verbatim(tmp_path: Path) -> None:
    base = _base(tmp_path)
    rows = collect_rows(base)

    assert len(rows.generations) == 2
    assert all(g.valid and g.indexed for g in rows.generations)
    assert {g.run_id for g in rows.generations} == {_RUN_ID_A, _RUN_ID_B}

    assert len(rows.runs) == 2
    run_a = next(r for r in rows.runs if r.run_id == _RUN_ID_A)
    assert run_a.repo_name == "fixture"
    assert run_a.status == "succeeded"
    assert run_a.files_scanned == 2

    assert len(rows.findings) == 2
    finding = next(f for f in rows.findings if f.run_id == _RUN_ID_A)
    assert finding.finding_id == "F-1"
    assert (finding.rule_id, finding.score, finding.exploitability) == ("hardcoded-secret", 42, 80)
    assert finding.tags == ("secret-exposure",)
    assert finding.cwe == ("CWE-798",)

    assert len(rows.suppressions) == 1
    assert rows.suppressions[0].suppressed_by == ("baseline-file",)

    assert len(rows.routes) == 2
    guarded = next(r for r in rows.routes if r.guards)
    assert guarded.guards == ("[Authorize]",)

    texts = [e for e in rows.evidence if e.kind == "text"]
    locations = [e for e in rows.evidence if e.kind == "location"]
    assert any(e.text == "api_key = 'AKIA...'" and not e.suppressed for e in texts)
    assert any(e.suppressed for e in texts)
    loc = next(e for e in locations if e.fingerprint == "fp-1")
    assert (loc.file, loc.line) == ("src/app.py", 3)


def test_invalid_generation_is_listed_not_indexed(tmp_path: Path) -> None:
    base = tmp_path / "out"
    base.mkdir()
    _write_generation(base, _RUN_ID_A, findings=[_FINDING])
    broken = base / "20261103T000000-ccc333"
    broken.mkdir()
    safe_write_text(broken, broken / "artifact-manifest.json", json.dumps({"garbage": True}))

    rows = collect_rows(base)

    broken_row = next(g for g in rows.generations if g.run_id == broken.name)
    assert not broken_row.valid and not broken_row.indexed
    assert broken_row.error
    assert len(rows.findings) == 1  # only the valid generation contributes rows


# --- AC-302: delete + rebuild yields identical content ---------------------------


def test_ac302_delete_and_rebuild_identical(tmp_path: Path) -> None:
    base = _base(tmp_path)
    _, target = rebuild_index(base)
    first_bytes = target.read_bytes()
    before_payload = _payload(base)
    conn, reason = open_fresh_index(base)
    assert reason is None
    assert conn is not None
    try:
        before_dump = dump_tables(conn)
    finally:
        conn.close()

    target.unlink()
    _rows, target2 = rebuild_index(base)

    assert target2 == target
    assert target.read_bytes() == first_bytes  # byte-identical: same hash too
    assert _payload(base) == before_payload
    conn, reason = open_fresh_index(base)
    assert reason is None and conn is not None
    try:
        assert dump_tables(conn) == before_dump
    finally:
        conn.close()
    loaded = load_rows(base)
    assert loaded.source == "index"


def test_rebuild_over_corrupt_index_replaces_it(tmp_path: Path) -> None:
    base = _base(tmp_path)
    target = index_path(base)
    target.parent.mkdir(parents=True)
    target.write_bytes(b"garbage that is not a database")
    _, rebuilt = rebuild_index(base)
    assert rebuilt == target
    loaded = load_rows(base)
    assert loaded.source == "index"


# --- AC-303: every unusable index state falls back to the generations -------------


def test_ac303_missing_index_falls_back(tmp_path: Path) -> None:
    base = _base(tmp_path)
    loaded = load_rows(base)
    assert loaded.source == "filesystem"
    assert loaded.reason == "missing"
    assert loaded.rows == collect_rows(base)


def test_ac303_truncated_index_falls_back(tmp_path: Path) -> None:
    base = _base(tmp_path)
    rebuild_index(base)
    expected_rows = collect_rows(base)
    with index_path(base).open("wb") as handle:
        handle.truncate(0)
    loaded = load_rows(base)
    assert loaded.source == "filesystem"
    assert loaded.reason == "corrupt"
    assert loaded.rows == expected_rows


def test_ac303_foreign_file_falls_back(tmp_path: Path) -> None:
    base = _base(tmp_path)
    target = index_path(base)
    target.parent.mkdir(parents=True)
    target.write_bytes(b"plain text, definitely not sqlite")
    loaded = load_rows(base)
    assert loaded.source == "filesystem"
    assert loaded.reason == "corrupt"
    assert loaded.rows == collect_rows(base)


def test_ac303_schema_mismatch_falls_back(tmp_path: Path) -> None:
    base = _base(tmp_path)
    target = index_path(base)
    target.parent.mkdir(parents=True)
    conn = sqlite3.connect(target)
    try:
        conn.execute("CREATE TABLE index_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        conn.executemany("INSERT INTO index_meta (key, value) VALUES (?, ?)", (
            ("schema_version", "999"),
            ("index_format", "someone-elses-format"),
            ("fingerprint", "irrelevant"),
        ))
        conn.commit()
    finally:
        conn.close()
    loaded = load_rows(base)
    assert loaded.source == "filesystem"
    assert loaded.reason == "schema_mismatch"


def test_ac303_stale_index_falls_back(tmp_path: Path) -> None:
    base = _base(tmp_path)
    rebuild_index(base)
    _write_generation(base, "20261104T000000-ddd444", findings=[_FINDING])
    loaded = load_rows(base)
    assert loaded.source == "filesystem"
    assert loaded.reason == "stale"
    assert len(loaded.rows.findings) == 3  # the fallback sees the new generation


def test_corruption_mid_read_falls_back(tmp_path: Path) -> None:
    """Damage that only shows part-way through a table read is still a fallback."""
    base = _base(tmp_path)
    rebuild_index(base)
    expected = collect_rows(base)
    target = index_path(base)
    raw = bytearray(target.read_bytes())
    raw[len(raw) // 2:] = b"\x00" * (len(raw) - len(raw) // 2)
    target.write_bytes(bytes(raw))
    loaded = load_rows(base)
    assert loaded.source == "filesystem"
    assert loaded.reason == "corrupt"
    assert loaded.rows == expected


# --- the narrowed exception handler in open_fresh_index ----------------------------


def test_freshness_oserror_propagates_and_closes(tmp_path: Path, monkeypatch) -> None:
    base = _base(tmp_path)
    rebuild_index(base)

    def _boom(_base: Path) -> str:
        raise OSError("inventory unreadable")

    monkeypatch.setattr(sqlite_mod, "index_fingerprint", _boom)
    with pytest.raises(OSError, match="inventory unreadable"):
        open_fresh_index(base)


def test_keyboard_interrupt_propagates(tmp_path: Path, monkeypatch) -> None:
    base = _base(tmp_path)
    rebuild_index(base)

    def _interrupt(_base: Path) -> str:
        raise KeyboardInterrupt

    monkeypatch.setattr(sqlite_mod, "index_fingerprint", _interrupt)
    with pytest.raises(KeyboardInterrupt):
        open_fresh_index(base)


# --- CLI: rebuild/status/dump/trends over the same base ----------------------------

_RUNNER = CliRunner()


def test_cli_trends_json_before_after_rebuild_diff(tmp_path: Path) -> None:
    base = _base(tmp_path)
    result = _RUNNER.invoke(app, ["index", "rebuild", "-o", str(base)])
    assert result.exit_code == 0, result.output
    before = _RUNNER.invoke(app, ["trends", "-o", str(base), "--json"])
    assert before.exit_code == 0, before.output

    index_path(base).unlink()
    result = _RUNNER.invoke(app, ["index", "rebuild", "-o", str(base)])
    assert result.exit_code == 0, result.output
    after = _RUNNER.invoke(app, ["trends", "-o", str(base), "--json"])
    assert after.exit_code == 0, after.output

    assert before.output == after.output  # AC-302: identical query results
    payload = json.loads(after.output)
    assert payload["source"] == "index"
    assert payload["totals"]["findings"] == 2
    assert payload["totals"]["by_severity"] == {"high": 1, "medium": 1, "low": 0}


def test_cli_trends_survives_corrupt_index(tmp_path: Path) -> None:
    """AC-303 at the CLI: a truncated index degrades to filesystem reads."""
    base = _base(tmp_path)
    _RUNNER.invoke(app, ["index", "rebuild", "-o", str(base)])
    expected = _RUNNER.invoke(app, ["trends", "-o", str(base), "--json"])
    assert expected.exit_code == 0
    expected_payload = json.loads(expected.output)

    with index_path(base).open("wb") as handle:
        handle.truncate(0)
    degraded = _RUNNER.invoke(app, ["trends", "-o", str(base), "--json"])
    assert degraded.exit_code == 0, degraded.output
    # CliRunner mixes stderr into output: the JSON starts at the first '{'.
    degraded_payload = json.loads(degraded.output[degraded.output.find("{"):])
    assert degraded_payload["source"] == "filesystem"
    assert degraded_payload["index_reason"] == "corrupt"
    for key in ("fingerprint", "generations", "runs", "totals", "by_rule"):
        assert degraded_payload[key] == expected_payload[key]
    assert "corrupt" in degraded.output.lower()


def test_cli_index_status_reports_fallback(tmp_path: Path) -> None:
    base = _base(tmp_path)
    missing = _RUNNER.invoke(app, ["index", "status", "-o", str(base), "--json"])
    assert missing.exit_code == 0
    assert json.loads(missing.output)["index"] == {"usable": False, "reason": "missing"}
    _RUNNER.invoke(app, ["index", "rebuild", "-o", str(base)])
    ok = _RUNNER.invoke(app, ["index", "status", "-o", str(base), "--json"])
    assert json.loads(ok.output)["index"]["usable"] is True


def test_cli_index_dump_requires_usable_index(tmp_path: Path) -> None:
    base = _base(tmp_path)
    missing = _RUNNER.invoke(app, ["index", "dump", "-o", str(base)])
    assert missing.exit_code == 1
    _RUNNER.invoke(app, ["index", "rebuild", "-o", str(base)])
    ok = _RUNNER.invoke(app, ["index", "dump", "-o", str(base)])
    assert ok.exit_code == 0, ok.output
    payload = json.loads(ok.output)
    assert set(payload) >= {"index_meta", "generations", "runs", "findings",
                            "suppressions", "routes", "evidence"}


def test_rebuild_replaces_existing_index_atomically_enough(tmp_path: Path) -> None:
    """A second rebuild over the first rebuild's file succeeds and matches."""
    base = _base(tmp_path)
    _, first_path = rebuild_index(base)
    first_hash = hashlib.sha256(first_path.read_bytes()).hexdigest()
    _, second_path = rebuild_index(base)
    assert second_path == first_path
    assert hashlib.sha256(first_path.read_bytes()).hexdigest() == first_hash
