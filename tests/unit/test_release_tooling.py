"""AR085 slice 1: focused tests for the release tooling.

Covers the artifact manifest writer (tools/build_release.py) and the detached
SHA-256 attestation writer (tools/attest_release.py), including the dirty-tree
refusal. Stdlib-only and hermetic: every subprocess is faked, no build and no
network is involved.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

SDIST_NAME = "attackmap-0.1.0.tar.gz"
WHEEL_NAME = "attackmap-0.1.0-py3-none-any.whl"
SDIST_BYTES = b"sdist-bytes"
WHEEL_BYTES = b"wheel-bytes"
COMMIT = "e939d42e6997e298148503fd54785ab284aecc6b"


def _load_tool(script: str, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, REPO_ROOT / "tools" / script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


build_release = _load_tool("build_release.py", "ar085_build_release")
attest_release = _load_tool("attest_release.py", "ar085_attest_release")


class FakeRun:
    """_run_command replacement: delegates to a handler, recording every call."""

    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def __call__(self, cmd, timeout=None, cwd=None, env=None):
        self.calls.append({"cmd": list(cmd), "cwd": cwd, "env": dict(env or {})})
        return self.handler(self.calls[-1])


# ---------------------------------------------------------------------------
# Manifest writer (tools/build_release.py)
# ---------------------------------------------------------------------------


def test_write_release_manifest_hashes_and_sorts(tmp_path: Path) -> None:
    (tmp_path / SDIST_NAME).write_bytes(SDIST_BYTES)
    (tmp_path / WHEEL_NAME).write_bytes(WHEEL_BYTES)

    manifest, target = build_release.write_release_manifest(tmp_path, "c0ffee00", 1700000000)

    assert target == tmp_path / "release-manifest.json"
    assert manifest["schema_version"] == 1
    assert manifest["manifest_kind"] == "attackmap-release-artifacts"
    assert manifest["git_commit"] == "c0ffee00"
    assert manifest["source_date_epoch"] == 1700000000
    assert manifest["artifact_count"] == 2
    names = [entry["path"] for entry in manifest["artifacts"]]
    assert names == sorted(names) == [WHEEL_NAME, SDIST_NAME]
    for entry in manifest["artifacts"]:
        payload = (tmp_path / entry["path"]).read_bytes()
        assert entry["sha256"] == hashlib.sha256(payload).hexdigest()
        assert entry["size_bytes"] == len(payload)
    on_disk = json.loads(target.read_text(encoding="utf-8"))
    assert on_disk == manifest
    assert target.read_bytes().endswith(b"\n")


def test_manifest_writer_ignores_non_artifact_files(tmp_path: Path) -> None:
    (tmp_path / SDIST_NAME).write_bytes(SDIST_BYTES)
    (tmp_path / "notes.txt").write_text("scratch", encoding="utf-8")

    manifest, _ = build_release.write_release_manifest(tmp_path, "c0ffee00", 1)

    assert [entry["path"] for entry in manifest["artifacts"]] == [SDIST_NAME]


def test_manifest_writer_refuses_directory_without_artifacts(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text("not an artifact", encoding="utf-8")

    with pytest.raises(build_release.ToolError, match="no sdist or wheel"):
        build_release.write_release_manifest(tmp_path, "c0ffee00", 1)
    assert not (tmp_path / "release-manifest.json").exists()


# ---------------------------------------------------------------------------
# Dirty-tree refusal (tools/build_release.py)
# ---------------------------------------------------------------------------


def test_dirty_tree_refused_before_any_build(tmp_path: Path) -> None:
    run = FakeRun(lambda call: (0, " M src/attackmap/engine.py\n", ""))

    with pytest.raises(build_release.ToolError, match="working tree is not clean"):
        build_release.build_release(REPO_ROOT, tmp_path / "out", run=run)

    assert len(run.calls) == 1  # only `git status --porcelain` ran; no build was issued
    assert run.calls[0]["cmd"][:3] == ["git", "status", "--porcelain"]
    assert not (tmp_path / "out").exists()


def test_untracked_file_refused(tmp_path: Path) -> None:
    run = FakeRun(lambda call: (0, "?? scratch.txt\n", ""))

    with pytest.raises(build_release.ToolError, match="working tree is not clean"):
        build_release.build_release(REPO_ROOT, tmp_path / "out", run=run)


def test_git_failure_refused(tmp_path: Path) -> None:
    run = FakeRun(lambda call: (128, "", "fatal: not a git repository"))

    with pytest.raises(build_release.ToolError, match="git status failed"):
        build_release.build_release(REPO_ROOT, tmp_path / "out", run=run)


# ---------------------------------------------------------------------------
# Pinned build (tools/build_release.py), fully faked
# ---------------------------------------------------------------------------


def _release_pipeline_run(build_exit: int) -> FakeRun:
    """Fake the whole clean-tree pipeline, materializing artifacts on the build call."""

    def handler(call):
        cmd = call["cmd"]
        if cmd[:3] == ["git", "status", "--porcelain"]:
            return 0, "", ""
        if cmd[:2] == ["git", "rev-parse"]:
            return 0, COMMIT + "\n", ""
        if cmd[:2] == ["git", "log"]:
            return 0, "1700000000\n", ""
        if cmd[1:3] == ["-m", "build"]:
            out_dir = Path(cmd[cmd.index("--outdir") + 1])
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / SDIST_NAME).write_bytes(SDIST_BYTES)
            (out_dir / WHEEL_NAME).write_bytes(WHEEL_BYTES)
            return build_exit, "", "boom" if build_exit else ""
        raise AssertionError(f"unexpected command: {cmd}")

    return FakeRun(handler)


def test_clean_tree_pins_source_date_epoch_and_writes_manifest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(build_release, "check_build_environment", lambda: None)
    run = _release_pipeline_run(build_exit=0)

    manifest, target = build_release.build_release(REPO_ROOT, tmp_path / "dist", run=run)

    build_calls = [c for c in run.calls if c["cmd"][1:3] == ["-m", "build"]]
    assert len(build_calls) == 1
    assert build_calls[0]["env"].get("SOURCE_DATE_EPOCH") == "1700000000"
    assert "--no-isolation" in build_calls[0]["cmd"]
    assert manifest["source_date_epoch"] == 1700000000
    assert manifest["git_commit"] == COMMIT
    assert [entry["path"] for entry in manifest["artifacts"]] == [WHEEL_NAME, SDIST_NAME]
    assert target.name == "release-manifest.json"


def test_build_failure_leaves_no_manifest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(build_release, "check_build_environment", lambda: None)
    run = _release_pipeline_run(build_exit=1)

    with pytest.raises(build_release.ToolError, match="python -m build failed"):
        build_release.build_release(REPO_ROOT, tmp_path / "dist", run=run)

    assert not (tmp_path / "dist" / "release-manifest.json").exists()


def test_build_refuses_nonempty_out_dir_without_running_build(tmp_path: Path) -> None:
    out_dir = tmp_path / "dist"
    out_dir.mkdir()
    (out_dir / "stale.whl").write_bytes(b"stale")
    run = FakeRun(lambda call: (_ for _ in ()).throw(AssertionError("no command should run")))

    with pytest.raises(build_release.ToolError, match="non-empty directory"):
        build_release.build_artifacts(REPO_ROOT, out_dir, 1700000000, run=run)

    assert run.calls == []


def test_preflight_reports_missing_build_backends(monkeypatch: pytest.MonkeyPatch) -> None:
    real_find_spec = importlib.util.find_spec

    def fake_find_spec(name, package=None):
        if name in {"setuptools", "wheel"}:
            return None
        return real_find_spec(name, package)

    monkeypatch.setattr(build_release.importlib.util, "find_spec", fake_find_spec)

    with pytest.raises(build_release.ToolError, match="setuptools, wheel"):
        build_release.check_build_environment()


# ---------------------------------------------------------------------------
# Detached attestation (tools/attest_release.py)
# ---------------------------------------------------------------------------


def _write_manifest(dist: Path) -> Path:
    dist.mkdir(parents=True, exist_ok=True)
    (dist / SDIST_NAME).write_bytes(SDIST_BYTES)
    (dist / WHEEL_NAME).write_bytes(WHEEL_BYTES)
    _, target = build_release.write_release_manifest(dist, "c0ffee00", 1700000000)
    return target


def test_attest_writes_detached_sha256_lines(tmp_path: Path) -> None:
    manifest_path = _write_manifest(tmp_path / "dist")

    out = attest_release.write_detached(manifest_path)

    assert out == tmp_path / "dist" / "release-manifest.sha256"
    raw = out.read_bytes()
    assert raw.endswith(b"\n") and b"\r" not in raw
    lines = raw.decode("utf-8").splitlines()
    assert lines == [
        f"{hashlib.sha256(WHEEL_BYTES).hexdigest()}  {WHEEL_NAME}",
        f"{hashlib.sha256(SDIST_BYTES).hexdigest()}  {SDIST_NAME}",
    ]


def test_attest_main_writes_to_custom_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    manifest_path = _write_manifest(tmp_path / "dist")
    custom = tmp_path / "custom.sha256"

    rc = attest_release.main(["--manifest", str(manifest_path), "--output", str(custom)])

    assert rc == 0
    assert custom.exists()
    assert len(custom.read_bytes().splitlines()) == 2
    assert "Detached manifest" in capsys.readouterr().out


def test_attest_rejects_wrong_schema(tmp_path: Path) -> None:
    path = tmp_path / "release-manifest.json"
    path.write_text(
        json.dumps({
            "schema_version": 2,
            "manifest_kind": attest_release.EXPECTED_KIND,
            "artifacts": [{"path": "a.whl", "sha256": "0" * 64}],
        }),
        encoding="utf-8",
    )

    with pytest.raises(attest_release.ToolError, match="schema_version"):
        attest_release.write_detached(path)


def test_attest_rejects_wrong_kind(tmp_path: Path) -> None:
    path = tmp_path / "release-manifest.json"
    path.write_text(
        json.dumps({"schema_version": 1, "manifest_kind": "something-else", "artifacts": []}),
        encoding="utf-8",
    )

    with pytest.raises(attest_release.ToolError, match="attackmap-release-artifacts"):
        attest_release.write_detached(path)


def test_attest_rejects_empty_artifacts(tmp_path: Path) -> None:
    path = tmp_path / "release-manifest.json"
    path.write_text(
        json.dumps({"schema_version": 1, "manifest_kind": attest_release.EXPECTED_KIND, "artifacts": []}),
        encoding="utf-8",
    )

    with pytest.raises(attest_release.ToolError, match="no artifacts"):
        attest_release.write_detached(path)


def test_attest_rejects_bad_digest(tmp_path: Path) -> None:
    path = tmp_path / "release-manifest.json"
    path.write_text(
        json.dumps({
            "schema_version": 1,
            "manifest_kind": attest_release.EXPECTED_KIND,
            "artifacts": [{"path": "a.whl", "sha256": "nothex"}],
        }),
        encoding="utf-8",
    )

    with pytest.raises(attest_release.ToolError, match="Invalid sha256"):
        attest_release.write_detached(path)


def test_attest_rejects_escaping_path(tmp_path: Path) -> None:
    path = tmp_path / "release-manifest.json"
    path.write_text(
        json.dumps({
            "schema_version": 1,
            "manifest_kind": attest_release.EXPECTED_KIND,
            "artifacts": [{"path": "../evil.whl", "sha256": "0" * 64}],
        }),
        encoding="utf-8",
    )

    with pytest.raises(attest_release.ToolError, match="Unsafe artifact path"):
        attest_release.write_detached(path)


def test_attest_rejects_duplicate_paths(tmp_path: Path) -> None:
    path = tmp_path / "release-manifest.json"
    path.write_text(
        json.dumps({
            "schema_version": 1,
            "manifest_kind": attest_release.EXPECTED_KIND,
            "artifacts": [
                {"path": "a.whl", "sha256": "0" * 64},
                {"path": "a.whl", "sha256": "1" * 64},
            ],
        }),
        encoding="utf-8",
    )

    with pytest.raises(attest_release.ToolError, match="Duplicate artifact entry"):
        attest_release.write_detached(path)
