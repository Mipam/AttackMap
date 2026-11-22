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


# ---------------------------------------------------------------------------
# AC-406 gate: --twice --compare (tools/build_release.py)
# ---------------------------------------------------------------------------


def _double_build_run(payloads: list[bytes]) -> FakeRun:
    """Fake clean-tree pipeline; build call N materializes artifacts from payloads[N]."""
    state = {"builds": 0}

    def handler(call):
        cmd = call["cmd"]
        if cmd[:3] == ["git", "status", "--porcelain"]:
            return 0, "", ""
        if cmd[:2] == ["git", "rev-parse"]:
            return 0, COMMIT + "\n", ""
        if cmd[:2] == ["git", "log"]:
            return 0, "1700000000\n", ""
        if cmd[1:3] == ["-m", "build"]:
            index = min(state["builds"], len(payloads) - 1)
            state["builds"] += 1
            out_dir = Path(cmd[cmd.index("--outdir") + 1])
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / SDIST_NAME).write_bytes(b"sdist-" + payloads[index])
            (out_dir / WHEEL_NAME).write_bytes(b"wheel-" + payloads[index])
            return 0, "", ""
        raise AssertionError(f"unexpected command: {cmd}")

    return FakeRun(handler)


def _patch_gate_main(monkeypatch: pytest.MonkeyPatch, payloads: list[bytes]) -> None:
    """Patch clean-tree and builds so build_release.main() runs hermetically."""
    monkeypatch.setattr(build_release, "check_clean_tree", lambda repo_root, run=None: (COMMIT, 1700000000))
    counter = {"builds": 0}

    def fake_build(repo_root, out_dir, epoch, run=None):
        payload = payloads[min(counter["builds"], len(payloads) - 1)]
        counter["builds"] += 1
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / SDIST_NAME).write_bytes(b"sdist-" + payload)
        (out_dir / WHEEL_NAME).write_bytes(b"wheel-" + payload)

    monkeypatch.setattr(build_release, "build_artifacts", fake_build)


def test_build_twice_second_dir_is_fresh_sibling(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(build_release, "check_build_environment", lambda: None)
    run = _double_build_run([b"same", b"same"])

    first, second, second_dir = build_release.build_twice(REPO_ROOT, tmp_path / "dist", run=run)

    assert second_dir == tmp_path / "dist-rebuild"
    assert first[1] == tmp_path / "dist" / "release-manifest.json"
    assert second[1] == second_dir / "release-manifest.json"
    assert first[0]["git_commit"] == second[0]["git_commit"] == COMMIT
    assert first[0]["source_date_epoch"] == second[0]["source_date_epoch"] == 1700000000
    git_calls = [c for c in run.calls if c["cmd"][0] == "git"]
    assert len(git_calls) == 3  # status, rev-parse, log: the clean tree is checked exactly once
    build_calls = [c for c in run.calls if c["cmd"][1:3] == ["-m", "build"]]
    assert len(build_calls) == 2
    assert build_calls[0]["env"]["SOURCE_DATE_EPOCH"] == build_calls[1]["env"]["SOURCE_DATE_EPOCH"] == "1700000000"


def test_compare_builds_equal_sets_pass(tmp_path: Path) -> None:
    first_dir, second_dir = tmp_path / "one", tmp_path / "two"
    for directory in (first_dir, second_dir):
        directory.mkdir()
        (directory / SDIST_NAME).write_bytes(b"identical-sdist")
        (directory / WHEEL_NAME).write_bytes(b"identical-wheel")

    ok, mismatches = build_release.compare_builds(first_dir, second_dir)

    assert ok is True
    assert mismatches == []


def test_compare_builds_differing_sets_list_mismatches(tmp_path: Path) -> None:
    first_dir, second_dir = tmp_path / "one", tmp_path / "two"
    for directory, payload in ((first_dir, b"one"), (second_dir, b"two")):
        directory.mkdir()
        (directory / SDIST_NAME).write_bytes(b"identical-sdist")
        (directory / WHEEL_NAME).write_bytes(b"wheel-" + payload)

    ok, mismatches = build_release.compare_builds(first_dir, second_dir)

    assert ok is False
    assert len(mismatches) == 1  # only the wheel differs; the sdist must not be listed
    assert mismatches[0].startswith(WHEEL_NAME)
    assert "sha256" in mismatches[0]


def test_compare_builds_reports_missing_artifact(tmp_path: Path) -> None:
    first_dir, second_dir = tmp_path / "one", tmp_path / "two"
    first_dir.mkdir()
    second_dir.mkdir()
    for directory in (first_dir, second_dir):
        (directory / WHEEL_NAME).write_bytes(b"wheel-same")
    (first_dir / SDIST_NAME).write_bytes(b"only-in-first")

    ok, mismatches = build_release.compare_builds(first_dir, second_dir)

    assert ok is False
    assert mismatches == [f"{SDIST_NAME}: present only in the first build"]


def test_main_twice_compare_passes_when_reproducible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    _patch_gate_main(monkeypatch, [b"same", b"same"])

    rc = build_release.main(["--out", str(tmp_path / "dist"), "--twice", "--compare"])

    assert rc == 0
    assert "BUILD REPRODUCIBLE" in capsys.readouterr().out


def test_main_twice_compare_fails_with_mismatch_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    _patch_gate_main(monkeypatch, [b"one", b"two"])

    rc = build_release.main(["--out", str(tmp_path / "dist"), "--twice", "--compare"])

    assert rc == 1
    captured = capsys.readouterr()
    assert "BUILD NOT REPRODUCIBLE" in captured.err
    assert WHEEL_NAME in captured.err and SDIST_NAME in captured.err


def test_main_compare_without_twice_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as excinfo:
        build_release.main(["--out", str(tmp_path / "dist"), "--compare"])

    assert excinfo.value.code == 2


# ---------------------------------------------------------------------------
# Ed25519 signing and verification (tools/attest_release.py)
# ---------------------------------------------------------------------------

CRYPTOGRAPHY_AVAILABLE = importlib.util.find_spec("cryptography") is not None
requires_crypto = pytest.mark.skipif(
    not CRYPTOGRAPHY_AVAILABLE,
    reason="cryptography not importable; signing is honestly unavailable in this environment",
)


def _build_dir(dist: Path, with_sig: bool = False) -> Path:
    """A dummy attested build directory: two artifacts, manifest, detached sha256."""
    dist.mkdir(parents=True, exist_ok=True)
    (dist / SDIST_NAME).write_bytes(SDIST_BYTES)
    (dist / WHEEL_NAME).write_bytes(WHEEL_BYTES)
    _, target = build_release.write_release_manifest(dist, "c0ffee00", 1700000000)
    detached = attest_release.write_detached(target)
    if with_sig:
        detached.with_name(detached.name + attest_release.SIGNATURE_SUFFIX).write_bytes(b"signature-bytes")
    return dist


@requires_crypto
def test_sign_creates_keypair_and_round_trips(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    dist = _build_dir(tmp_path / "dist")
    key_dir = tmp_path / "keys"
    manifest = dist / "release-manifest.json"
    detached = dist / "release-manifest.sha256"

    assert attest_release.main(["--manifest", str(manifest), "--sign", str(key_dir)]) == 0
    assert (key_dir / attest_release.PRIVATE_KEY_NAME).is_file()
    assert (key_dir / attest_release.PUBLIC_KEY_NAME).is_file()
    assert (dist / "release-manifest.sha256.sig").is_file()
    assert "Signature" in capsys.readouterr().out

    assert attest_release.main(["--detached", str(detached), "--verify", str(key_dir / attest_release.PUBLIC_KEY_NAME)]) == 0
    assert "VERIFIED" in capsys.readouterr().out


@requires_crypto
def test_verify_is_deterministic_on_second_run(tmp_path: Path) -> None:
    dist = _build_dir(tmp_path / "dist")
    key_dir = tmp_path / "keys"
    attest_release.sign_detached(dist / "release-manifest.sha256", key_dir)
    first_sig = (dist / "release-manifest.sha256.sig").read_bytes()
    attest_release.sign_detached(dist / "release-manifest.sha256", key_dir)
    assert (dist / "release-manifest.sha256.sig").read_bytes() == first_sig
    ok, reasons = attest_release.verify_detached(
        dist / "release-manifest.sha256", key_dir / attest_release.PUBLIC_KEY_NAME
    )
    assert ok is True and reasons == []


@requires_crypto
def test_sign_refuses_keypair_rotation(tmp_path: Path) -> None:
    dist = _build_dir(tmp_path / "dist")
    key_dir = tmp_path / "keys"
    attest_release.sign_detached(dist / "release-manifest.sha256", key_dir)
    (key_dir / attest_release.PRIVATE_KEY_NAME).unlink()

    with pytest.raises(attest_release.ToolError, match="refusing to generate a new keypair"):
        attest_release.sign_detached(dist / "release-manifest.sha256", key_dir)


@requires_crypto
def test_verify_detects_tampered_artifact(tmp_path: Path) -> None:
    dist = _build_dir(tmp_path / "dist")
    key_dir = tmp_path / "keys"
    attest_release.sign_detached(dist / "release-manifest.sha256", key_dir)
    payload = bytearray((dist / WHEEL_NAME).read_bytes())
    payload[-1] ^= 0x01  # flip exactly one bit of one artifact
    (dist / WHEEL_NAME).write_bytes(bytes(payload))

    ok, reasons = attest_release.verify_detached(
        dist / "release-manifest.sha256", key_dir / attest_release.PUBLIC_KEY_NAME
    )

    assert ok is False
    assert len(reasons) == 1
    assert reasons[0].startswith(WHEEL_NAME)
    assert "hash does not match" in reasons[0]


@requires_crypto
def test_verify_detects_tampered_detached_manifest(tmp_path: Path) -> None:
    dist = _build_dir(tmp_path / "dist")
    key_dir = tmp_path / "keys"
    detached = dist / "release-manifest.sha256"
    attest_release.sign_detached(detached, key_dir)
    lines = detached.read_text(encoding="utf-8").splitlines()
    lines[0] = ("0" if lines[0][0] != "0" else "1") + lines[0][1:]  # alter one recorded hash
    detached.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, reasons = attest_release.verify_detached(detached, key_dir / attest_release.PUBLIC_KEY_NAME)

    assert ok is False
    assert any("signature does not match" in reason for reason in reasons)


@requires_crypto
def test_verify_rejects_non_ed25519_public_key(tmp_path: Path) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    dist = _build_dir(tmp_path / "dist")
    key_dir = tmp_path / "keys"
    attest_release.sign_detached(dist / "release-manifest.sha256", key_dir)
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_pub = tmp_path / "rsa-public.pem"
    rsa_pub.write_bytes(
        rsa_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

    with pytest.raises(attest_release.ToolError, match="Not an Ed25519 public key"):
        attest_release.verify_detached(dist / "release-manifest.sha256", rsa_pub)


@requires_crypto
def test_verify_without_signature_file_is_an_error(tmp_path: Path) -> None:
    dist = _build_dir(tmp_path / "dist")
    key_dir = tmp_path / "keys"
    attest_release.sign_detached(dist / "release-manifest.sha256", key_dir)
    (dist / "release-manifest.sha256.sig").unlink()

    with pytest.raises(attest_release.ToolError, match="run --sign before --verify"):
        attest_release.verify_detached(dist / "release-manifest.sha256", key_dir / attest_release.PUBLIC_KEY_NAME)


def test_sign_without_cryptography_exits_3(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    def no_crypto():
        raise attest_release.SigningUnavailable(
            "Signing requires the 'cryptography' package, which is not importable here."
        )

    monkeypatch.setattr(attest_release, "_crypto", no_crypto)
    dist = _build_dir(tmp_path / "dist")

    rc = attest_release.main(["--manifest", str(dist / "release-manifest.json"), "--sign", str(tmp_path / "keys")])

    assert rc == 3
    assert "cryptography" in capsys.readouterr().err
    assert not (tmp_path / "keys" / attest_release.PRIVATE_KEY_NAME).exists()


@requires_crypto
def test_main_verify_failure_exits_1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    dist = _build_dir(tmp_path / "dist")
    key_dir = tmp_path / "keys"
    attest_release.sign_detached(dist / "release-manifest.sha256", key_dir)
    payload = bytearray((dist / SDIST_NAME).read_bytes())
    payload[0] ^= 0x80
    (dist / SDIST_NAME).write_bytes(bytes(payload))

    rc = attest_release.main(["--detached", str(dist / "release-manifest.sha256"), "--verify", str(key_dir / attest_release.PUBLIC_KEY_NAME)])

    assert rc == 1
    captured = capsys.readouterr()
    assert "VERIFY FAILED" in captured.err
    assert SDIST_NAME in captured.err


# ---------------------------------------------------------------------------
# --publish: flat layout, post-copy re-verification, partial-copy refusal
# ---------------------------------------------------------------------------


def test_publish_copies_flat_layout_and_signature(tmp_path: Path) -> None:
    dist = _build_dir(tmp_path / "dist", with_sig=True)

    published = build_release.publish_release(dist, tmp_path / "dest")

    target = tmp_path / "dest" / "release"
    names = sorted(path.name for path in published)
    assert names == sorted([
        SDIST_NAME, WHEEL_NAME, "release-manifest.json", "release-manifest.sha256", "release-manifest.sha256.sig",
    ])
    assert all(path.parent == target for path in published)  # flat layout, no subdirectories
    for path in published:
        assert path.is_file()


def test_publish_creates_detached_manifest_when_missing(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / SDIST_NAME).write_bytes(SDIST_BYTES)
    (dist / WHEEL_NAME).write_bytes(WHEEL_BYTES)
    build_release.write_release_manifest(dist, "c0ffee00", 1700000000)
    assert not (dist / "release-manifest.sha256").exists()

    published = build_release.publish_release(dist, tmp_path / "dest")

    assert (dist / "release-manifest.sha256").is_file()  # created in the build dir too
    assert (tmp_path / "dest" / "release" / "release-manifest.sha256").is_file()
    assert len(published) == 4  # two artifacts + two manifests, no signature


def test_publish_refuses_without_release_manifest(tmp_path: Path) -> None:
    empty = tmp_path / "dist"
    empty.mkdir()

    with pytest.raises(build_release.ToolError, match="publish follows a build"):
        build_release.publish_release(empty, tmp_path / "dest")


def test_publish_refuses_nonempty_target(tmp_path: Path) -> None:
    dist = _build_dir(tmp_path / "dist", with_sig=True)
    target = tmp_path / "dest" / "release"
    target.mkdir(parents=True)
    (target / "previous-release.txt").write_text("old", encoding="utf-8")

    with pytest.raises(build_release.ToolError, match="non-empty directory"):
        build_release.publish_release(dist, tmp_path / "dest")
    assert (target / "previous-release.txt").read_text(encoding="utf-8") == "old"  # untouched


def test_publish_refuses_and_cleans_up_on_source_hash_mismatch(tmp_path: Path) -> None:
    dist = _build_dir(tmp_path / "dist", with_sig=True)
    payload = bytearray((dist / WHEEL_NAME).read_bytes())
    payload[-1] ^= 0x01  # drift an artifact after its manifests were written
    (dist / WHEEL_NAME).write_bytes(bytes(payload))

    with pytest.raises(build_release.ToolError, match="Post-copy hash mismatch"):
        build_release.publish_release(dist, tmp_path / "dest")
    assert not (tmp_path / "dest" / "release").exists()


def test_publish_cleans_up_when_copy_is_corrupted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    dist = _build_dir(tmp_path / "dist", with_sig=True)

    def corrupting_copy2(source, destination, **kwargs):
        destination.write_bytes(b"corrupted-in-transit")  # simulate bit rot during the copy

    monkeypatch.setattr(build_release.shutil, "copy2", corrupting_copy2)

    with pytest.raises(build_release.ToolError, match="differs from its source"):
        build_release.publish_release(dist, tmp_path / "dest")
    assert not (tmp_path / "dest" / "release").exists()


def test_main_single_build_publishes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    _patch_gate_main(monkeypatch, [b"same"])

    rc = build_release.main(["--out", str(tmp_path / "dist"), "--publish", str(tmp_path / "dest")])

    assert rc == 0
    target = tmp_path / "dest" / "release"
    assert (target / WHEEL_NAME).is_file() and (target / SDIST_NAME).is_file()
    assert (target / "release-manifest.json").is_file()
    assert (target / "release-manifest.sha256").is_file()
    assert f"Published {len(list(target.iterdir()))} files" in capsys.readouterr().out
