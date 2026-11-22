"""Reproducible release build driver (AR085 slice 1).

Refuses to run unless the working tree is exactly clean (``git status
--porcelain`` empty), pins ``SOURCE_DATE_EPOCH`` to the HEAD commit's
committer timestamp, builds the sdist and wheel with ``python -m build
--no-isolation`` (so the constraints-pinned environment, not a freshly
resolved one, produces the artifacts), and records the SHA-256 and size of
every artifact into ``release-manifest.json`` next to them. Nothing here
signs or publishes anything; docs/releases.md describes the intended flow
and the attestation step (tools/attest_release.py).
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

SCHEMA_VERSION = 1
MANIFEST_KIND = "attackmap-release-artifacts"
MANIFEST_NAME = "release-manifest.json"
ARTIFACT_SUFFIXES = (".tar.gz", ".whl")
GIT_TIMEOUT_SECONDS = 30
BUILD_TIMEOUT_SECONDS = 1800


class ToolError(Exception):
    """Fatal validation/build failure; no release manifest is written."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run_command(cmd, timeout=GIT_TIMEOUT_SECONDS, cwd=None, env=None):
    """Run a local command; returns (returncode, stdout, stderr). Injectable for tests."""
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd, env=env)
    return result.returncode, result.stdout, result.stderr


def check_clean_tree(repo_root: Path, run=_run_command) -> tuple[str, int]:
    """Return (HEAD commit, SOURCE_DATE_EPOCH) after refusing any dirty tree state.

    A release build must come from an exactly clean tree: modified, staged and
    untracked files are all refused, because the manifest ties artifact hashes
    to a commit and any local drift would make that claim dishonest.
    """
    code, out, err = run(["git", "status", "--porcelain"], cwd=repo_root)
    if code != 0:
        raise ToolError(f"git status failed: {(err or out).strip()}")
    if out.strip():
        preview = "\n".join(out.strip().splitlines()[:10])
        raise ToolError(
            "Refusing to build: the working tree is not clean "
            "(git status --porcelain must be empty). Offending entries:\n" + preview
        )
    code, out, err = run(["git", "rev-parse", "HEAD"], cwd=repo_root)
    if code != 0:
        raise ToolError(f"git rev-parse HEAD failed: {(err or out).strip()}")
    commit = out.strip()
    code, out, err = run(["git", "log", "-1", "--format=%ct"], cwd=repo_root)
    if code != 0 or not out.strip().isdigit():
        raise ToolError(f"Could not read the HEAD commit timestamp: {(err or out).strip()}")
    return commit, int(out.strip())


def check_build_environment() -> None:
    """Refuse to start when the pinned build backends are missing.

    The build runs with ``--no-isolation`` so the artifacts come from the
    environment pinned by constraints.txt (an isolated build would resolve
    ``setuptools>=68`` to whatever is newest and break reproducibility).
    """
    missing = [name for name in ("build", "setuptools", "wheel") if importlib.util.find_spec(name) is None]
    if missing:
        raise ToolError(
            "Release build needs " + ", ".join(missing) + " importable in the current interpreter "
            "(the build runs with --no-isolation so the pinned environment produces the artifacts). "
            "Install them and retry."
        )


def build_artifacts(repo_root: Path, out_dir: Path, source_date_epoch: int, run=_run_command) -> None:
    """Build the sdist and wheel into an empty out_dir with SOURCE_DATE_EPOCH pinned."""
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ToolError(
            f"Refusing to build into a non-empty directory: {out_dir}; "
            "choose a fresh directory so the manifest never mixes artifacts from two builds"
        )
    check_build_environment()
    out_dir.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "SOURCE_DATE_EPOCH": str(source_date_epoch)}
    cmd = [
        sys.executable, "-m", "build", "--no-isolation", "--sdist", "--wheel",
        "--outdir", str(out_dir), str(repo_root),
    ]
    code, out, err = run(cmd, timeout=BUILD_TIMEOUT_SECONDS, env=env)
    if code != 0:
        raise ToolError(f"python -m build failed (exit {code}):\n{(err or out).strip()}")


def collect_artifacts(out_dir: Path) -> list[Path]:
    artifacts = sorted(
        (p for p in out_dir.iterdir() if p.is_file() and p.name.endswith(ARTIFACT_SUFFIXES)),
        key=lambda p: p.name,
    )
    if not artifacts:
        raise ToolError(f"Build produced no sdist or wheel in {out_dir}")
    return artifacts


def write_release_manifest(out_dir: Path, git_commit: str, source_date_epoch: int) -> tuple[dict, Path]:
    """Hash every artifact in out_dir into release-manifest.json and return (manifest, path)."""
    if not git_commit:
        raise ToolError("git_commit must not be empty")
    entries = [
        {"path": p.name, "size_bytes": p.stat().st_size, "sha256": sha256_file(p)}
        for p in collect_artifacts(out_dir)
    ]
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "manifest_kind": MANIFEST_KIND,
        "git_commit": git_commit,
        "source_date_epoch": source_date_epoch,
        "artifacts": entries,
        "artifact_count": len(entries),
    }
    target = out_dir / MANIFEST_NAME
    target.write_bytes((json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))
    return manifest, target


def build_release(repo_root: Path, out_dir: Path, run=_run_command) -> tuple[dict, Path]:
    """Full slice-1 driver: clean tree, pinned build, artifact manifest."""
    repo_root = Path(repo_root).resolve()
    out_dir = Path(out_dir).resolve()
    commit, epoch = check_clean_tree(repo_root, run=run)
    build_artifacts(repo_root, out_dir, epoch, run=run)
    return write_release_manifest(out_dir, commit, epoch)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--out", required=True,
        help="fresh (empty or nonexistent) directory for the sdist, wheel and release-manifest.json; "
        "keep it outside the repository",
    )
    args = parser.parse_args(argv)
    repo_root = Path(__file__).resolve().parents[1]
    try:
        manifest, target = build_release(repo_root, Path(args.out))
    except ToolError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(f"Manifest: {target}")
    print(f"Commit: {manifest['git_commit']} (SOURCE_DATE_EPOCH={manifest['source_date_epoch']})")
    for entry in manifest["artifacts"]:
        print(f"  {entry['sha256']}  {entry['path']} ({entry['size_bytes']} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
