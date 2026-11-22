"""Reproducible release build driver (AR085).

Refuses to run unless the working tree is exactly clean (``git status
--porcelain`` empty), pins ``SOURCE_DATE_EPOCH`` to the HEAD commit's
committer timestamp, builds the sdist and wheel with ``python -m build
--no-isolation`` (so the constraints-pinned environment, not a freshly
resolved one, produces the artifacts), and records the SHA-256 and size of
every artifact into ``release-manifest.json`` next to them. Nothing here
signs or publishes anything; docs/releases.md describes the intended flow
and the attestation step (tools/attest_release.py).

``--twice --compare`` is the AC-406 gate primitive: two independent builds
of the same clean tree (the second into ``<out>-rebuild``) must produce
identical artifact hash sets; the run exits 0 only when they do, and lists
every mismatching artifact otherwise. A build-comparison failure exits 1;
validation failures (dirty tree, bad environment, build errors) exit 2.

``--publish DEST`` copies the attested build into a flat ``DEST/release``
layout (artifacts, release-manifest.json, release-manifest.sha256, and the
signature when one exists) and re-verifies every hash after the copy; any
copy or hash failure removes what it wrote so a partial publish can never
look complete.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

SCHEMA_VERSION = 1
MANIFEST_KIND = "attackmap-release-artifacts"
MANIFEST_NAME = "release-manifest.json"
DETACHED_MANIFEST_NAME = "release-manifest.sha256"
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
    """Single-build driver: clean tree, pinned build, artifact manifest."""
    repo_root = Path(repo_root).resolve()
    out_dir = Path(out_dir).resolve()
    commit, epoch = check_clean_tree(repo_root, run=run)
    build_artifacts(repo_root, out_dir, epoch, run=run)
    return write_release_manifest(out_dir, commit, epoch)


def build_twice(repo_root: Path, out_dir: Path, run=_run_command):
    """Two independent builds of one clean tree; the second goes to <out>-rebuild.

    The clean tree is checked once and both builds share its commit and
    SOURCE_DATE_EPOCH: the AC-406 gate compares two builds of the same commit,
    never two states of the tree. Returns (first, second, second_dir) where
    each build result is (manifest, manifest_path).
    """
    repo_root = Path(repo_root).resolve()
    out_dir = Path(out_dir).resolve()
    second_dir = out_dir.with_name(out_dir.name + "-rebuild")
    commit, epoch = check_clean_tree(repo_root, run=run)
    build_artifacts(repo_root, out_dir, epoch, run=run)
    build_artifacts(repo_root, second_dir, epoch, run=run)
    first = write_release_manifest(out_dir, commit, epoch)
    second = write_release_manifest(second_dir, commit, epoch)
    return first, second, second_dir


def compare_builds(first_dir: Path, second_dir: Path) -> tuple[bool, list[str]]:
    """Compare the two builds' artifact hash sets by name.

    Returns (reproducible, mismatch lines); an empty mismatch list means the
    builds are byte-identical as far as SHA-256 can attest.
    """
    def inventory(directory: Path) -> dict[str, str]:
        return {path.name: sha256_file(path) for path in collect_artifacts(directory)}

    first = inventory(Path(first_dir))
    second = inventory(Path(second_dir))
    mismatches = []
    for name in sorted(set(first) | set(second)):
        if name not in second:
            mismatches.append(f"{name}: present only in the first build")
        elif name not in first:
            mismatches.append(f"{name}: present only in the second build")
        elif first[name] != second[name]:
            mismatches.append(f"{name}: sha256 {first[name]} != {second[name]}")
    return not mismatches, mismatches


def _print_manifest(label: str, manifest: dict, target: Path) -> None:
    print(f"{label}: {target}")
    print(f"Commit: {manifest['git_commit']} (SOURCE_DATE_EPOCH={manifest['source_date_epoch']})")
    for entry in manifest["artifacts"]:
        print(f"  {entry['sha256']}  {entry['path']} ({entry['size_bytes']} bytes)")


def _load_attest_module():
    """Load tools/attest_release.py from this script's directory (same lease, one parser)."""
    spec = importlib.util.spec_from_file_location(
        "ar085_attest_release", Path(__file__).resolve().parent / "attest_release.py"
    )
    if spec is None or spec.loader is None:
        raise ToolError("Could not load tools/attest_release.py for detached-manifest handling")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def publish_release(build_dir: Path, dest: Path) -> list[Path]:
    """Copy the attested build into a flat <dest>/release layout, re-verifying every hash.

    Creates the detached sha256 manifest when it is missing (same deterministic
    format as tools/attest_release.py), copies the signature when one exists,
    and refuses to publish without a valid manifest pair. On any copy or hash
    mismatch the files it wrote are removed, so a partial publish can never
    look complete. Returns the sorted list of published paths.
    """
    build_dir = Path(build_dir).resolve()
    dest = Path(dest).resolve()
    target = dest / "release"
    manifest_path = build_dir / MANIFEST_NAME
    detached_path = build_dir / DETACHED_MANIFEST_NAME
    if not manifest_path.is_file():
        raise ToolError(f"No {MANIFEST_NAME} in {build_dir}; publish follows a build")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except ValueError as error:
        raise ToolError(f"{MANIFEST_NAME} is not valid JSON: {error}") from error
    if manifest.get("schema_version") != SCHEMA_VERSION or manifest.get("manifest_kind") != MANIFEST_KIND:
        raise ToolError(f"Unsupported or malformed {MANIFEST_NAME}")
    if not isinstance(manifest.get("artifacts"), list) or not manifest["artifacts"]:
        raise ToolError(f"{MANIFEST_NAME} records no artifacts")

    attest = _load_attest_module()
    if not detached_path.is_file():
        detached_path = attest.write_detached(manifest_path)
    entries = {
        entry["path"]: entry["sha256"]
        for entry in manifest["artifacts"]
        if isinstance(entry.get("path"), str) and isinstance(entry.get("sha256"), str)
    }
    if len(entries) != len(manifest["artifacts"]):
        raise ToolError(f"{MANIFEST_NAME} has an artifact entry missing path or sha256")
    detached = attest.parse_detached(detached_path)
    if entries != detached:
        raise ToolError(f"{MANIFEST_NAME} and {DETACHED_MANIFEST_NAME} disagree; refusing to publish")

    sig_path = build_dir / (DETACHED_MANIFEST_NAME + ".sig")
    copies = [(build_dir / name, target / name) for name in sorted(entries)]
    copies.append((manifest_path, target / MANIFEST_NAME))
    copies.append((detached_path, target / DETACHED_MANIFEST_NAME))
    if sig_path.is_file():
        copies.append((sig_path, target / sig_path.name))

    target_existed = target.exists()
    if target_existed and any(target.iterdir()):
        raise ToolError(f"Refusing to publish into a non-empty directory: {target}")
    target.mkdir(parents=True, exist_ok=True)
    copied: list[Path] = []
    try:
        for source, destination in copies:
            shutil.copy2(source, destination)
            copied.append(destination)
        for source, destination in copies:
            if source.read_bytes() != destination.read_bytes():
                raise ToolError(f"Copied file differs from its source: {destination.name}")
        for name, digest in sorted(entries.items()):
            if sha256_file(target / name) != digest:
                raise ToolError(f"Post-copy hash mismatch: {name}")
    except Exception:
        for path in copied:
            path.unlink(missing_ok=True)
        if not target_existed:
            shutil.rmtree(target, ignore_errors=True)
        raise
    return [destination for _, destination in copies]


def _publish_and_report(build_dir: Path, dest: str) -> None:
    published = publish_release(build_dir, Path(dest))
    print(f"Published {len(published)} files to {Path(dest).resolve() / 'release'}")
    for path in published:
        print(f"  {path}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--out", required=True,
        help="fresh (empty or nonexistent) directory for the sdist, wheel and release-manifest.json; "
        "keep it outside the repository",
    )
    parser.add_argument(
        "--twice", action="store_true",
        help="build a second time into <out>-rebuild from the same clean tree (AC-406)",
    )
    parser.add_argument(
        "--compare", action="store_true",
        help="with --twice: fail the run when the two builds' artifacts differ",
    )
    parser.add_argument(
        "--publish", metavar="DEST",
        help="after a successful build: copy the artifacts, both manifests and the signature "
        "(when present) into a flat DEST/release layout, re-verifying every hash after the copy",
    )
    args = parser.parse_args(argv)
    if args.compare and not args.twice:
        parser.error("--compare requires --twice")
    repo_root = Path(__file__).resolve().parents[1]
    try:
        if args.twice:
            out_dir = Path(args.out).resolve()
            first, second, second_dir = build_twice(repo_root, out_dir)
            _print_manifest("First manifest", first[0], first[1])
            _print_manifest("Second manifest", second[0], second[1])
            reproducible, mismatches = compare_builds(out_dir, second_dir)
            if reproducible:
                print("BUILD REPRODUCIBLE")
                if args.publish:
                    _publish_and_report(out_dir, args.publish)
                return 0
            print("BUILD NOT REPRODUCIBLE", file=sys.stderr)
            for line in mismatches:
                print(f"  {line}", file=sys.stderr)
            return 1
        manifest, target = build_release(repo_root, Path(args.out))
    except ToolError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    _print_manifest("Manifest", manifest, target)
    if args.publish:
        _publish_and_report(Path(args.out).resolve(), args.publish)
    return 0


if __name__ == "__main__":
    sys.exit(main())
