"""Detached SHA-256 attestation manifest for release artifacts (AR085 slice 1).

Given a ``release-manifest.json`` produced by tools/build_release.py, writes a
detached ``release-manifest.sha256`` with one ``<sha256>  <path>`` line per
artifact, compatible with ``sha256sum --check`` when run from the artifact
directory. Deliberately dependency-free and unsigned: this is the
deterministic primitive a later slice will wrap in a real signature. The
hashes verify content integrity only; they do not authenticate origin.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA_VERSION = 1
EXPECTED_KIND = "attackmap-release-artifacts"
DEFAULT_OUTPUT_NAME = "release-manifest.sha256"
SAFE_ENTRY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ToolError(Exception):
    """Fatal validation failure; the detached manifest is not written."""


def load_manifest(manifest_path: Path) -> list[tuple[str, str]]:
    """Validate a release-manifest.json and return sorted (path, sha256) pairs."""
    if not manifest_path.is_file():
        raise ToolError(f"Release manifest not found: {manifest_path}")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except ValueError as error:
        raise ToolError(f"release-manifest.json is not valid JSON: {error}") from error
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ToolError(f"Unsupported manifest schema_version: {manifest.get('schema_version')}")
    if manifest.get("manifest_kind") != EXPECTED_KIND:
        raise ToolError(f"Not an {EXPECTED_KIND} manifest: {manifest.get('manifest_kind')!r}")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ToolError("Manifest records no artifacts")
    entries: list[tuple[str, str]] = []
    seen: set[str] = set()
    for entry in artifacts:
        name = entry.get("path", "")
        digest = entry.get("sha256", "")
        if not SAFE_ENTRY.match(name) or name in {".", ".."}:
            raise ToolError(f"Unsafe artifact path: {name!r}")
        if not SHA256.match(digest):
            raise ToolError(f"Invalid sha256 for {name}: {digest!r}")
        if name in seen:
            raise ToolError(f"Duplicate artifact entry: {name}")
        seen.add(name)
        entries.append((name, digest))
    return sorted(entries)


def render_detached(entries: list[tuple[str, str]]) -> str:
    """Render the sha256sum-compatible body: one '<hash>  <path>' line per artifact."""
    return "".join(f"{digest}  {name}\n" for name, digest in entries)


def write_detached(manifest_path: Path, output: Path | None = None) -> Path:
    """Write release-manifest.sha256 next to the manifest (or at output) and return its path."""
    manifest_path = Path(manifest_path)
    entries = load_manifest(manifest_path)
    target = Path(output) if output is not None else manifest_path.parent / DEFAULT_OUTPUT_NAME
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(render_detached(entries).encode("utf-8"))
    return target


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--manifest", required=True, help="release-manifest.json from tools/build_release.py")
    parser.add_argument(
        "--output", help=f"detached manifest target (default: {DEFAULT_OUTPUT_NAME} next to --manifest)",
    )
    args = parser.parse_args(argv)
    try:
        target = write_detached(Path(args.manifest), Path(args.output) if args.output else None)
    except ToolError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(f"Detached manifest: {target}")
    for line in target.read_text(encoding="utf-8").splitlines():
        print(f"  {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
