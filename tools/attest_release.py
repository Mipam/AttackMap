"""Detached SHA-256 attestation and Ed25519 signing for release artifacts (AR085).

Given a ``release-manifest.json`` produced by tools/build_release.py, writes a
detached ``release-manifest.sha256`` with one ``<sha256>  <path>`` line per
artifact, compatible with ``sha256sum --check`` when run from the artifact
directory.

Slice 3 adds real signing on top of that primitive:

- ``--sign KEY_DIR`` writes the detached manifest and signs its exact bytes
  with an Ed25519 keypair stored in (or generated on first use into)
  KEY_DIR. The private key is an unencrypted PKCS8 PEM written 0600
  (best-effort on Windows); never hardcode or commit keys.
- ``--detached D --verify PUBLIC_KEY`` verifies the signature over the
  detached manifest and re-hashes every artifact the manifest lists, so both
  tampered manifests and tampered artifacts fail verification.

The cryptography package is required for both modes. When it is not
importable the tool exits 3 with an honest message instead of emitting or
accepting a fake signature. Hashes always verify content integrity only;
origin authentication comes from the signature and whoever publishes the
public key.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import sys
from pathlib import Path

SCHEMA_VERSION = 1
EXPECTED_KIND = "attackmap-release-artifacts"
DEFAULT_OUTPUT_NAME = "release-manifest.sha256"
SIGNATURE_SUFFIX = ".sig"
PRIVATE_KEY_NAME = "release-signing-private.pem"
PUBLIC_KEY_NAME = "release-signing-public.pem"
SAFE_ENTRY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
DETACHED_LINE = re.compile(r"^([0-9a-f]{64})  (.+)$")


class ToolError(Exception):
    """Fatal validation failure; the requested output is not written."""


class SigningUnavailable(ToolError):
    """cryptography is not importable; an honest failure beats a fake signature."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _crypto():
    """Import cryptography lazily; returns the symbols signing/verification need."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as error:
        raise SigningUnavailable(
            "Signing requires the 'cryptography' package, which is not importable in this "
            "interpreter; refusing to emit or accept a fake signature. Install it and retry."
        ) from error
    return serialization, Ed25519PrivateKey, Ed25519PublicKey, InvalidSignature


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


def parse_detached(detached_path: Path) -> dict[str, str]:
    """Parse a detached sha256 manifest into {path: sha256}, validating the format."""
    if not detached_path.is_file():
        raise ToolError(f"Detached manifest not found: {detached_path}")
    entries: dict[str, str] = {}
    for line in detached_path.read_text(encoding="utf-8").splitlines():
        match = DETACHED_LINE.match(line)
        if match is None:
            raise ToolError(f"Malformed detached manifest line: {line!r}")
        name, digest = match.group(2), match.group(1)
        if not SAFE_ENTRY.match(name) or name in {".", ".."}:
            raise ToolError(f"Unsafe artifact path in detached manifest: {name!r}")
        if name in entries:
            raise ToolError(f"Duplicate artifact entry in detached manifest: {name}")
        entries[name] = digest
    if not entries:
        raise ToolError("Detached manifest records no artifacts")
    return entries


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


def _write_restricted(path: Path, data: bytes) -> None:
    """Write bytes with 0600 permissions (best-effort where the OS ignores the mode)."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
    with contextlib.suppress(OSError):  # e.g. Windows ACLs do not map chmod; advisory there
        os.chmod(path, 0o600)


def _load_or_create_keypair(key_dir: Path):
    """Load the Ed25519 signing key from KEY_DIR, generating the pair on first use."""
    serialization, Ed25519PrivateKey, _, _ = _crypto()
    key_dir = Path(key_dir)
    private_path = key_dir / PRIVATE_KEY_NAME
    public_path = key_dir / PUBLIC_KEY_NAME
    if private_path.is_file():
        try:
            private_key = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
        except (ValueError, OSError) as error:
            raise ToolError(f"Could not load signing private key {private_path}: {error}") from error
    elif public_path.is_file():
        raise ToolError(
            f"Public key exists without a private key in {key_dir}; refusing to generate a new "
            "keypair that would silently rotate the release signing identity"
        )
    else:
        private_key = Ed25519PrivateKey.generate()
        key_dir.mkdir(parents=True, exist_ok=True)
        _write_restricted(
            private_path,
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )
    public_path.parent.mkdir(parents=True, exist_ok=True)
    if not public_path.is_file():
        public_path.write_bytes(
            private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    return private_key


def sign_detached(detached_path: Path, key_dir: Path) -> Path:
    """Sign the detached manifest's exact bytes with Ed25519; returns the .sig path."""
    detached_path = Path(detached_path)
    parse_detached(detached_path)  # refuse to sign malformed or fake content
    private_key = _load_or_create_keypair(Path(key_dir))
    signature = private_key.sign(detached_path.read_bytes())
    sig_path = detached_path.with_name(detached_path.name + SIGNATURE_SUFFIX)
    sig_path.write_bytes(signature)
    return sig_path


def verify_detached(detached_path: Path, public_key_path: Path) -> tuple[bool, list[str]]:
    """Verify the signature and re-hash every artifact the detached manifest lists.

    Returns (ok, reasons): tampering with either the detached manifest itself
    (signature mismatch) or any artifact it lists (hash mismatch) fails.
    """
    serialization, _, Ed25519PublicKey, InvalidSignature = _crypto()
    detached_path = Path(detached_path)
    sig_path = detached_path.with_name(detached_path.name + SIGNATURE_SUFFIX)
    if not sig_path.is_file():
        raise ToolError(
            f"Signature file not found: {sig_path}; run --sign before --verify"
        )
    try:
        public_key = serialization.load_pem_public_key(Path(public_key_path).read_bytes())
    except (ValueError, OSError) as error:
        raise ToolError(f"Could not load public key {public_key_path}: {error}") from error
    if not isinstance(public_key, Ed25519PublicKey):
        raise ToolError(f"Not an Ed25519 public key: {public_key_path}")

    reasons: list[str] = []
    artifacts_dir = detached_path.parent
    for name, digest in sorted(parse_detached(detached_path).items()):
        artifact = artifacts_dir / name
        if not artifact.is_file():
            reasons.append(f"{name}: artifact missing")
        elif sha256_file(artifact) != digest:
            reasons.append(f"{name}: artifact hash does not match the manifest")
    try:
        public_key.verify(sig_path.read_bytes(), detached_path.read_bytes())
    except InvalidSignature:
        reasons.append("signature does not match the detached manifest (tampered or wrong key)")
    return not reasons, reasons


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--manifest", help="release-manifest.json from tools/build_release.py (write/sign modes)")
    parser.add_argument(
        "--output", help=f"detached manifest target (default: {DEFAULT_OUTPUT_NAME} next to --manifest)",
    )
    parser.add_argument(
        "--sign", metavar="KEY_DIR",
        help="write the detached manifest, then sign its exact bytes with the Ed25519 keypair "
        "stored in (or generated on first use into) KEY_DIR",
    )
    parser.add_argument(
        "--verify", metavar="PUBLIC_KEY",
        help="verify the signature over the detached manifest given by --detached and re-hash "
        "every artifact it lists",
    )
    parser.add_argument("--detached", help=f"detached manifest to verify, e.g. {DEFAULT_OUTPUT_NAME}")
    args = parser.parse_args(argv)
    if args.verify and (args.sign or args.manifest or args.output):
        parser.error("--verify takes only --detached")
    if args.verify and not args.detached:
        parser.error("--verify requires --detached")
    try:
        if args.verify:
            ok, reasons = verify_detached(Path(args.detached), Path(args.verify))
            if ok:
                print(f"VERIFIED: {args.detached}")
                return 0
            print("VERIFY FAILED", file=sys.stderr)
            for reason in reasons:
                print(f"  {reason}", file=sys.stderr)
            return 1
        if args.sign:
            if not args.manifest:
                parser.error("--sign requires --manifest")
            target = write_detached(Path(args.manifest), Path(args.output) if args.output else None)
            sig_path = sign_detached(target, Path(args.sign))
            print(f"Detached manifest: {target}")
            print(f"Signature: {sig_path}")
            print(f"Keypair: {Path(args.sign)} ({PRIVATE_KEY_NAME}, {PUBLIC_KEY_NAME})")
            return 0
        if not args.manifest:
            parser.error("--manifest is required (or use --sign / --verify)")
        target = write_detached(Path(args.manifest), Path(args.output) if args.output else None)
    except SigningUnavailable as error:
        print(f"error: {error}", file=sys.stderr)
        return 3
    except ToolError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(f"Detached manifest: {target}")
    for line in target.read_text(encoding="utf-8").splitlines():
        print(f"  {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
