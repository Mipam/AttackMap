# Release engineering

AR085: deterministic release artifacts with signing and publication.
`.github/workflows/release.yml` is manual-only (`workflow_dispatch`, no
publish step). SHA-256 values verify content integrity; the Ed25519
signature (slice 3) is what binds them to a signing identity.

## Local flow

Run from a clean worktree on the release commit, with output directories
outside the repository:

1. `tools/build_release.py` refuses to run unless `git status --porcelain`
   is empty, so a manifest can honestly tie hashes to a commit.
2. `python tools/build_release.py --out <fresh-dir>` builds the sdist and
   wheel with `python -m build --no-isolation` and `SOURCE_DATE_EPOCH` pinned
   to the HEAD commit's committer timestamp, then writes
   `release-manifest.json` next to the artifacts with a SHA-256 and size for
   each one. It refuses a non-empty output directory so artifacts from two
   builds are never mixed.
   `--no-isolation` is deliberate: an isolated build resolves
   `setuptools>=68` to whatever is newest and breaks reproducibility. The
   interpreter must have `build`, `setuptools` and `wheel` importable (the
   driver preflights this and says which are missing); pins live in
   `constraints.txt` alongside the rest of the toolchain.
3. AC-406 gate:
   `python tools/build_release.py --out <fresh-dir> --twice --compare`
   builds a second time into `<fresh-dir>-rebuild` from the same clean-tree
   check and fails (exit 1, listing every mismatching artifact) unless both
   builds produce identical artifact hash sets. Reproducible runs print
   `BUILD REPRODUCIBLE`.
4. Attestation:
   `python tools/attest_release.py --manifest <fresh-dir>/release-manifest.json`
   writes the detached `release-manifest.sha256`: one `<sha256>  <path>` line
   per artifact, `sha256sum --check` compatible, no dependencies.
5. Signing (slice 3), requires the `cryptography` package:
   - `python tools/attest_release.py --manifest <m> --sign <key-dir>` rewrites
     the detached manifest and signs its exact bytes with an Ed25519 keypair
     stored in (or generated on first use into) `<key-dir>`, producing
     `release-manifest.sha256.sig`. The private key is an unencrypted PKCS8
     PEM written 0600 (best-effort on Windows); keep the key dir out of the
     repository and protect it accordingly. A key dir holding a public key
     without its private key is refused, so a re-run can never silently
     rotate the signing identity.
   - `python tools/attest_release.py --detached <dir>/release-manifest.sha256
     --verify <key-dir>/release-signing-public.pem` verifies the signature
     and re-hashes every artifact the manifest lists: a tampered manifest or
     a one-byte-flipped artifact both fail (exit 1). Where `cryptography` is
     not importable, sign/verify exit 3 with an honest message instead of
     faking a result.
6. Publication:
   `python tools/build_release.py --out <dir> --publish <dest>` (combinable
   with `--twice --compare`, and skipped when the gate fails) copies the
   artifacts, both manifests and the signature into a flat
   `<dest>/release/` layout, re-verifying every hash after the copy. Any
   copy or hash mismatch removes what it wrote: a partial publish can never
   look complete.
7. Analyzer lock integrity stays a release gate (AR011):
   `python tools/generate_release_sbom.py --check sbom.json` fails if any
   official plugin is not pinned to an immutable commit.

## CI (manual only)

`.github/workflows/release.yml` runs the flow on `workflow_dispatch`:

- `reproducible-build`: the pinned toolchain from `constraints.txt`, then
  `build_release.py --out dist --twice --compare`; uploads artifacts and
  both manifests.
- `attestation`: `attest_release.py` over the built manifest (stdlib-only,
  installs nothing), verifies it with `sha256sum --check`, uploads it.
- `sign` (optional): runs only when a signing key is configured; otherwise
  its first step prints a clear skip message and the job succeeds.
  - Configure: repo **variable** `RELEASE_SIGNING_PUBLIC_KEY` (the Ed25519
    public PEM) and repo **secret** `RELEASE_SIGNING_PRIVATE_KEY` (the
    matching PKCS8 private PEM). Generate a keypair locally with
    `attest_release.py --manifest <m> --sign <key-dir>` and copy the two
    PEMs out of `<key-dir>`. Keys are never hardcoded in the workflow; the
    private key is read from the secret into `signing-key/` at run time and
    the job fails (rather than skipping) if the public variable is set but
    the private secret is missing.
  - Signing installs `cryptography>=42`; this signing-time dependency is
    intentionally not pinned in `constraints.txt` yet — pin it there when
    it becomes a general dev dependency.
- `plugin-lock-sbom`: the AR011 pinned-analyzer check, SBOM uploaded.

There is no publish step and no other secret access in the workflow; the
sign job only emits `release-manifest.sha256.sig` as a workflow artifact.

## Status

Slice 1 (2026-11-22): build driver, manifest, detached sha256 manifest,
focused unit tests (`tests/unit/test_release_tooling.py`).
Slice 2 (2026-11-22): `--twice --compare` reproducibility gate and the
manual-only `release.yml` workflow (build gate, attestation, plugin lock).
Slice 3 (2026-11-22): Ed25519 `--sign`/`--verify` with honest exit 3 when
cryptography is absent, `--publish DEST` with post-copy re-verification,
and the optional CI `sign` job.

## Next (post-AR085)

- Publish step: upload `DEST/release/` (artifacts + manifests + signature)
  to the release location once signing keys are provisioned.
- Optionally fold the Windows frozen package into the same manifest so all
  release artifacts share one attestation story.
