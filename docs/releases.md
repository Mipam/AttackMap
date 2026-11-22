# Release engineering

AR085: deterministic release artifacts. Slices 1-2 are wired into a
manual-only workflow (`.github/workflows/release.yml`, `workflow_dispatch`
only, no secrets). Nothing here signs anything or authenticates origin —
SHA-256 values verify content integrity only.

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
3. AC-406 gate (slice 2):
   `python tools/build_release.py --out <fresh-dir> --twice --compare`
   builds a second time into `<fresh-dir>-rebuild` from the same clean-tree
   check and fails (exit 1, listing every mismatching artifact) unless both
   builds produce identical artifact hash sets. Reproducible runs print
   `BUILD REPRODUCIBLE`.
4. `python tools/attest_release.py --manifest <fresh-dir>/release-manifest.json`
   writes the detached `release-manifest.sha256`: one `<sha256>  <path>` line
   per artifact, `sha256sum --check` compatible, no dependencies. This is the
   primitive slice 3 wraps in a real signature.
5. Analyzer lock integrity stays a release gate (AR011):
   `python tools/generate_release_sbom.py --check sbom.json` fails if any
   official plugin is not pinned to an immutable commit.

## CI (manual only)

`.github/workflows/release.yml` runs the same flow on `workflow_dispatch`:

- `reproducible-build`: the pinned toolchain from `constraints.txt`, then
  `build_release.py --out dist --twice --compare`; uploads both build
  directories' manifests and the first build's artifacts.
- `attestation`: `attest_release.py` over the built manifest (stdlib-only,
  installs nothing), verifies it with `sha256sum --check`, uploads it.
- `plugin-lock-sbom`: the AR011 pinned-analyzer check, SBOM uploaded.

There is no publish step and no secret access anywhere in the workflow.

## What slice 3 owes

- Wrap `release-manifest.sha256` in a real signature (Sigstore/cosign or
  equivalent) so hashes authenticate origin, not just content.
- Publication of artifacts + manifest + signature + the Windows ZIP.
- Optionally fold the Windows frozen package (AR043 tooling) into the same
  manifest so all release artifacts share one attestation story.

## Status

Slice 1 (2026-11-22): build driver, manifest, detached sha256 manifest,
focused unit tests (`tests/unit/test_release_tooling.py`).
Slice 2 (2026-11-22): `--twice --compare` reproducibility gate and the
manual-only `release.yml` workflow (build gate, attestation, plugin lock).
