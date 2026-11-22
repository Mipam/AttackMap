# Release engineering

AR085 groundwork: deterministic, offline release artifacts. Slice 1 is not
wired into CI yet; nothing here signs anything or authenticates origin —
SHA-256 values verify content integrity only.

## Current flow (slice 1)

Run from a clean worktree on the release commit, with the output directory
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
3. `python tools/attest_release.py --manifest <fresh-dir>/release-manifest.json`
   writes the detached `release-manifest.sha256`: one `<sha256>  <path>` line
   per artifact, `sha256sum --check` compatible, no dependencies. This is the
   primitive a later slice wraps in a real signature.
4. Analyzer lock integrity stays a release gate (AR011):
   `python tools/generate_release_sbom.py --check sbom.json` fails if any
   official plugin is not pinned to an immutable commit.

## Intended later slices (not implemented yet)

- Reproducibility proof for AC-406: two clean builds of the same commit,
  compare artifact hashes (`--twice --compare` driver).
- Attestation wrapped in a real signature; CI publishing of
  `release-manifest.json` + `release-manifest.sha256` alongside the
  Windows ZIP in a `release*.yml` workflow.

## Status

Slice 1 (2026-11-22): build driver, manifest, detached sha256 manifest,
focused unit tests (`tests/unit/test_release_tooling.py`). No CI wiring.
