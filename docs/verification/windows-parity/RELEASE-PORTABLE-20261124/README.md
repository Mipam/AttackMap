# RELEASE-PORTABLE-20261124 — unsigned portable Windows build

Standalone Windows package built from the current core tree. Unsigned
development channel, same scope as RELEASE-PORTABLE-20261107 (no signing, no
installer/MSIX).

## Source

| Fact | Value |
| --- | --- |
| Branch / HEAD | `codex/windows-build-development` at `8c7161f` |
| Core version | `attackmap 1.5.1` |
| Build date | 2026-11-24 (UTC stage id `dev-20261124151344-38a8aa57`) |
| Release lock | `C:/tmp/attackmap-scratch/winbuild-20261124/lock/release-lock.json` (244 release inputs, toolchain identities for python/pyinstaller/dotnet_sdk) |
| Engine | PyInstaller one-dir freeze, bound to the release lock (source/toolchain/analyzer-requirements checksums) |

## Artifacts

Delivered at `C:\Projects\FINISHED\AttackMap-Windows-20261124\`:

| Artifact | Size / hash |
| --- | --- |
| `AttackMap-Windows\` (extracted portable app) | 892 files; per-file inventory + SHA-256 in `portable-inventory.json` |
| `AttackMap-1.5.1-windows-x64-portable-20261124.zip` | 121,318,423 bytes, SHA-256 `a63ffe45155ede5c3dab9d516c0ff096a0229302ecaa2ed6d0a11308c84d8982` (sidecar `.sha256` present) |
| Original stage ZIP | `dev-20261124151344-38a8aa57.zip`, 124,123,570 bytes, SHA-256 `54799327ce61858cb35dd19b8a9d273675a811702b764d09934585fe0306a9af` (in `desktop/windows/artifacts/development-packages/`) |

Contents: WinUI 3 native shell (`AttackMap.NativeSpike.exe`, self-contained
.NET 8 + Windows App SDK 2.4), frozen Python engine at `engine/attackmap.exe`
(15 bundled analyzer packages from the public `mlaify` pins, loading through
the core v1 adapter — protocol flip to Mipam forks is wave-22 core
integration, not part of this build), SBOM (`release-sbom.json`), provenance
(stage manifest, release lock, engine verification, native build proof,
source binding).

## Verification (all on this host)

- Release test set: **320 passed, 1 skipped** (desktop/windows test projects).
- Frozen engine proof: **21 modules discovered**, native broker commands
  present, atomic scan + frozen compare action ready; scan exit 0 /
  `completed` / artifact `ready`; action exit 0 / `completed`; desktop schema
  versions 1.0–1.5. Record: `AttackMap-Windows/provenance/engine-verification.json`.
- Native publish proof: `provenance/native-build-proof.json` (inputs unchanged
  before/after publish).
- Portable transform: every copied byte re-hashed against the stage manifest,
  stage + stage ZIP re-inventoried unchanged after packaging, ZIP CRC-verified
  entry by entry. Record: `portable-transform-verification.json`.
- Post-copy smoke from `FINISHED`: `engine\attackmap.exe --version` →
  `attackmap 1.5.1`; `modules --json` lists the bundled analyzers.

## Deviations from the 20261107 flow

- Build environment: Git Bash lacks `ProgramFiles`/`ProgramFiles(x86)`/
  `ProgramData`/`PUBLIC`/`ComSpec` and sets `TEMP=/tmp`; NuGet/MSBuild need
  Windows-style values. The publish driver sets them explicitly and runs
  `dotnet build-server shutdown` first (stale build servers cached the
  poisoned environment). Root cause of the `Value cannot be null
  (Parameter 'path1')` NuGet failure.
- `desktop/windows/fixtures/findings.json` (deterministic generated fixture)
  was missing on current HEAD; regenerated, hash verified, release lock
  regenerated afterwards.
- The frozen engine's `engine-verification.json` listed itself in
  `payload_files`; the packager requires the proof not to reference itself, so
  that single self-referential row was removed (file content otherwise
  untouched; the manifest re-hashes the proof at stage time).
- `portable_transform.py` (scratch helper): the portable inventory snapshot
  moved after SBOM generation so `release-sbom.json` is included in the
  inventory and the ZIP (previously the final consistency assert failed).

## Open findings (not fixed in this build)

- **Juice-shop report self-compare fails on current HEAD**: "Ambiguous finding
  identity" during compare of a freshly scanned juice-shop report. Genuine
  current-core finding surfaced by the release verification; recorded for a
  core wave, not worked around here.
- Analyzer plugin repos: migration to the `Mipam` forks (SDK v2 declarations)
  is wave-22 core integration; this build intentionally bundles the public
  `mlaify` pins (content unchanged apart from the protocol adapter path).
- WP043 rendering acceptance stays FAILED as recorded; nothing in this build
  addresses it. Clean-host and manual acceptance gates remain open, same as
  20261107.
- Known pre-existing plugin test drift (c/cpp `native_sinks`/`native_deps`,
  iac conformance, terraform CRLF fixtures, swift `AppSurfaceIssue` port) was
  catalogued during wave 22; the frozen engine loads all bundled analyzers
  successfully (21 modules), so runtime behavior is unaffected.

## Rollback / reproducibility

Re-run from HEAD `8c7161f`: regenerate the release lock, freeze the engine,
verify it (`engine-verification.json`), publish the native shell with the
fixed environment, run `tools/package_native_windows.ps1 -Profile
RequiredBundled`, then the portable transform. All scratch inputs from this
build are under `C:/tmp/attackmap-scratch/winbuild-20261124/`.
