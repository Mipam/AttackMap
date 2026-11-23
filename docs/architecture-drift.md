# Architecture drift dashboard

Companion to [docs/adr/](adr/index.md) (AR088, AC-409). Reports the trend of
four structural health metrics across commits — the same metrics the AR009
ratchet gates, measured the same way, so a drift reading can never disagree
with the ratchet about the present.

## Metrics

| Key | Meaning | Direction of healthy |
| --- | --- | --- |
| `import_cycles` | Import cycles in the internal package graph (`tools/arch_report`) | down (gate: 0) |
| `fan_in_max` | Highest per-module fan-in — distinct internal importers of any module | down (hotspot watch) |
| `longest_function_lines` | Longest function span in source lines | down |
| `broad_excepts` | `except Exception` / `except BaseException` handlers, AST-counted | down |

Note on definitions: the AR009 ratchet records `models_fan_in` (fan-in of
`attackmap.models` specifically); this dashboard records the **maximum**
fan-in over all modules, which is a different (hotspot-oriented) number.
Both use the same importer-counting code.

## How to run (per release)

From the repo root, project interpreter only:

```bash
.venv/Scripts/python.exe -m tools.arch_drift --since 5ee4d20 --json     # full history since roadmap baseline
.venv/Scripts/python.exe -m tools.arch_drift --since <prev-release-tag> # since the last release
```

- `--since` is inclusive and must be an ancestor of `HEAD`.
- `--max-samples N` (default 8) caps measured commits; the commit list is
  evenly sampled, always including both endpoints.
- Without `--json` the tool prints a human-readable table plus the trend.
- Exit code is 0 on success, 2 on bad input. The tool is read-only: it
  extracts sampled commits with `git archive` into a temp directory and never
  touches the working tree or history.

Publish per release: paste the `--json` output (or the table) into the
release notes and update the "Current values" row below.

## Where the trends come from (method)

For each sampled commit, `tools/arch_drift.py`:

1. `git archive <commit> src/attackmap | tar -x` into a scratch directory —
   no checkout, no working-tree mutation;
2. runs the **same AST machinery as `tools/arch_report`** (imported, not
   re-implemented) on the extracted tree: module graph → cycles, per-module
   importers → fan-in, function spans, `except Exception/BaseException`
   handlers;
3. records the four metrics plus commit sha and subject.

Because the measurement code is shared with the ratchet gate, drift numbers
at any commit are definitionally comparable with `baseline.json`. The
synthetic-repo unit tests (`tests/unit/test_arch_drift.py`) build a tiny
two-commit git repo under `C:/tmp/attackmap-scratch/ar088` and verify exact
counts, JSON shape, and error paths — the real repo's history is never used
in tests.

## Current values

Measured on `codex/windows-build-development`, wave-13 integration
(`tools/arch_report` scope, `src/attackmap`):

| Metric | Roadmap baseline `5ee4d20` | Now (wave 13) | Delta |
| --- | --- | --- | --- |
| import_cycles | 49 | 0 | −49 |
| fan_in_max | 63 | 60 | −3 |
| longest_function_lines | 787 | 750 | −37 |
| broad_excepts | 62 | 63 | +1 |

The last five commits (`HEAD~5..HEAD`) are flat at 0 / 60 / 750 / 63 — no
structural drift in the recent window. The AR009 ratchet baseline
(`docs/architecture-roadmap-2026-11-21/baseline.json`) records the same
current values for `import_cycles`, `longest_function_lines`, and
`broad_excepts`, plus `models_fan_in` 60 and 194 modules; tighten-only.
