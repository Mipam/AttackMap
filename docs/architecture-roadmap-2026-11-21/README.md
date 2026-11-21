# Architecture & Product Roadmap — 2026-11-21

**Status: PROPOSED.** This plan is *not yet* the active implementation authority.

## Why this folder exists

The 2026-11-21 principal-architect review of AttackMap found a specific shape: five
exemplary subsystems (artifact publication, process supervision, the analyzer SDK, the
isolated analyzer host, the safe filesystem layer) surrounded by a flat 111-module
namespace with 44 import cycles, a 33-field god aggregate, three parallel option
structs, and no static gates in CI.

This plan converts that review into executable work. It is deliberately **not** written
as an append-only checkpoint log. It has exactly four living documents:

| Document | Role |
| --- | --- |
| [`roadmap.md`](roadmap.md) | Product + architecture roadmap: phases, capability outcomes, exit gates, KPIs, sequencing. |
| [`criteria.md`](criteria.md) | Acceptance criteria `AC-001`–`AC-409`. Each is measurable and has a verification command. |
| [`todo.md`](todo.md) | Executable task cards `AR001`–`AR088`: scope, files, steps, dependencies, acceptance, verification. |
| [`backlog.json`](backlog.json) | Machine-readable counterpart: ids, phases, priorities, dependencies, criteria links, parallel-work leases. |

## Relationship to the active Windows-parity plan

This plan **does not** change `WP001`–`WP044`, their statuses, or their acceptance gates.

- `docs/roadmap-windows-parity-2026-10-20.md`, `docs/windows-parity-todo.md` and
  `docs/windows-parity-backlog.json` remain authoritative for the **Windows native
  surface** and for Windows M3 acceptance.
- This plan governs **engine, architecture, reasoning, and product-surface** work.
- `AR` tasks must not modify `docs/verification/windows-parity/**` evidence, nor
  `docs/windows-parity-*`, nor retained fixtures. If an `AR` task touches a file owned
  by an open `WP` task, the `WP` lease rules win.
- Phase 0 and Phase 1 are engine-only and may proceed in parallel with non-Windows work.
  Phase 3 GUI work must be coordinated with whichever `WP` currently owns
  `src/attackmap/ui/**` and the native shell.

**Promotion requires an explicit owner decision.** Until `AGENTS.md` names this plan in
its documentation-authority section, treat it as a proposal: useful, reviewable, and
safe to ignore.

## How an agent starts

1. Read `roadmap.md` §3 (phases) and §5 (sequencing) to find the current phase.
2. Open `todo.md` and pick the lowest-id task whose dependencies are `DONE`.
3. Check `backlog.json` for `lease_key` conflicts before touching files.
4. Implement, then verify against the `Acceptance` line using the exact commands given.
5. Update **only** this folder's four documents. Do not append dated checkpoint
   paragraphs to `docs/README.md`.

## Ground truth used by this plan

Measured on `HEAD 5ee4d20` (branch `codex/windows-build-development`):

| Metric | Value |
| --- | --- |
| Modules in `src/attackmap` | 131 (111 flat at package root) |
| Import cycles | 44 |
| `models` fan-in | 64 / 131 |
| `ScanResult` fields | 33 |
| Longest function | 787 lines (`generate_findings`) |
| Functions > 80 lines | 74 |
| Broad `except Exception` | 62 |
| Modules importing `logging` | 3 / 131 |
| Test functions | 2,764 across 338 files (230 at `tests/` root) |
| Lint / type / coverage gates | none |
| Default time budget | 600 s, checked at stage boundaries only |

Any threshold in `criteria.md` is expressed relative to these numbers, so the plan stays
honest if the baseline moves.
