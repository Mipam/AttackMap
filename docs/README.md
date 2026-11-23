# AttackMap documentation index

Start here. This index records **which documents govern work**; the rules are in
[AGENTS.md](../AGENTS.md) and the authority split below follows the owner
decision of 2026-11-23 (commit `11ed09d`).

> The previous version of this file was a long chronicle of dated Windows
> parity checkpoints. That chronicle is historical status prose, not current
> state; it remains recoverable from git history. Current wave state is in the
> latest handoff (below).

## 1. Active authority — read first

| Area | Documents |
| --- | --- |
| Project rules | [AGENTS.md](../AGENTS.md) (repo root) |
| Engine / architecture / reasoning / product surfaces | [architecture-roadmap-2026-11-21/](architecture-roadmap-2026-11-21/roadmap.md) — `roadmap.md`, `criteria.md`, `todo.md`, `backlog.json` (AR001–AR088; 41/56 cards done at wave 13) |
| Windows native surface + Windows M3 | [Roadmap Windows parity](roadmap-windows-parity-2026-10-20.md) · [Windows parity TODO](windows-parity-todo.md) (WP001–WP044) · [Windows parity backlog](windows-parity-backlog.json) |
| Supporting the Windows parity plan (initial findings, not live completion state) | [Windows parity audit](windows-parity-audit-2026-10-20.md) · [source manifest](windows-parity-sources-2026-10-20.json) · [plan validation](verification/windows-parity/plan-validation-2026-10-20.json) |
| Architecture decisions | [adr/](adr/) |
| Architecture drift tracking | [architecture-drift.md](architecture-drift.md) |
| Latest handoff (current wave state, protocol, pitfalls, verify commands) | [handoff-architecture-roadmap-wave13-2026-11-23.md](handoff-architecture-roadmap-wave13-2026-11-23.md) · older: [handoff/](handoff/) |
| Retained evidence (never move/edit/delete) | [verification/](verification/) |

## 2. Onboarding

- [onboarding.md](onboarding.md) — install → first scan → read a report →
  fast tests, under 10 minutes (Windows Git Bash).
- [onboarding-timing.md](onboarding-timing.md) — an actually timed dry run of
  the onboarding steps (2026-11-23).

## 3. Reference

- [reference/](reference/README.md) — static generated snapshots: rule
  catalog, built-in analyzers, `attackmap.sdk` contract surface, detection
  quality baseline. Per-rule prose docs: [reference/rules/](reference/rules/index.md).

## 4. Archive

- [archive/](archive/index.md) — superseded planning and checkpoint prose
  (copied 2026-11-23, AR068). **Not** an independent source of agent tasks,
  priorities, delivery status, or release approval.

## Everything else at this level

All other top-level `*.md` files in `docs/` that are not listed above are
historical working notes (roadmap-era plans, design explorations, dated status
pages). Per `AGENTS.md` they must not be used as a task source or as proof of
current state; read them only as reference for a specific active task, and
verify technical claims against current code.
