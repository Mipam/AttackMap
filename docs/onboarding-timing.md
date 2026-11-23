# Onboarding timed dry run

Recorded 2026-11-23 ~22:09–22:11 local (Europe/Prague) by executing
[onboarding.md](onboarding.md) step by step on branch
`codex/windows-build-development`, attackmap **1.5.1**, Windows Git Bash,
project interpreter `.venv/Scripts/python.exe`.

**Deviation from the AR068 brief:** the brief suggested creating a tiny fixture
repo under scratch. The repo already ships three maintained one-file demo apps
in `examples/` made exactly for this purpose, so the dry run scanned
`examples/orders-api-demo` instead of an ad-hoc fixture (more honest about what
a new user actually does).

**Install step (onboarding §1) — not re-executed:** the brief forbids modifying
`.venv`, and this machine's venv was rebuilt on 2026-11-23 (handoff §0) with
`py -3.13 -m venv`, the `setuptools<80` pin, and `pip install -e ".[llm,dev]"`
already applied. The install commands were validated as pre-satisfied
prerequisites (`attackmap --version` and the scan below both run from that
venv) rather than re-run. On a fresh machine they take ~5 min once.

## Measured steps

| # | Step (onboarding §) | Command (as run) | Wall time |
| --- | --- | --- | --- |
| 0 | Prereq (§0) | `py -3.13 --version` | ~0.1 s |
| 1 | Smoke check (§2) | `.venv/Scripts/python.exe -m attackmap --version` → `attackmap 1.5.1` | 1.4 s |
| 2 | Scan (§3) | `.venv/Scripts/python.exe -m attackmap analyze examples/orders-api-demo --output C:/tmp/attackmap-onboarding --no-progress --time-budget-seconds 120` | 2.2 s, exit 0 |
| 3 | List reports (§4) | `ls C:/tmp/attackmap-onboarding` + `ls <generation-id>` | <0.5 s |
| 4 | Read report (§4) | opened `defensive-review.md` (113 lines; HIGH SQL injection + auth findings, 1 attack path) | ~2 min human reading |
| 5 | Fast tests (§5) | `.venv/Scripts/python.exe -m pytest tests/architecture -q` | **11 passed** in 4.7 s (exit 0) |
| 6 | Tour (§6) | `... rules list` (1.4 s), `... modules` (2.4 s), `... analyze --help` | ~4 s, all exit 0 |

Timestamps: first command 22:09:20, last command 22:10:30.

## Totals

- Command execution: **~70 s** for steps 0–3 + 5–6.
- Including human report reading: **≈ 3.5 min**.
- Budget: < 10 min excluding install. **PASS** with large margin.

## Scan result snapshot (evidence the walkthrough really ran)

```
Scanned 1 files · Routes: 4 · Datastores: 2
[HIGH] Request input flows into a raw SQL query (SQL injection) (exploitability 85/100)
[HIGH] State-changing routes are reachable without an authentication control
[MEDIUM] Public routes likely sit close to sensitive data operations
[MEDIUM] Secret-bearing environment variables are referenced in executable paths
Attack path: Public input into sensitive data path
Reports written to: C:\tmp\attackmap-onboarding\20261123T211005-e740c9487e714963a18966d409763613
```

Note: reports are written to a timestamped generation **subdirectory** of
`--output`; onboarding.md §4 documents this.
