# Onboarding — first scan in under 10 minutes

Concrete path from a fresh checkout to a verified working install on
**Windows + Git Bash**. Every command below was executed successfully on
2026-11-23 (branch `codex/windows-build-development`, attackmap 1.5.1); the
timed dry run with wall times is recorded in
[onboarding-timing.md](onboarding-timing.md).

> **Interpreter rule:** always use `.venv/Scripts/python.exe` (the project
> interpreter). A system Python or another venv produces false failures.

## 0. Prerequisites

- Python 3.13 with the `py` launcher:

  ```bash
  py -3.13 --version
  ```

- Git Bash (commands below use POSIX paths like `/c/Projects/...`).

## 1. Install (once, ~5 min — skip if `.venv` already exists)

```bash
cd /c/Projects/INPROGRESS/AttackMap
py -3.13 -m venv .venv
.venv/Scripts/python.exe -m pip install "setuptools<80"
.venv/Scripts/python.exe -m pip install -e ".[llm,dev]"
```

`setuptools<80` is pinned on purpose: setuptools ≥ 78 rejects this repo's
`[tool.setuptools.package-data]` dotted keys.

## 2. Smoke check (~10 s)

```bash
.venv/Scripts/python.exe -m attackmap --version
```

Expected: `attackmap 1.5.1` (or newer).

## 3. Scan a tiny example app (~30–60 s)

The repo ships three intentionally vulnerable one-file demo apps in
`examples/` (see `examples/README.md`). Scan one:

```bash
.venv/Scripts/python.exe -m attackmap analyze examples/orders-api-demo \
  --output C:/tmp/attackmap-onboarding --no-progress --time-budget-seconds 120
```

Expected: exit 0 and a `Reports written to ...` line.

Useful flags (from `src/attackmap/surfaces/cli.py`):

- `-o`, `--output` — report directory (default `reports`).
- `--format all|markdown|json` — report set (default `all`).
- `--no-progress` — quiet progress bar (piped output auto-disables it).
- `--time-budget-seconds N` — deterministic-pipeline ceiling (default 600).
- `--module NAME` / `--analyzer-profile NAME` — analyzer selection.
- `--incremental` — reuse cached per-file results (safe full-fallback cache).
- `--llm` — AI narrative review; needs an LLM provider, skip on first run.

## 4. Read the report (~2 min)

```bash
ls C:/tmp/attackmap-onboarding
```

Reports land in a timestamped generation subdirectory
(`<output>/<YYYYMMDDTHHMMSS-...>/` — the scan prints the exact path). List it:

```bash
ls C:/tmp/attackmap-onboarding/<generation-id>
```

Start here, in this order:

1. `defensive-review.md` — the human review: overview, findings with
   file:line evidence, attack paths, recommendations.
2. `attack-surface.md` and `architecture.md` — the inferred surface and
   structure of the app.
3. `attackmap-exploitability.md` — hotspots ranked by explainable scoring.
4. `attackmap-report.sarif` — the same findings for IDEs / CI ingestion.

Other files in the directory: `defensive-review.json`,
`review-context-pack.json`, Mermaid (`attackmap-paths.md`,
`attackmap-topology.md`) and Graphviz (`*.dot`) graphs, plus
`run-manifest.json` / `artifact-manifest.json` run bookkeeping.

## 5. Run the fast test subset (~30 s)

```bash
.venv/Scripts/python.exe -m pytest tests/architecture -q
```

Expected: `11 passed` — the layering/cycle ratchet. The full non-live suite
is ~7 000 tests / ~5 min (see the current handoff doc, section 8).

## 6. One-minute product tour (optional)

```bash
.venv/Scripts/python.exe -m attackmap rules list        # finding-rule catalog
.venv/Scripts/python.exe -m attackmap modules           # installed analyzers
.venv/Scripts/python.exe -m attackmap analyze --help    # every scan flag
```

Static snapshots of the rule catalog, analyzers, and the SDK contract live in
[reference/](reference/README.md).

## Where to read next

- [README.md](README.md) — documentation index (authority docs first).
- [archive/](archive/index.md) — superseded historical documents.
- `AGENTS.md` (repo root) — project philosophy and working rules.
