# Acceptance Criteria — Architecture & Product Roadmap 2026-11-21

Every criterion is **measurable** and names its verification. A criterion is `PASS` only
when the command output is attached as evidence; "looks right" is not acceptance.

**Conventions**

- `AC-0xx` = Phase 0, `AC-1xx` = Phase 1, `AC-2xx` = Phase 2, `AC-3xx` = Phase 3,
  `AC-4xx` = Phase 4.
- Thresholds are expressed relative to the baseline in
  [`README.md`](README.md#ground-truth-used-by-this-plan) so they survive rebases.
- `ratchet baseline` = the value captured once by AR009 and only ever tightened.
- Priority: **High** = blocks the phase gate · **Medium** = required before the next
  phase starts · **Low** = required before plan completion.

---

## Phase 0 — Stop the bleeding

### AC-001 · Lint gate is real · High
`ruff check` exits 0 against the ratchet baseline, and CI fails when a new violation is
introduced.
**Verify:**
```bash
ruff check .
ruff check --statistics . | tail -5     # compare to baseline recorded in AR009
```
**Evidence:** CI run URL or local transcript + baseline file diff.

---

### AC-002 · Type gate is real · High
`mypy src/attackmap` reports no errors beyond the ratchet baseline, and CI fails on new
errors.
**Verify:**
```bash
mypy src/attackmap --ignore-missing-imports --check-untyped-defs
```
**Evidence:** baseline count in AR009 + CI job log.

---

### AC-003 · Fast suite is fast · High
The `unit + contract` selection completes in **< 5 minutes** on a 4-core CI runner with
`-n auto`, and no test exceeds 120 s.
**Verify:**
```bash
pytest -m "unit or contract" -n auto --timeout=120 --durations=20
```
**Evidence:** `--durations` output and total wall time.

---

### AC-004 · Coverage never regresses · High
`pytest --cov=attackmap` produces a total percentage ≥ the ratchet floor, and CI fails
when it drops.
**Verify:**
```bash
pytest -m "unit or contract" --cov=attackmap --cov-report=term --cov-fail-under=<FLOOR>
```
**Evidence:** coverage report + the floor value stored in `pyproject.toml`.

---

### AC-005 · No new import cycles · High
`tests/architecture/test_import_boundaries.py` fails on any cycle not in the allowlist,
and the allowlist length equals the baseline (44).
**Verify:**
```bash
pytest tests/architecture/ -v
python -m tools.arch_report --cycles --json | python -c "import json,sys;d=json.load(sys.stdin);print(len(d['cycles']))"
```
**Evidence:** test output + cycle count.

---

### AC-006 · Every run has an event log · High
Each published generation contains `events.jsonl` with, at minimum, one record per
stage and one per analyzer, and every record carries
`ts, run_id, stage, event, status`.
**Verify:**
```bash
attackmap analyze C:\\tmp\\juice-shop -o /tmp/am-out --no-progress
python - <<'PY'
import json, pathlib
gen = json.loads((pathlib.Path('/tmp/am-out')/'current-generation.json').read_text())
p = pathlib.Path('/tmp/am-out')/gen['generation']/'events.jsonl'
rows = [json.loads(l) for l in p.read_text().splitlines() if l.strip()]
assert rows, 'empty event log'
req = {'ts','run_id','stage','event','status'}
assert all(req <= set(r) for r in rows), 'missing required fields'
assert any(r['event']=='analyzer' and r['status']=='end' for r in rows)
print('records:', len(rows))
PY
```
**Evidence:** record count + sample of 3 lines.

---

### AC-007 · Policy constants have one home · High
`SEVERITY_RANK`, `SKIP_DIRS`, `LOW_QUALITY_SEGMENTS`, and `MUTATING_METHODS` exist exactly
once, and no module re-declares them.
**Verify:**
```bash
grep -rn "SEVERITY_RANK\s*=" src/attackmap | wc -l        # expect 1
grep -rn "_SKIP_DIRS\s*=" src/attackmap | wc -l           # expect 1
grep -rn "LOW_QUALITY_SEGMENTS\s*=" src/attackmap | wc -l # expect 1
```
**Evidence:** the three counts + `git diff --stat` of the replacement.

---

### AC-008 · Encoding is clean · High
No U+FFFD (replacement character) appears in `src/`, prompt templates, or
`pyproject.toml`, and CI enforces it.
**Verify:**
```bash
python - <<'PY'
import pathlib, sys
bad = []
for p in list(pathlib.Path('src').rglob('*.py')) + [pathlib.Path('pyproject.toml')]:
    t = p.read_text(encoding='utf-8', errors='strict')
    if '\ufffd' in t:
        bad.append(str(p))
print('\n'.join(bad))
sys.exit(1 if bad else 0)
PY
```
**Evidence:** empty output + exit 0.

---

### AC-009 · Analyzer trust is secure by default · High
A run that would load a non-official analyzer fails with a typed error unless the caller
passes an explicit opt-in, and the error names the analyzer and the flag.
**Verify:**
```bash
python - <<'PY'
from attackmap.analyzers import resolve_run_analyzers, UntrustedAnalyzerError
# simulate an untrusted entry point; expect refusal without opt-in
PY
attackmap analyze <fixture> -o /tmp/x --allow-untrusted-analyzers   # must succeed
attackmap analyze <fixture> -o /tmp/y                              # must fail, typed
```
**Evidence:** both exit codes + the error message.

---

### AC-010 · Cancellation is observed inside a stage · High
With `--time-budget-seconds 5` on a repo whose scan stage exceeds 5 s, the run stops
within **5 seconds** of expiry and publishes a partial result with an explicit
limitation.
**Verify:**
```bash
time attackmap analyze <large-fixture> -o /tmp/b --time-budget-seconds 5
python - <<'PY'
import json, pathlib
r = json.loads((pathlib.Path('/tmp/b')/'report.json').read_text())
assert any('budget' in l.lower() for l in r['limitations']), r['limitations']
PY
```
**Evidence:** wall time ≤ 10 s + limitation text.

---

### AC-011 · Tests are categorized · High
`tests/` contains `unit/`, `integration/`, `contract/`, `live/` and `fixtures/`; markers
are registered; `pytest -m unit` collects without error.
**Verify:**
```bash
ls tests
pytest -m unit --collect-only -q | tail -3
pytest -m "not live" --collect-only -q | tail -3
```
**Evidence:** directory listing + collection counts.

---

### AC-012 · Failures are typed, not swallowed · High
New code raises typed errors; broad `except Exception` count is ≤ the ratchet baseline,
and any remaining broad handler records a limitation or `analyzer_error`.
**Verify:**
```bash
grep -rn "except Exception" src/attackmap | wc -l   # ≤ baseline (62)
python -m tools.arch_report --broad-excepts --json
```
**Evidence:** count + the taxonomy module path.

---

### AC-013 · AttackMap audits its own dependencies · Medium
`pip-audit` runs in CI against a generated `constraints.txt`, and the release SBOM lists
all 15 pinned analyzer plugins with `pin_status` and `content_verified`.
**Verify:**
```bash
pip-audit -r constraints.txt
python tools/generate_release_sbom.py --check
python - <<'PY'
import json
d = json.load(open('sbom.json'))
assert all({'package','sha','pin_status','content_verified'} <= set(a) for a in d['analyzers'])
assert len(d['analyzers']) >= 15
PY
```
**Evidence:** audit summary + SBOM analyzer count.

---

## Phase 1 — Create the seams

### AC-101 · Foundation is acyclic · High
No cycle exists among `foundation/` modules (`safe_fs`, `redact`, `srcpaths`,
`artifact_manifest`, `artifact_publisher`).
**Verify:** `pytest tests/architecture/test_import_boundaries.py -k foundation -v`

---

### AC-102 · No compatibility shim remains · High
`recon_models` is deleted and no module imports it.
**Verify:** `grep -rn "recon_models" src tests | wc -l` → `0`

---

### AC-103 · Model package is split · High
`model/` exists with `observations.py`, `findings.py`, `paths.py`, `snapshot.py`,
`evidence.py`; `models` fan-in ≤ 25.
**Verify:**
```bash
python -m tools.arch_report --fan-in --json | python -c "import json,sys;print(json.load(sys.stdin)['models'])"
```
**Expected:** ≤ 25.

---

### AC-104 · Ledger is extraction metadata · Medium
`AnalyzerRunLedger` lives in `extraction/ledger.py`, not in `models`.
**Verify:** `grep -rn "class AnalyzerRunLedger" src/attackmap`

---

### AC-105 · One request object · High
`RunSpec` is the only run configuration; `AnalyzeOptions` is deleted; CLI, GUI, and fleet
are adapters that construct `RunSpec`.
**Verify:**
```bash
grep -rn "AnalyzeOptions" src tests | wc -l     # 0
grep -rn "class RunSpec" src/attackmap          # 1
pytest -m contract -k runspec
```

---

### AC-106 · No ambient feature configuration · High
No `os.environ[...] = ...` writes remain for feature flags, and no `ContextVar` carries
run configuration.
**Verify:**
```bash
grep -rn "os.environ\[" src/attackmap | grep -v "PYTHON" | wc -l   # 0
grep -rn "ContextVar" src/attackmap | grep -vi "budget\|reservation" | wc -l
```

---

### AC-107 · Analyzers run in parallel · High
Analyzer wall time on the reference repo improves **≥ 2.5×** versus the Phase 0 baseline.
**Verify:**
```bash
python -m tools.bench_analyzers --repo C:\\tmp\\juice-shop --repeat 3 --json
```
**Evidence:** before/after JSON with medians.

---

### AC-108 · Parallelism is deterministic · High
Serial and parallel execution produce byte-identical merged output on the regression
corpus.
**Verify:**
```bash
attackmap analyze <fixture> -o /tmp/ser --workers 1
attackmap analyze <fixture> -o /tmp/par --workers 4
diff -r /tmp/ser/current/report.json /tmp/par/current/report.json
```
**Evidence:** empty diff.

---

### AC-109 · Zero cycles · High
The allowlist is empty and the architecture test passes with `allowlist == 0`.
**Verify:** `pytest tests/architecture/ -v` + allowlist length assertion.

---

### AC-110 · Layer direction is enforced · High
A deliberate upward import fails the test with a message naming the offending module.
**Verify:** add a temporary `from ..surfaces import cli` inside `model/` → test must fail →
revert.

---

### AC-111 · Contracts are pinned · High
Contract tests cover SDK surface, merge schema, and artifact compatibility, and a
deliberate breaking change fails them.
**Verify:** `pytest -m contract -v`

---

## Phase 2 — Turn knowledge into data

### AC-201 · Rule registry exists · High
`attackmap.rules.REGISTRY` exposes ≥ 40 rules, each with `id`, `title`, `cwe`,
`severity`, `confidence`, `rationale`.
**Verify:**
```bash
attackmap rules list --json | python -c "import json,sys;d=json.load(sys.stdin);print(len(d));assert len(d)>=40;assert all({'id','cwe','rationale'}<=set(r) for r in d)"
```

---

### AC-202 · Every rule is tested · High
Each rule id has at least one focused test, and the test fails when the rule is disabled.
**Verify:** `pytest tests/rules/ -v --collect-only | grep -c "test_"` ≥ rule count, plus
one mutation check per family.

---

### AC-203 · Aggregator is small · High
`generate_findings` is ≤ 60 lines and contains no severity literals.
**Verify:**
```bash
python - <<'PY'
import ast, pathlib
src = pathlib.Path('src/attackmap/reasoning/findings.py').read_text()
fn = next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef) and n.name == 'generate_findings')
print(fn.end_lineno - fn.lineno + 1)
PY
```
**Expected:** ≤ 60.

---

### AC-204 · Rules are discoverable · Medium
`attackmap rules list` and `attackmap rules show <id>` work offline and are covered by a
CLI test.
**Verify:** `attackmap rules show AM-ROUTE-001`

---

### AC-205 · Docs are generated · Medium
`docs/reference/rules/` is generated from `RuleMeta`, and CI fails when it is stale.
**Verify:** `python -m tools.gen_rule_docs --check`

---

### AC-206 · Detection quality is measured · High
A per-rule precision/recall baseline is published for the reference corpus, with the
corpus revision and commit recorded.
**Verify:** `attackmap eval rules --corpus corpus/reference.yaml --json > eval.json`

---

### AC-207 · Findings are self-explaining · High
Every `Finding` carries a non-empty `rationale` and at least one evidence reference.
**Verify:**
```bash
python - <<'PY'
import json, pathlib
r = json.loads(pathlib.Path('/tmp/am-out/current/report.json').read_text())
assert all(f.get('rationale') and f.get('evidence') for f in r['findings'])
PY
```

---

### AC-208 · Scoring has one home · High
No severity/confidence weight tables exist outside `reasoning/ranking.py`.
**Verify:** `grep -rn "_SEVERITY_WEIGHT\|_CONFIDENCE_MULTIPLIER" src/attackmap | wc -l` → `1` file.

---

## Phase 3 — Harden the product edges

### AC-301 · Plugin contract v2 · High
`EXTRACTION_PROTOCOL_VERSION == "2.0"`, `ExtractionResult` carries a discriminated
`observations` list, and a v1 analyzer still runs via the adapter.
**Verify:** `pytest -m contract -k "sdk_v2 or v1_adapter"`

---

### AC-302 · Index is reconstructible · High
Deleting `index.sqlite` and running `attackmap index rebuild` yields identical query
results.
**Verify:**
```bash
attackmap trends --json > /tmp/before.json
rm ~/.attackmap/repos/*/index.sqlite
attackmap index rebuild
attackmap trends --json > /tmp/after.json
diff /tmp/before.json /tmp/after.json
```

---

### AC-303 · Index is disposable · High
If the index is corrupt, the CLI degrades to filesystem reads with a warning and never
fails a scan.
**Verify:** truncate `index.sqlite` → `attackmap analyze ...` must still succeed.

---

### AC-304 · Library API works · High
A five-line Python script produces a report without importing internal modules.
**Verify:**
```python
from pathlib import Path
from attackmap import analyze, RunSpec
result = analyze(RunSpec(repos=(Path("."),), output=Path("/tmp/lib")))
print(len(result.findings))
```

---

### AC-305 · API surface is declared · Medium
All `/api/*` endpoints have Pydantic request/response models, and the average handler is
≤ 20 lines.
**Verify:** `python -m tools.api_report --check`

---

### AC-306 · No cross-thread UI calls · High
An assertion or test proves no tkinter call occurs off the main thread.
**Verify:** `pytest tests/integration/test_ui_threading.py -v`

---

### AC-307 · Frontend has no build step · Medium
`ui/web/src` is ES modules only, `index.html` loads `type="module"`, and no bundler
config exists.
**Verify:** `grep -n 'type="module"' src/attackmap/ui/web/index.html` + absence of
`package.json` build scripts.

---

### AC-308 · GUI is fast · Medium
State load for a repo with 50 generations completes in **< 200 ms** (p95 of 20 runs).
**Verify:** `python -m tools.bench_gui_state --generations 50 --repeat 20 --json`

---

### AC-309 · AI boundary is versioned · High
`EvidenceBundle` has a schema version and compatibility gate; uncited claims are rejected.
**Verify:** `pytest -m contract -k evidence_bundle` + a fixture with an uncited claim.

---

### AC-310 · Fleet parity is explicit · High
Every documented feature either works in fleet mode or raises a typed
`UnsupportedInFleet` error naming the feature and the reason; no silent no-ops.
**Verify:**
```bash
attackmap fleet --help | grep -c "unsupported"
pytest -m integration -k fleet_parity
```

---

### AC-311 · Onboarding is real · Medium
A new contributor runs a successful scan in < 10 minutes following one document, verified
by a timed dry run.
**Verify:** timed walkthrough recorded in `docs/onboarding-timing.md`.

---

### AC-312 · PDF export degrades gracefully · Low
PDF export works through an explicit backend protocol and, when no supported browser is
available, raises a typed `PdfUnavailable(reason)` instead of a bare failure.
**Verify:**
```bash
attackmap export --format pdf --report /tmp/am-out/current/report.json -o /tmp/r.pdf
python - <<'PY'
from attackmap.surfaces.ui.export.pdf import PdfUnavailable
# simulate a host with no browser on PATH
PY
```
**Evidence:** produced PDF size > 0 + the typed error message from the no-browser path.

---

## Phase 4 — Expansion

### AC-401 · Incremental re-scan is fast · High
A 10k-file repo with 50 modified files re-scans in **< 10 s** (warm CAS, p95 of 5).
**Verify:** `python -m tools.bench_incremental --files 10000 --changed 50 --repeat 5 --json`

---

### AC-402 · Portfolio mode exists · High
`attackmap portfolio analyze repos.yaml` emits a portfolio generation with a cross-repo
graph and ranked hotspots.
**Verify:** run on a 3-repo fixture; assert `portfolio.json` has `graph.nodes`, `edges`,
`hotspots`.

---

### AC-403 · Ecosystem is on v2 · Medium
All official analyzers declare `EXTRACTION_PROTOCOL_VERSION = "2.0"` and the v1 adapter
is exercised only by a compatibility test.
**Verify:** `python -m tools.check_analyzer_versions`

---

### AC-404 · Runs are observable · Medium
`events.jsonl` carries `run_id`, `trace_id`, stage timings, and skip reasons; a summary
command renders them.
**Verify:** `attackmap explain-run <generation>`

---

### AC-405 · Performance is governed · Medium
The perf suite fails on a > 20% regression in analyzer time, scan time, or memory.
**Verify:** `pytest -m perf --benchmark-compare-fail=mean:20%`

---

### AC-406 · Builds are reproducible · Medium
Two clean builds of the same commit produce identical hashes for the engine artifact.
**Verify:** `python -m tools.repro_build --twice --compare`

---

### AC-407 · Hostile input is survivable · High
The hostile corpus (symlink loops, zip bombs, 1 GB single line, binary masquerading as
source, deeply nested YAML) produces no crash, hang, or unbounded memory growth.
**Verify:** `pytest -m integration -k hostile --timeout=300`

---

### AC-408 · Rules are contributable · Low
A rule authoring guide plus a template produces a passing rule from scratch in < 30
minutes.
**Verify:** `docs/contributing/rules.md` + `tools/new_rule.py --id AM-DEMO-001` dry run.

---

### AC-409 · Decisions are recorded · Low
`docs/adr/` has an index and ≥ 8 ADRs covering the decisions in this roadmap, and a drift
dashboard reports cycle count, fan-in, and function-length trends per release.
**Verify:** `python -m tools.arch_drift --since 5ee4d20 --json`

---

## Summary matrix

| Phase | Criteria | High | Medium | Low |
| --- | --- | --- | --- | --- |
| 0 | AC-001…AC-013 (13) | 12 | 1 | 0 |
| 1 | AC-101…AC-111 (11) | 10 | 1 | 0 |
| 2 | AC-201…AC-208 (8) | 6 | 2 | 0 |
| 3 | AC-301…AC-312 (12) | 6 | 5 | 1 |
| 4 | AC-401…AC-409 (9) | 3 | 4 | 2 |
| **Total** | **53** | **37** | **13** | **3** |
