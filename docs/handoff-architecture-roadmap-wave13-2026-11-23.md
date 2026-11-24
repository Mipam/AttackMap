# Handoff — AttackMap architecture roadmap, post wave 13

**Written 2026-11-23 (~19:50 local) for the next agent; file restored ~20:30 after an
incident wiped the worktree (see "Incident" below).** State below was measured this
session, not recalled.

## 0. Incident 2026-11-23 ~19:47–19:51 (read before doing anything)

An unknown process **permanently deleted the entire worktree**, including most of
`.git` metadata (HEAD, refs, config, index, hooks), leaving only `.git/objects`
(5234 files incl. all 3 packfiles), a locked `.venv/Scripts/python.exe`, and
`.pytest_cache`. Not Defender, not Explorer-to-bin (bin empty), not a move (no copy
found), not disk errors (System log clean). Cause UNKNOWN — no deleting process was
found running afterwards; the remaining forensics (USN journal, Security log object
access) need an elevated shell.

**Forensic addendum (2026-11-23 ~20:40, full session-log review):**
- Every Bash command of all three wave-14 agents (agent-7/8/9, 88 commands total)
  and of the main agent was extracted from the runtime wire logs. **No agent
  issued any delete/clean/format command.** Tools used: Read/Grep/Edit/Write/
  Bash only — no Skill, no worktree, no background tasks.
- Bracketed timeline: 19:46:41 agents launched; 19:51:37 `sed secrets.py` still
  worked; 19:51:41–19:51:50 agents' `ls`/`git` began failing (files vanishing
  under them, .venv pyvenv.cfg gone); 19:52:41 main agent noticed; 19:52:50
  TaskStop ×2; deletion stable by 19:53:33. So the deleter ran ~19:51:38–19:53:3x
  and stopped within a minute of the TaskStops.
- Conclusion: no agent command caused it. Either the swarm/parallel-agent
  runtime layer (invisible from inside; cleanup bug while 3 agents shared one
  tree) or an external process. USN journal / Sysmon would be needed to name
  the process (needs admin). Until then: **do not run 3 parallel writers in one
  tree again; prefer sequential agents or proven disjoint leases.**

**Recovery performed (same day ~20:00–20:30):**
- `.git/objects` backed up first to `C:\tmp\attackmap-scratch\git-rescue\objects`
  (123 MB — KEEP IT until the next stable checkpoint is verified).
- `.git` skeleton rebuilt: HEAD → `refs/heads/codex/windows-build-development` =
  `0647c9db2eadb4ba934a3e798483a94357b9bea0`, minimal config (NOTE:
  `core.longpaths=true` is REQUIRED — the repo has paths over 260 chars under
  `docs/verification/windows-parity/`).
- `git fsck --full`: **no missing/corrupt objects**; only dangling debris.
- `git reset --hard` restored all 7236 tracked files; worktree clean at `0647c9d`.
- `.venv` was rebuilt from scratch (`py -3.13 -m venv` + `pip install -e ".[llm,dev]"`).
- `pyproject.toml` needed one fix after the rebuild: setuptools ≥78 rejects the
  old dotted `[tool.setuptools.package-data]` keys (`attackmap.reasoning = …`,
  `attackmap.surfaces.ui = …` — "must be array" error). Replaced with the flat
  equivalent `attackmap = ["reasoning/taint_sinks.yaml", "surfaces/ui/web/**/*",
  "surfaces/ui/fixtures/*.json"]` (committed in `91422cb`). Pin `setuptools<80`
  in the venv when reinstalling.
- **EOL rebuild trap (cost 19 false "regressions")**: the destroyed local git
  config was `core.autocrlf=input` (checkout = verbatim blob bytes, no
  conversion). The first rebuilt config used `autocrlf=false`, which — together
  with `.gitattributes` explicit `text` rules — still converts LF→CRLF on
  checkout for `*.json/*.yaml/*.md/…` (core.eol native). Hash-audited evidence
  fixtures then failed: `fixtures/desktop-workflows` expected hashes,
  `tests/unit/test_evaluation_increment.py` (WP030 provenance sha256),
  `test_wp043_live_capture` + `test_ui_supervision` (timing/content knock-ons).
  Fix applied: `git rm --cached -r . && git reset --hard` with
  `core.autocrlf=input` (no `core.eol`). **17 files must additionally carry
  CRLF working-tree bytes** (manifest hashes were recorded over CRLF bytes):
  `fixtures/desktop-workflows/{suppressed.json,suppressions.yaml}`, `tests/fixtures/desktop-options-v12/{request-defaults.json,request-sentinels.json}` and 13 files
  under `fixtures/evaluation/increment-20261031/repos/{dvwa,clean-catalog}/…`.
  They intentionally show as ` M` in `git status` (blob stays LF — do NOT
  `git add` them; staging would renormalize to LF and re-break the hashes).
- **Pillow was missing** in the rebuilt venv (it is not declared in
  `pyproject.toml`; the old venv had it manually). Installed Pillow 13.0.0;
  WP043 live-capture tests need it. Reinstall after every venv rebuild.

Lessons: (1) this repo currently exists ONLY on this machine and was one locked
file away from total loss — push to a remote or mirror the objects after the next
wave; (2) the object store alone is sufficient for full recovery if you know one
good commit sha — record the integration sha in the handoff every wave (done below).

## 1. Read this first

- Authority: `docs/architecture-roadmap-2026-11-21/{roadmap,criteria,todo}.md` +
  `backlog.json`, then the code. `AGENTS.md` names this plan as the active
  implementation authority for engine/architecture/reasoning/product-surface work
  (owner decision 2026-11-23, commit 11ed09d); the Windows parity roadmap stays
  authoritative for the Windows native surface and Windows M3.
- **The tree is CLEAN.** Everything is committed on
  `codex/windows-build-development` at `0647c9d`, 68 commits ahead of its remote,
  unpushed (push only when the owner asks). Nothing untracked except this file.
- Product rules unchanged: defensive only, evidence first, `AGENTS.md` binding.
- Owner reads Czech and wants short honest reports: what was verified and how,
  what failed, what is not verified. LM Studio live runs reported separately from
  fixture tests.

## 2. Where things stand

| Fact | Value |
| --- | --- |
| Branch / HEAD | `codex/windows-build-development` at `0647c9d` |
| Cards | **41 of 56 DONE**, 15 OPEN (`todo.md` and `backlog.json` agree; progress table maintained) |
| Full non-live suite (last run, wave 13) | **6975 passed, 11 failed, 0 errors** in ~5.3 min — the 11 are the known host failures (section 9) |
| Ratchet | PASS, tightened: ruff 649, mypy 537/69 files, broad excepts 63, longest function 750 (now `surfaces/api.py`, not engine), modules 194, cycles 0, layer violations 0 |
| Report identity gate | `84c7b18a…` UNCHANGED — the committed gate is a **static empty-fixture corpus**, so report content changes do not move it (pitfall 7) |
| Rule ids in reports | **snake_case registry ids** since wave 13 (owner decision); suppressions + SARIF accept both forms via `rule_id_aliases` (`model/taxonomy.py`) |
| `generate_findings` | 788 → **417 lines** (`threat_model.py` 2068 → 1605); AC-203's ≤60 target needs a further retirement wave |

Open cards: AR049, AR050 (phase 2); AR063–AR068, AR070 (phase 3); AR080–AR084,
AR088 (phase 4). Dependency-wise AR049+AR050 are next (lease `reasoning-output`,
sequential); AR084 needs AR048 (done); AR070 needs AR061+AR063; AR083 needs
AR067; AR080/AR081 need AR061/AR069 (all done); AR088 needs AR031 (done).

## 3. What landed since the wave-11 handoff (all verified, see commits)

Wave 19 (3 parallel lanes — owner-approved; leases verified disjoint with one
deliberate split: AR066 was forbidden `api/artifacts.py` and exposed
`export_md.render_pdf` as a drop-in, which the parent wired at integration,
removing the old inline chrome block + `_find_chrome_or_edge`, ruff 7 → 2):
- **AR064** (`ui-server`) — dialog main-thread dispatcher (AC-306):
  `dialogs.py` with `PlatformDialogs` + `MainThreadDispatcher` (queue +
  main-loop hook; the Tk hook is a repeating `root.after` chain — naive
  `after` from a worker raises "main thread is not in main loop" on real Tk
  and was replaced). tkinter call sites in `api/scans.py`/`api/artifacts.py`
  routed through it; zero wire-format changes. Proof:
  `tests/integration/test_ui_threading.py` (6 tests: static tripwire,
  dispatcher guarantee, live HTTP end-to-end on ThreadingHTTPServer, real-Tk
  smoke). Follow-up debt: `launch.py` should install a pump so dispatched
  dialogs deliver on the browser-fallback path (one line once a main loop
  exists).
- **AR065** (`ui-web`) — frontend ES module split (AC-307): the 626-line
  `app.js` monolith split into `main.js`/`api.js` (ESM, same token
  contract)/`state.js`/`paint.js`/`util.js` + `views/*.js` (22 modules);
  single `<script type="module">`, no bundler; `tools/gen_api_types.py`
  generates `api-types.js` from `schemas.py` (--check for CI). Freshness node
  harness ported to `SourceTextModule` loading (`node
  --experimental-vm-modules`); `tests/integration/test_ui.py` ported to an
  `_all_js()` helper. Two tiny documented exports added: `state.js
  `pendingRefresh()`, `paint.js` `setRenderObserver(fn)`. Also fixed a real
  pre-existing bug: the PDF-preview fetch used a nonexistent `state.token`
  (always 403) — now `getToken()`.
- **AR066** (`ui-export`) — PDF export behind a protocol (AC-312):
  `export/pdf.py` with `PdfBackend` + Chrome/Edge backends (flags
  verbatim-identical to the old inline call), typed `PdfUnavailable` /
  `PdfRenderError`; real Edge render verified (%PDF-1.4, 1 page); typed-error
  path isolated. Integration wiring in `api/artifacts.py` by parent.
- After wave 19: **54/56** cards DONE. Remaining 2: AR081 (portfolio, 8 d),
  AR082 (SDK v2 — needs the external analyzer repos on github.com/mlaify).
  Wave 20 candidates: AR081 split into slices, or AR082 if the owner provides
  the external repo situation.
- GUI work: M3 preview for the new frontend — `attackmap ui` rendered in the
  browser (WebView2 absent on this host, documented fallback), full nav +
  toolbar visually reviewed on screenshots.

Wave 18 (2 parallel lanes, same protocol; AR063 lease `ui-server` × AR080-perf
lease `extraction`, verified disjoint):
- **AR063** (`ui-server` lease) — GUI server decomposition (AC-305):
  `surfaces/ui/server.py` 899 → 362 lines; 13 `/api/*` handlers extracted to
  `surfaces/ui/api/{routes,schemas,scans,artifacts,settings}.py` (bucket
  deviation documented in the package doc); 23 Pydantic models validate the
  legacy payloads (byte-identical wire format); single token check
  (`routes.token_ok`) applied by the dispatcher; `tools/api_report.py --check`
  green (13/13 routes both directions, avg handler 7.5/20 lines); cycle-free
  via TYPE_CHECKING + registration side-effect (server imports
  `api.artifacts`/`api.settings` for `@route` registration). M3: visible
  preview done — `attackmap ui` served to the browser (WebView2 absent on
  this host, documented fallback), full UI rendered, Activity nav clicked and
  reviewed on screenshot.
- **AR080 perf follow-up** (`extraction` lease) — **AC-401 MET**: warm p95
  **21.07 → 9.19 s** (10k files/50 changed, 5 reps, fresh scratch,
  equivalence 5/5; chain 21.07 → 15.37 → 9.90 → 9.19). Dominant cost was
  every cached item pydantic-validated twice per run; fixed by shape-only
  `_payload_shape_ok` + `model_construct` replay in `incremental.py`
  (checksum + engine identity remain the integrity gates; documented
  "corruption, not forgery" trust stance unchanged — forgery-replay test
  pins it). Also BlobStore single-stat, eviction skip when provably under
  cap, `index.py` prefix-rel. **Security nuance ratified at integration:**
  warm replay no longer re-runs validation/redaction on cache content; legit
  entries are byte-identical (bench + wp033 100-seed + test_incremental
  campaigns), forged entries replay as stored (consistent with the documented
  stance). Revert = one function (`load_payload`). Cold ratio 1.733 is a
  tool-internal secondary target, NOT part of AC-401 (criteria: warm p95
  only) — cold write-path restructure is follow-up debt.
  Records: `C:/tmp/attackmap-scratch/ar080perf/run{1,2,3b}.log`.
- Baseline correction (wave 18): the wave-17 ruff 648 was a **mis-measure**;
  the reproducible value at head `1e55a59` is **649** (git-archive extracts
  count 651 — two `.superpowers/sdd/*.py` files the worktree ruff skips only
  because `.git` is present). Both wave-18 lanes verified net-zero on ruff
  per-file. Baseline corrected 648 → 649 with note; also tightened mypy
  537→535/68, broad 58→57, fns>80 75→74, modules 200→206.
- After wave 18: **51/56** cards DONE (AR080 closed). Remaining 5: AR064,
  AR065, AR066 (GUI cluster — all unblocked NOW by AR063), AR081 (portfolio),
  AR082 (SDK v2, external repos github.com/mlaify). Wave 19 candidate:
  AR064 × AR066 (both `ui-*` leases — verify disjointness against current
  code; AR065 is `ui-web` and could form a third disjoint lane).

Wave 17 (2 parallel lanes, same protocol; AR083×AR080, lease disjointness
verified against current code — `orchestration/`+`ai`+`surfaces/ui` vs
`extraction/`+`tools/bench_incremental.py`):
- **AR083** (`orchestration` lease) — observability: `src/attackmap/diagnostics/`
  (new leaf package; `metrics.py` RunMetrics counters/timings) + `trace_id`
  (uuid4 per run) threaded through `run_spec`/`pipeline`/`analyzers` via a
  budget `ContextVar`; `extraction/progress.py` additive `extra=` merge so
  progress events carry trace context; new CLI `explain-run
  <generation|path|current> [-o BASE] [--json]` surfacing run metrics and
  evidence from existing endpoints; activity view in
  `surfaces/ui/web/src/activity.js` wired into app.js/index.html
  (feature-detected, reads existing endpoints only). Tests:
  `test_diagnostics_metrics.py`, `test_explain_run.py`. Identity hash
  unchanged; ratchet PASS (ruff 649→648, modules 197→200, longest fn 750
  after parent extracted `_init_run_events`/`_record_scan_metrics`/
  `_record_budget_skip` from pipeline.py).
- **AR080** (`extraction` lease) — CAS cache: `src/attackmap/extraction/cas.py`
  sha256 blob store, per-analyzer cache keyed `(analyzer_id, analyzer_version,
  blob_hash)`, LRU eviction with current-run pinning, degrade-to-no-cache
  guards (broad excepts narrowed by parent to `(OSError, ValueError,
  RuntimeError)`); wiring in `scanner.py`; `tools/bench_incremental.py`
  extended `--files --changed --repeat --json`; `test_cas.py` (19 tests).
  **AC-401 gate NOT met**: 10k files / 50 changed, warm p95 = **21.07 s vs
  target < 10 s** (ratio 0.29 ≤ 0.5 ✓; cold 1.7× full). Card stays
  **PARTIAL/OPEN** — perf follow-up is now measurable via AR084 suite.
  Log: `C:/tmp/attackmap-scratch/ar080/bench-10k.log`.
  Integration fix at wave-17 gates: the WP033 mutation campaign audits the
  per-file cache layer, but the CAS rode the global default root
  (`~/.attackmap/cas`, shared across processes) and masked per-file cache
  corruption by design (second-chance + repair). The campaign now disables
  CAS (`ATTACKMAP_CAS=0` monkeypatch, env scrubbed) — CAS has its own
  `test_cas.py`; no product behavior change.
- After wave 17: **49.5/56** (AR080 code landed, perf gate open). Remaining
  7.5: AR063, AR064, AR065, AR066, AR070 (GUI cluster — biggest unlock,
  needs visible preview per M3), AR081, AR082, AR080-perf.

Wave 16 (2 parallel lanes, same protocol; AR012×AR068 chosen because
AR012 **blocks** AR083 and AR083's trace_id work would have collided with
AR012's pipeline edits — AR080 deferred to pair with AR083 in wave 17):
- **AR012** (`errors` lease) — `attackmap.errors` typed taxonomy
  (AttackMapError + 7 typed errors with code/detail/hint; definitions in
  `foundation/errors.py`, `attackmap/errors.py` canonical re-export — flipping
  that direction is a deferred parent decision); broad excepts **63 → 58**;
  every remaining broad catch records or re-raises (tripwire test). Follow-up:
  `orchestration/fleet_admission.py` has a local FleetAdmissionError shadowing
  the taxonomy one.
- **AR068** (`docs` lease) — `docs/archive/` (byte-identical copies + index;
  6 originals deleted at integration), `docs/onboarding.md` (timed walkthrough
  ~3.5 min recorded in `docs/onboarding-timing.md`), generated
  `docs/reference/` (49 rules / 9 analyzers / 51 SDK exports), `docs/README.md`
  rewritten as the documentation index. Root README roadmap link updated.
  "Unsure" docs left in place (see agent report in session).
- After wave 16: **48/56** cards DONE. Remaining 8: AR063, AR064, AR065,
  AR066, AR070 (GUI cluster — needs visible preview per M3), AR080 (CAS),
  AR081 (portfolio), AR082 (SDK v2, external repos). Wave 17 candidate:
  AR083 (unblocked by AR012) × AR080 — verified disjoint (orchestration/ai/ui
  vs extraction).

Wave 15 (2 parallel lanes, same protocol; lanes AR067×AR084, lease
disjointness verified against current code):
- **AR067** (`ai` lease) — `EvidenceBundle` schema_version=1 (findings/paths/
  controls/limitations, stable citation ids, caps mirror the evidence pack);
  prompts build from the bundle; uncited claims rejected via citations
  validator; `gate_bundle_schema_version` is the AR083 hook. Identity hash
  unchanged. Contract tier grew 242 → 246 (new
  `tests/contract/test_evidence_bundle_contract.py`).
- **AR084** (`perf` lease) — `tools/bench_analyzers.py` (synthetic fixture
  repos, analyzer/full/incremental wall time + tracemalloc peak memory,
  per-commit JSON trend store, record-and-warn default,
  `--fail-on-regression` for nightly) + `tests/perf/` (10 tests: smoke +
  >20% gate logic, hermetic). `.github/workflows/perf.yml` added by parent
  (nightly, artifact trend store). Note: incremental-vs-full ratio here
  compares per-file pass vs end-to-end scan — definitions in the tool
  docstring.
- After wave 15: **46/56** cards DONE. Remaining 10: AR012, AR063, AR064,
  AR065, AR066, AR068, AR070, AR080, AR081, AR082. AR083 now unblocked
  (needs AR067 ✓); the AR063→{64,65,70} GUI cluster is the next big unlock —
  GUI work needs a visible preview per M3 steering. AR082 needs external
  analyzer repos (github.com/mlaify).

Wave 14 (parallel lanes, post-incident protocol — agents never git-mutate;
parent integrates after gates; 2 lanes max, lease disjointness verified
against current code before launch):
- **Wave 14a** (`ddc0046`): **AR049** rationale + evidence on every Finding
  (AC-207; registry RuleMeta + observed evidence line, 12 cascade backfills,
  SARIF property bag, redaction-aware; identity hash unchanged) +
  **AR088** 8 ADRs + index + `tools/arch_drift.py` (cycles/fan-in/function/
  broad-excepts per commit; AC-409).
- **Wave 14b** (`2215223`): **AR050** all ranking/dedupe policy centralized in
  `reasoning/ranking.py` (AC-208; total deterministic ordering with id
  tie-breaker; identity hash unchanged; models fan-in 60→61 recorded in
  baseline.json as the structural cost of the mandated module; the
  `rules/evaluation.py` mirror copy is intentional rules-lane property, do NOT
  centralize it) + yaml RecursionError hardening in `output/suppress.py` and
  `surfaces/ui/suppress_write.py` with 3 regression tests (before/after
  proven). Follow-up candidate: `output/sarif.py:49-51` local severity table.
- Suite after wave 14b: **6990 passed, 11 known host failures** (§9).

Wave 11 (commits `949a324`, `0866916`, `4ab1a3b`, `db883eb`, integration `a2a84ba`):
- **AR047** rule test harness (439 tests, meta-tests + mutation green).
- **AR062** public library API `surfaces/api.py` (`analyze(spec)`; import 0.001 s;
  library ≈ CLI speed); `RunSpec.repos/output`.
- **AR061** derived SQLite index: `orchestration/derived_index/{rows,sqlite,
  rebuild,query}.py`, `attackmap index rebuild|status|dump`, `attackmap trends`;
  AC-302 reconstructible and AC-303 disposable **verified live**; GUI/desktop
  readers not rewired (follow-ups for AR070+, listed in the AR061 card).
- **AR086** hostile-input hardening: 11 integration tests + 2 opt-in stress;
  committed fixtures 567 B; fixed a real defect — `yaml.safe_load*` caught only
  `YAMLError`, deep YAML escaped as `RecursionError` and crashed scans; fixed at
  3 extraction sites (config_scanner, workflow_scanner ×2, lockfiles).

Wave 12 (commits `74d2915`, `ec8697d`, integration `b5e2d02`):
- **AR048** detection quality harness: `corpus/reference.yaml` + `attackmap eval
  rules --corpus ... --json` (AC-206); baseline published in
  `docs/reference/detection-quality.md` (precision 0.882 / recall 0.938).
- **AR087** rule authoring guide + `tools/new_rule.py` scaffold +
  `tests/rules/_template.py`.
- Parent fix: `tools/report_identity.py::compute_scan_identity` was broken since
  AR025 (imported deleted `AnalyzeOptions`); re-pointed at
  ScanRequest/RunSpec/execute_scan_request.

Wave 13 (owner decision 11ed09d; commits `e5597c4`, `5b53029`, integration `0647c9d`):
- **Dual-id** (`e5597c4`): suppressions match legacy↔snake_case both directions
  (also fixed `rule_slug` mangling snake_case selectors); SARIF needed no change;
  18 new tests incl. registry cross-check. Alias source:
  `rule_id_aliases()` in `model/taxonomy.py`.
- **Wiring pass** (`5b53029`): REGISTRY now produces the scan pipeline's
  findings for all ported families; ported cascade branches deleted;
  exploitability fusion applied over registry findings. New shared module
  `reasoning/finding_format.py` (breaks the rules→threat_model import edge).
  Equivalence: **122 repos (AR048 corpus + 120 seeded synthetic + juice-shop),
  1210 findings, 0 divergences** field-for-field modulo `rule_id` mapping via
  `legacy_rule_ids`; the only additions are 2 `demo_weak_default_credentials`
  findings on juice-shop. 17 pre-existing test files updated from pinned legacy
  ids — each listed with justification in the AR046 card's wave-13 note.
- Identity gate hash did NOT move (static fixture — pitfall 7).

## 4. Owner decisions made 2026-11-23 (do not re-litigate)

1. **Rule ids**: reports switched to registry snake_case ids; suppressions and
   SARIF accept both old and new via `legacy_rule_ids`. EXECUTED in wave 13.
2. **Plan authority**: the AGENTS.md paragraph naming
   `docs/architecture-roadmap-2026-11-21/` as the active plan is in. The
   roadmap's own `README.md` still says "Status: PROPOSED" — the owner was not
   asked about that file; leave it or ask.
3. Working style: parallel agents with strict leases, parent integrates — the
   owner explicitly authorized subagents on 2026-11-23 ("chci vlny spustit jako
   paralelní agenty!").

## 5. Deferred / follow-up debt (not cards — pick up alongside waves)

- **Unported cascade families still emit legacy ids**: unauth-state-change +
  AM038 webhook variant (needs AttackSurface exposure + disk I/O),
  unauth-outbound-integration / public-data-route (exposure downgrade),
  bola-modify / bola-read (authz_candidates), AM038 observed-activity webhook
  (source_texts + disk I/O). Each is named in its port card with the context
  slice it needs.
- **AC-203**: `generate_findings` ≤60 lines (now 417). Needs porting the above
  families + a final retirement pass. No card exists; treat as part of the
  cascade-retirement follow-up.
- **AR042 edge rules** (`same_file_*`, `same_module_*`): registry-only,
  excluded from reports via `_REGISTRY_ONLY_RULE_IDS` — pending a product
   decision on whether they surface as findings.
- **Aggregate ids without taxonomy entries** (`workflow_security`,
  `supply_chain_risk`, demo, edge rules) are not in the flat `attackmap rules`
  catalog union (taxonomy lives in model/, was another lane's lease).
- **Machine-local scan identity** (`compute_scan_identity`): vulnerable-app now
  hashes `5ad12d57…` (id cutover consequence). Nothing in CI consumes it;
  re-baseline where a local workflow pins it.
- **yaml RecursionError latent sites** — FIXED in wave 14b (commit after
  `ddc0046`): both `except (yaml.YAMLError, RecursionError)` clauses +
  3 regression tests in `tests/integration/test_hostile_inputs.py` (before/after
  proven). `ai/supply_chain.py:152` confirmed ALREADY SAFE.
- **sarif.py local severity-weight table** (`output/sarif.py:49-51`, separate
  `{"high": 9.0, …}`) — NOT centralized by AR050 (out of its lease); candidate
  for a future ranking-centralization follow-up if the owner wants it.
- **GUI/desktop readers still bypass the derived index** (AR061 follow-ups):
  `surfaces/ui/server.py`, `surfaces/ui/output.py`, desktop_actions/worker/
  capabilities, diagnostics_export, retention, desktop_provider — AR070's job.
- **AR048 corpus**: revision "1" pinned; `demo_weak_default_credentials` now
  fires on juice-shop (2 findings) but still not on the corpus fixture by
  design; regenerate + bump `corpus_revision` when the fixture changes.
- Coverage floor in CI stays 21% (fast selection measured 37.71% at wave 9;
  raising is safe but was deliberately deferred). CI has never run on this
  branch; AC-003/AC-010 Linux-runner bounds unverified.
- `attackmap rules` flat catalog is a legacy/cascade-union command kept on
  purpose (documents the ids `rule:` suppressions match; see AR046 parent
  correction). Do not remove it without a replacement story.

## 6. Suggested next waves

1. **Recreate wave 14** (all three lanes: AR049 → then AR050; AR088; the two
   yaml fixes). Briefs exist in spirit in section 5; rebuild from the cards.
2. Then any of: AR084 (perf suite, needs AR048 eval harness), AR080 (CAS, big),
   AR081 (portfolio), AR083 (observability, needs AR067 first), AR063+ (GUI work
   — M3 steering: GUI tasks must produce a visible preview and real visual
   review, not just green tests). AR082 needs external analyzer-repo work.
3. **PUSHED 2026-11-23 (wave 15):** `origin` = https://github.com/Mipam/AttackMap,
   branch `codex/windows-build-development` @ `bd6007e` (remote also has older
   `main` @ `611a379`). The repo is no longer local-only — but keep making
   pushes at stable checkpoints; the 2026-11-23 total worktree loss only worked
   out because .git/objects was left behind. See section 0.

## 7. Working protocol (proven this session — keep)

- Per agent: exclusive file lease, explicit `git add <paths>` (never `-A`),
  `git branch --show-current` before each commit, final report with exact
  commands/results/deviations/unverified. Agents work in the main tree in
  parallel; never stash/checkout/reset/clean.
- **Wave 14a/b amendment (post-incident, proven): agents NEVER run any git
  mutation at all** — no `add/commit/reset/clean/checkout`; they leave all
  changes uncommitted and the parent integrates after gates. Rationale: index
  lock collisions and un-integratable half-states across parallel lanes; the
  2026-11-23 worktree destruction happened while parallel agents shared the
  tree, so lanes are kept as small as possible (2) with lease disjointness
  VERIFIED AGAINST CURRENT CODE by the parent before every launch (wave 14a:
  AR049×AR088; wave 14b: AR050×yaml-fixes — 14c was deferred a wave because
  both AR050 and 14c collide with AR049's blast radius).
- Parent integration checklist: (1) `git show --stat` per commit = leased paths
  only; (2) diff `surfaces/cli.py` and every pre-existing test an agent touched;
  (3) an agent's "pre-existing failure" is unverified until reproduced on the
  settled tree; (4) after any structural wave run the WHOLE non-live selection;
  (5) backlog `status` and `evidence` in the same edit (DONE+OPEN must equal 56);
  (6) `todo.md` and `backlog.json` must agree; test basenames unique.
- Status docs (`todo.md`, `backlog.json`, `baseline.json`), `AGENTS.md`, and
  `.github/workflows/ci.yml` are PARENT-OWNED — agents never touch them.
- Scratch: `C:\tmp\attackmap-scratch\<task>\`, one subfolder per task, empty it
  after every wave — EXCEPT `git-rescue/` (keep until a post-recovery checkpoint
  is verified and ideally pushed).

## 8. Commands and expected results

From the repo root, project interpreter ONLY (`.venv/Scripts/python.exe` —
other interpreters produce false failures). After the incident the venv was
rebuilt; if anything is missing, `pip install -e ".[llm,dev]"` again.

| Check | Command | Expected |
| --- | --- | --- |
| Layers/cycles | `-m pytest tests/architecture -q` | 11 passed |
| Contracts | `-m pytest tests/contract -q` | 246 passed, 1 skipped |
| Rule tests + meta-tests | `-m pytest tests/rules -q` | 439 passed |
| Rule docs | `tools/gen_rule_docs.py --check` | 50 files up to date |
| Ratchet | `tools/ratchet_check.py --baseline docs/architecture-roadmap-2026-11-21/baseline.json` | PASS |
| Report identity | `-m tools.report_identity` | 84c7b18a… |
| Full suite | `-m pytest -q -ra -m "not live" -n auto --timeout=300 -p no:cacheprovider` | ~7133 passed, 11 known failures + up to 2 load-flaky, ~5 min |
| Registry in pipeline | `attackmap.exe rules list --json` | 49 registry ids |
| Eval baseline | `attackmap.exe eval rules --corpus corpus/reference.yaml --json` | exit 0, per-rule tp/fp/fn |

Baseline recorded at `0647c9d` (last tightened wave 19): ruff 646, mypy 535/68,
cycles 0, broad excepts 57, longest function 750, 74 functions >80 lines,
models fan-in 61, 209 modules. Tighten-only.

## 9. Known host failures (NOT regressions)

`tests/unit/test_output_exclusion.py` (6), `tests/unit/test_scanner.py` (2:
Flask blueprint prefix, path normalization),
`tests/unit/test_local_provider_timeouts.py` (2),
`tests/unit/test_regex_budget.py::test_pattern_scales_linearly` for
`python_django_routes._MODULE` (1). Also load-flaky under `-n auto`:
`tests/integration/test_resource_budgets.py::test_time_budget_check_overhead_is_negligible`
and `tests/integration/test_execution_supervision.py::test_fifty_cancel_cycles`
(timing assertions; pass solo and in small groups — re-run before treating as
regression). Anything else failing is new.

## 10. Pitfalls (accumulated, incl. new this session)

1. Interpreter: `.venv/Scripts/python.exe` for everything.
2. Security hook blocks bash commands whose text writes source/test/security
   files — agents create files with edit tools only; keep helpers in scratch.
3. Worktree imports resolve to the main tree (editable install); a worktree
   needs its own venv. `git checkout <sha>` detaches HEAD — use a worktree.
4. Test module names: no `__init__.py` in tests/; basenames unique suite-wide.
5. **Agent step cap (~200 steps/turn)**: the wave-13 wiring agent burned its
   cap mid-verification. Split big lanes into (a) implementation brief and
   (b) a short "finish-only" resume. `Agent(resume="agent-N")` keeps context.
6. **Account usage limits** can kill several agents at once (wave 11 happened
   this way) — commit early, keep leases small.
7. **Report identity gate is a static empty-fixture corpus**: it does NOT move
   when report content changes. For anything touching finding production, prove
   safety with a capture/compare corpus (122-repo equivalence harness pattern).
8. The AR047 mutation meta-tests are the tripwire for wiring mistakes (wave 13
   caught exactly this). `tests/rules/_harness.py`, `conftest.py`,
   `test_rule_*.py` are lane-untouchable — fix the wiring, not the harness.
9. `tools/report_identity.py --corpus <path>`: `tests/fixtures/regression.yaml`
   does not exist (stale verify command in todo.md's common-verification block).
10. demo_weak_default_credentials fires on juice-shop (+2 high/high findings)
    — expected since the wiring pass.
11. After any worktree/.git rebuild: `core.autocrlf=input` (NOT `false` — with
    the repo's explicit `text` attributes, `false` still CRLF-converts on
    checkout via native core.eol), no `core.eol`. Then restore the 17 CRLF-byte
    files listed in §0 (they show as ` M` — leave them uncommitted).
12. Pillow is required for WP043 capture tests but undeclared — reinstall into
    every fresh venv.
11. **Recovered .git needs `core.longpaths=true`** or checkout dies on the deep
    `docs/verification/windows-parity/` paths (Filename too long).
12. Forensics for the incident (if the owner wants the culprit): from an
    ELEVATED shell — `fsutil usn readjournal C: | findstr /i attackmap` (USN
    journal names the deleting process for recent entries), and check the
    Security log if object-access auditing was on. Non-admin diagnostics
    exhausted: not AV, not Explorer, not a move, no crash, no fresh archives.
