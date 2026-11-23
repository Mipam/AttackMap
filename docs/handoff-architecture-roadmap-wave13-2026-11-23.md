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
- **yaml RecursionError latent sites** (same defect class as AR086, NOT fixed;
  outside that lane's lease): `output/suppress.py:~476`,
  `surfaces/ui/suppress_write.py:~101` (the wave-14 lane CONFIRMED both
  reachable and fixed them in its worktree — the fix was LOST in the incident;
  recreate: `except (yaml.YAMLError, RecursionError)` + regression case in
  tests/integration/test_hostile_inputs.py). `ai/supply_chain.py:152` was
  checked and found ALREADY SAFE (`except Exception:` since AR029) — the
  wave-11 handoff's claim was stale.
- **Wave 14 was interrupted by the incident** (three lanes, all uncommitted,
  work lost but fully recreatable): AR049 rationale/evidence (design was
  settled: model fields + populate in reasoning + render in output; re-brief
  from the card), AR088 ADRs + drift tool (ADRs were drafted, 8/8 drift tests
  passed pre-incident), yaml hardening (see above — two except clauses + one
  additive test case).
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
3. **After the next verified wave: push or mirror.** This repo survived a total
   worktree loss only because .git/objects was left behind. See section 0.

## 7. Working protocol (proven this session — keep)

- Per agent: exclusive file lease, explicit `git add <paths>` (never `-A`),
  `git branch --show-current` before each commit, final report with exact
  commands/results/deviations/unverified. Agents work in the main tree in
  parallel; never stash/checkout/reset/clean.
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
| Contracts | `-m pytest tests/contract -q` | 242 passed, 1 skipped |
| Rule tests + meta-tests | `-m pytest tests/rules -q` | 439 passed |
| Rule docs | `tools/gen_rule_docs.py --check` | 50 files up to date |
| Ratchet | `tools/ratchet_check.py --baseline docs/architecture-roadmap-2026-11-21/baseline.json` | PASS |
| Report identity | `-m tools.report_identity` | 84c7b18a… |
| Full suite | `-m pytest -q -ra -m "not live" -n auto --timeout=300 -p no:cacheprovider` | ~6975 passed, 11 known failures, ~5.3 min |
| Registry in pipeline | `attackmap.exe rules list --json` | 49 registry ids |
| Eval baseline | `attackmap.exe eval rules --corpus corpus/reference.yaml --json` | exit 0, per-rule tp/fp/fn |

Baseline recorded at `0647c9d`: ruff 649 (repo-wide), mypy 537/69, cycles 0,
broad excepts 63, longest function 750, 75 functions >80 lines, models fan-in
60, 194 modules. Tighten-only.

## 9. Known host failures (NOT regressions)

`tests/unit/test_output_exclusion.py` (6), `tests/unit/test_scanner.py` (2:
Flask blueprint prefix, path normalization),
`tests/unit/test_local_provider_timeouts.py` (2),
`tests/unit/test_regex_budget.py::test_pattern_scales_linearly` for
`python_django_routes._MODULE` (1). Anything else failing is new.

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
