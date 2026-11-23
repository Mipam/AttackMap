# Authoring a reasoning rule — the 30-minute walkthrough

This is the hands-on guide for adding a rule to the kernel rule registry. A
rule is two things: a frozen `RuleMeta` (its stable, suppressible identity)
and one `evaluate(ctx)` method that turns observation records into
`Finding`s. Everything below uses the Windows dev environment
(`.venv/Scripts/python.exe`); on POSIX swap in `python` / `.venv/bin/python`.

What exists before you start (all paths repo-relative):

- `src/attackmap/reasoning/rules/base.py` — the `RuleMeta` / `Rule` contract.
- `src/attackmap/reasoning/rules/registry.py` — `REGISTRY`, the
  process-wide registry every rule module self-registers into on import.
- `src/attackmap/reasoning/context.py` — `ReasoningContext`, the read-only
  snapshot of scan slices a rule may see.
- `src/attackmap/model/taxonomy.py` — `RULE_TAXONOMY`, the CWE / OWASP /
  ASVS / ATT&CK enrichment keyed by stable rule id.
- `tests/rules/_harness.py` — the focused-test harness
  (`run_rule`, `assert_rule_positive`, `assert_rule_negative`).
- `tests/rules/_template.py` — the copy-paste test template.
- `tools/new_rule.py` — the scaffold tool; `tools/gen_rule_docs.py` — the
  reference-doc generator.

## The walkthrough, timed

We will add a real (small) rule end to end: pick a signal, scaffold, write
`evaluate()`, add fixtures and a focused test, run the tier, regenerate the
docs. Budget 30 minutes; each step shows its slice of the budget.

### 0:00–3:00 — Pick a signal

A rule reasons over one `ReasoningContext` slice. The slices (see
`src/attackmap/reasoning/context.py` for the record models):

| Slice | Record model | Typical rule family |
| --- | --- | --- |
| `routes` | `Route` | route exposure / auth gaps |
| `external_calls` | `ExternalCall` | outbound trust boundaries |
| `databases` | `DatabaseHint` | datastore edges |
| `auth_hints` | `AuthHint` | auth coverage |
| `secret_hints` | `SecretHint` | secret exposure |
| `taint_chains` | `TaintChain` | injection sinks |
| `code_weaknesses` | `CodeWeakness` | code-level weaknesses |
| `web_hardening_issues` | `WebHardeningIssue` | debug/CSP/config exposure |
| `vulnerabilities` | `Vulnerability` | dependency CVEs |
| `workflow_issues` | `WorkflowIssue` | CI workflow posture |
| `supply_chain_issues` | `SupplyChainIssue` | dependency supply chain |

Helper lookups on the context: `routes_by_file`, `calls_by_file`,
`files_by_suffix(".py")`, `source_text(path)`. Rules must not do disk I/O —
the context is the whole world a rule gets, and the container is frozen.

Our walkthrough rule: fire when a scan observed **debug mode enabled** — but
say the family you want does not exist yet; the point is the shape, not the
signal. Check what already covers it so you do not duplicate:

```bash
.venv/Scripts/python.exe -m attackmap rules list
.venv/Scripts/python.exe -m attackmap rules show debug_mode_exposure
```

(`attackmap rules list --json` / `rules show <id>` read the registered
rules; plain `attackmap rules` lists the report producer's ids.)

### 3:00–5:00 — Scaffold the rule and its test

```bash
.venv/Scripts/python.exe tools/new_rule.py --id demo_debug_mode_check
```

The tool validates the id (`^[a-z][a-z0-9_]*$`), rejects duplicates against
`REGISTRY`, and creates:

- `src/attackmap/reasoning/rules/demo_debug_mode_check.py` — a
  `RuleMeta`-carrying class whose `evaluate()` raises `NotImplementedError`
  with the contract in the message. The `REGISTRY.register(...)` line is
  **commented out on purpose**: a scaffolded rule must not register (a
  registered rule whose `evaluate()` raises is reported as a broken rule on
  every scan).
- `tests/rules/test_demo_debug_mode_check.py` — failing stubs with the
  `@pytest.mark.rule(...)` marks **commented out** (an active mark naming an
  unregistered id fails the stale-marker check, see below).

Prefer to experiment outside the repo first? Target a scratch dir — nothing
in the tree is touched:

```bash
.venv/Scripts/python.exe tools/new_rule.py --id demo_rule \
    --rules-dir C:/tmp/attackmap-scratch/rules \
    --test C:/tmp/attackmap-scratch/test_demo_rule.py
```

### 5:00–10:00 — Fill in `RuleMeta` and the taxonomy entry

Edit the scaffolded module. `RuleMeta` fields (`base.py`):

| Field | Notes |
| --- | --- |
| `id` | The snake_case id you scaffolded. Never changes, never carries prose; it is the SARIF ruleId and the suppression key. |
| `title` | One-sentence finding title. |
| `cwe` | e.g. `"CWE-489"` — must agree with the taxonomy entry. |
| `severity` | `"high"` / `"medium"` / `"low"`. |
| `confidence` | Float 0.0–1.0, the rule's trust in its own detection; `confidence_band()` maps it onto the finding's low/medium/high band (≥ 0.8 high, ≥ 0.5 medium). |
| `rationale` | Why the rule exists — this text lands on every finding, so explain the risk. |
| `tags` | First tag groups the generated docs index; keep them short and stable. |

Porting a legacy cascade branch? Also set `legacy_rule_ids = ("dashed-id",)`
on the class so the generated page records the mapping.

Then the taxonomy entry — **without it the rule's findings lose their
CWE/OWASP/ASVS/ATT&CK enrichment** (`tools/gen_rule_docs.py` shows a lone CWE
row, and the pipeline attaches nothing). In
`src/attackmap/model/taxonomy.py`:

- Porting: reference the legacy entry's object in the `RULE_TAXONOMY.update`
  block — `"demo_debug_mode_check": RULE_TAXONOMY["debug-enabled"],` — never
  hand-copy the data.
- Brand-new rule: add a new `RuleTaxonomy(cwe=(489,), owasp=("A05:2021",),
  asvs=(), attack=())` entry keyed by your id, plus any new CWE id in
  `CWE_NAMES` / ATT&CK id in `ATTACK_TECHNIQUES`. Verify ids against the
  source (cwe.mitre.org, owasp.org, the ASVS release, the ATT&CK STIX
  bundle), not memory. `tests/test_taxonomy.py` fails when a rule id has no
  mapping, so this cannot be forgotten silently.

### 10:00–18:00 — Write `evaluate()`

Uncomment `REGISTRY.register(...)` at the bottom of the module and add the
import to `src/attackmap/reasoning/rules/__init__.py` (next to the other
ported modules) — importing the package is what populates `REGISTRY`
everywhere, including `tools/gen_rule_docs.py` and the test tier.

```python
from .base import RuleMeta, confidence_band  # (already in the scaffold; add confidence_band)

def evaluate(self, ctx: ReasoningContext) -> list[Finding]:
    issues = [i for i in ctx.web_hardening_issues if i.kind == "debug_enabled"]
    if not issues:
        return []
    return [
        Finding(
            title=self.meta.title,
            severity=self.meta.severity,
            rule_id=self.meta.id,          # the attribution contract
            confidence=confidence_band(self.meta.confidence),
            evidence=[f"{i.file}:{i.line} — {i.evidence_text}" for i in issues[:10]],
            locations=[FindingLocation(file=i.file, line=i.line) for i in issues],
            mitigation="Turn debug mode off before shipping; ...",
            tags=list(self.meta.tags),
        )
    ]
```

The finding contract:

- Every finding carries `rule_id=self.meta.id` — findings are attributable
  and suppressible, and the harness *fails* a positive test that emits a
  foreign rule id.
- One `FindingLocation` per distinct `(file, line)` behind the evidence;
  never cap locations.
- Keep evidence lines short and capped (~10); the class docstring and the
  `evaluate()` docstring render into the generated reference page under
  "Evidence expectations", so state what the rule expects to observe.

### 18:00–23:00 — Fixtures and the focused test

Copy the template and adapt it:

```bash
cp tests/rules/_template.py tests/rules/test_demo_debug_mode_check.py
```

(`tests/` has no `__init__.py`; the basename must be unique suite-wide.)

Fixtures are built **in code** — a `ScanResult` (narrowed by the harness
through `ReasoningContext.from_scan`) or a `ReasoningContext` used as is.
The harness never scans a repository on disk; that is the integration tier.

```python
import pytest
from _harness import assert_rule_negative, assert_rule_positive

pytestmark = [pytest.mark.unit]

POSITIVE = ScanResult(root="", web_hardening_issues=[
    WebHardeningIssue(kind="debug_enabled", file="app/settings.py", line=30,
                      evidence_text="DEBUG = True", severity="medium"),
])
NEGATIVE = ScanResult(root="", web_hardening_issues=[
    WebHardeningIssue(kind="weak_csp", file="app/middleware.py", line=9,
                      evidence_text="unsafe-inline", severity="medium"),
])

@pytest.mark.rule("demo_debug_mode_check")
def test_fires_on_debug_enabled():
    assert_rule_positive("demo_debug_mode_check", POSITIVE, at="app/settings.py")

@pytest.mark.rule("demo_debug_mode_check")
def test_stays_silent_on_other_hardening_issues():
    assert_rule_negative("demo_debug_mode_check", NEGATIVE,
                         reason="other web-hardening kinds are other rules' signal")
```

The `@pytest.mark.rule("<id>")` mark is the registration convention: it
makes the test the rule's *focused test*, which is what the two AR047
meta-tests (below) read from disk. A parametrized test names the rule per
case: `pytest.param(..., marks=pytest.mark.rule("<id>"))`.

### 23:00–26:00 — Run the tests

```bash
# focused
.venv/Scripts/python.exe -m pytest tests/rules/test_demo_debug_mode_check.py -v
# the whole rule tier (also runs the coverage + mutation meta-tests)
.venv/Scripts/python.exe -m pytest tests/rules -q
```

Two meta-tests guard the convention (see `tests/rules/test_rule_coverage.py`
and `test_rule_mutation.py`):

- **Coverage (AC-202):** every registered rule id has at least one *active*
  focused test. A new rule without tests **fails the suite** — that is why
  the scaffolded marks ship commented, and why the template skips itself.
- **Mutation:** disabling a rule (it emits nothing) must break at least one
  of its focused tests — so a test that passes regardless of what the rule
  emits does not count. A test that asserts nothing lets the mutant survive
  and is flagged.

Also: a `rule` mark naming an id that is not registered fails the
stale-marker check — the usual cause is a renamed rule or a typo.

### 26:00–28:00 — Regenerate the reference docs

`docs/reference/rules/*.md` is a generated artifact — never edit it by hand.

```bash
.venv/Scripts/python.exe tools/gen_rule_docs.py          # (re)write the pages
.venv/Scripts/python.exe tools/gen_rule_docs.py --check  # must stay clean (CI blocks on it)
```

A `docs/reference/rules/demo_debug_mode_check.md` page appears, grouped in
the index under your first tag, with the taxonomy enrichment table and your
docstrings. The generator discovers rules by importing
`attackmap.reasoning.rules`, so a rule that is not imported in
`rules/__init__.py` is invisible to it.

### 28:00–30:00 — The last mile

```bash
.venv/Scripts/python.exe -m pytest tests/rules -q                    # whole tier green
.venv/Scripts/python.exe -m ruff check src/attackmap tests tools     # clean
.venv/Scripts/python.exe -m attackmap rules show demo_debug_mode_check  # the catalog sees it
```

Done. If your rule intentionally changes a ratchet metric, update
`tools/ratchet_check.py`'s baseline per that tool's docs — a docs-only change
never moves a metric.

## Retiring or demoing a rule

- **Retire:** delete the rule's module (and its import in
  `rules/__init__.py`), delete its focused test file (or remove its
  `rule` marks), drop its `RULE_TAXONOMY` entry if nothing else uses the
  key, then re-run `gen_rule_docs.py` (it prunes stale pages). The cascade's
  legacy dashed ids in `RULE_TAXONOMY` stay until the cascade itself is
  retired — do not remove an entry the active producer still looks up.
- **Demo rules:** keep them small, tag them honestly, and give them real
  focused tests like any other rule — the seed rule
  (`demo_weak_default_credentials` in `rules/__init__.py`) is the reference.
  A demo rule that registers without tests fails the coverage meta-test
  exactly like a production rule.

## Pitfalls checklist

1. Id not matching `^[a-z][a-z0-9_]*$` — `RuleMeta` rejects it at import.
2. Rule imported nowhere → invisible to `REGISTRY`, the docs generator and
   the CLI. Add the module import in `rules/__init__.py`.
3. Missing `RULE_TAXONOMY` entry → findings lose CWE/OWASP/ATT&CK
   enrichment; `tests/test_taxonomy.py` fails.
4. `rule` mark naming an unregistered id → stale-marker check fails.
5. Test without the `rule` mark → coverage check fails (the rule reads as
   untested even though the test exists).
6. Editing generated docs by hand → `--check` fails next CI run.
7. Skipped focused tests do not cover a rule — pytest never runs them, so
   the coverage check counts them as absent.
