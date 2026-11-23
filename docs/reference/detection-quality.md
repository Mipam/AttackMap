# Detection quality baseline (AR048 / AC-206)

Published per-rule precision/recall for the labelled reference corpus
(`corpus/reference.yaml`). The corpus drives a real `analyze()` scan per
fixture repository and compares the findings against the labelled
expectations; the report records the corpus and tool versions so a baseline
line is attributable and reproducible.

## How to regenerate

```bash
# Human table:
.venv/Scripts/python.exe -m tools.eval_rules --corpus corpus/reference.yaml

# Machine-readable (AC-206 verify command):
.venv/Scripts/attackmap.exe eval rules --corpus corpus/reference.yaml --json > eval.json

# Optional recall gate (exits 1 when a named rule falls below the gate):
.venv/Scripts/python.exe -m tools.eval_rules --corpus corpus/reference.yaml \
    --fail-under-recall hardcoded_secret_literals=1.0
```

Scan artifacts go to a temporary directory and are deleted when the run
finishes; only the comparison is emitted. A completed measurement always
exits 0 — a low score is a measurement, not a failure.

## Versions

- Tool: `1.5.1` (`attackmap --version`, single-sourced from `src/attackmap/__init__.py`)
- Corpus revision: `1`
- Corpus commit: recorded per run in the report's `corpus_commit` field
  (`git rev-parse HEAD` at the corpus location; `null` outside a git work tree)

## Baseline (corpus revision 1, tool 1.5.1, 2026-11-23)

One case, `vulnerable-app` (`corpus/repos/vulnerable-app`, revision `1`), with
16 expectations across 11 rules. The scan path still emits the legacy dashed
rule ids — the cascade is the active producer until the registry retirement
wiring — so the tool maps findings onto the stable snake_case registry ids
through each registered rule's `legacy_rule_ids` before comparing.

```
rule                           tp  fp  fn  expected  found  precision  recall
debug_mode_exposure            1   0   0   1         1      1.00       1.00
demo_weak_default_credentials  0   0   1   1         0      n/a        0.00
hardcoded_secret_literals      3   0   0   3         1      1.00       1.00
insecure-upload                0   1   0   0         1      0.00       n/a
public-data-route              0   1   0   0         1      0.00       n/a
route_exposed_admin            1   0   0   1         1      1.00       1.00
route_public_webhook           1   0   0   1         1      1.00       1.00
route_upload_import            1   0   0   1         1      1.00       1.00
route_weak_auth_controls       1   0   0   1         1      1.00       1.00
secret_env_references          1   0   0   1         1      1.00       1.00
taint_flow_sql_execute         1   0   0   1         1      1.00       1.00
taint_sink_subprocess_shell    1   0   0   1         1      1.00       1.00
workflow_security              4   0   0   4         4      1.00       1.00
totals                         15  2   1   16        15     0.88       0.94
```

## Reading the baseline

- The ten registry rules with expectations measure precision 1.00 / recall
  1.00 on this corpus: each labelled detection fires, and no finding in
  expectation-labelled rule families is spurious.
- `demo_weak_default_credentials` is the one false negative, deliberately:
  the seed rule is registered but not yet wired into the scan pipeline, so
  nothing on the scan path can satisfy it. The FN keeps the baseline honest
  about that gap until the cascade-retirement wiring lands.
- `insecure-upload` and `public-data-route` are false positives carrying
  legacy cascade ids with no registered snake_case counterpart yet. They are
  real detections the fixture does not label — recorded noise, not hidden —
  and they explain the totals precision of 0.88.
- `n/a` marks an unmeasured side: precision with no findings, recall with no
  expectations.

## Corpus format

See the header comment of `corpus/reference.yaml` and the docstring of
`attackmap.eval.rules.load_cases`. Expectations name the snake_case registry
id (`attackmap rules list`), the repo-relative file, and an inclusive
`line_range`; a finding matches when its rule id is equal and any location
names the same file with a line inside the range.

Keep fixture repositories tiny and stable: expectation line ranges pin exact
source lines, so editing a fixture means regenerating this baseline and
bumping `corpus_revision`.
