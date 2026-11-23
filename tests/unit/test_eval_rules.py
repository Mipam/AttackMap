"""AR048 detection-quality harness tests.

Covers, in the ``unit`` tier where possible:
  * the pure comparison semantics — TP/FP/FN, line-range boundaries, file
    mismatch, unlocated findings, precision/recall math, deterministic order;
  * corpus schema validation (`attackmap.eval.load_cases`);
  * deterministic report bytes (``generated_at`` injected);
  * the ``attackmap eval rules`` CLI smoke through CliRunner;
  * one end-to-end mini-corpus through the real ``analyze`` scan.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from attackmap.eval import (
    Expectation,
    LocatedFinding,
    compare,
    load_cases,
    render_table,
    report_dict,
)
from attackmap.surfaces.eval_cli import run_evaluation

pytestmark = [pytest.mark.unit]

REPO_ROOT = Path(__file__).resolve().parents[2]
CORPUS_YAML = REPO_ROOT / "corpus" / "reference.yaml"

runner = CliRunner()


def _finding(rule_id: str, *locations: tuple[str, int | None]) -> LocatedFinding:
    return LocatedFinding(rule_id=rule_id, locations=tuple(locations))


# --- matching semantics ---------------------------------------------------------


def test_expectation_matches_finding_on_rule_file_and_inclusive_range():
    finding = _finding("hardcoded_secret_literals", ("src/app.py", 17))
    assert finding.satisfies(Expectation("hardcoded_secret_literals", "src/app.py", 10, 17))
    assert finding.satisfies(Expectation("hardcoded_secret_literals", "src/app.py", 17, 20))
    assert not finding.satisfies(Expectation("hardcoded_secret_literals", "src/app.py", 18, 20))
    assert not finding.satisfies(Expectation("hardcoded_secret_literals", "src/app.py", 1, 16))


def test_expectation_requires_same_rule_and_same_file():
    finding = _finding("route_public_webhook", ("src/app.py", 22))
    assert not finding.satisfies(Expectation("other_rule", "src/app.py", 1, 30))
    assert not finding.satisfies(Expectation("route_public_webhook", "other.py", 1, 30))


def test_unlocated_finding_never_satisfies_an_expectation():
    finding = _finding("taint_flow_sql_execute", ("src/app.py", None))
    assert not finding.satisfies(Expectation("taint_flow_sql_execute", "src/app.py", 1, 100))


def test_expectation_rejects_bad_line_range():
    with pytest.raises(ValueError, match="line_range"):
        Expectation("rule", "file.py", 0, 5)
    with pytest.raises(ValueError, match="line_range"):
        Expectation("rule", "file.py", 7, 6)


# --- confusion counts -----------------------------------------------------------


def test_compare_counts_tp_fp_fn_per_rule():
    findings = [
        _finding("rule_a", ("f.py", 5)),           # satisfies expectation 1 -> not an FP
        _finding("rule_a", ("f.py", 100)),          # matches nothing -> FP
        _finding("rule_b", ("f.py", 9)),            # satisfies both rule_b expectations -> no FP
    ]
    expectations = [
        Expectation("rule_a", "f.py", 1, 10),
        Expectation("rule_a", "f.py", 50, 60),      # unsatisfied -> FN
        Expectation("rule_b", "f.py", 8, 9),
        Expectation("rule_b", "f.py", 9, 10),
        Expectation("rule_c", "f.py", 1, 3),        # no findings at all -> FN
    ]
    stats = {item.rule_id: item for item in compare(findings, expectations).per_rule}
    assert (stats["rule_a"].tp, stats["rule_a"].fp, stats["rule_a"].fn) == (1, 1, 1)
    assert (stats["rule_b"].tp, stats["rule_b"].fp, stats["rule_b"].fn) == (2, 0, 0)
    assert (stats["rule_c"].tp, stats["rule_c"].fp, stats["rule_c"].fn) == (0, 0, 1)
    # One aggregate finding satisfies several expectations without becoming FPs.
    assert stats["rule_b"].found == 1


def test_compare_orders_rules_deterministically_regardless_of_input_order():
    expectations = [Expectation("z_rule", "f.py", 1, 2), Expectation("a_rule", "f.py", 1, 2)]
    forward = compare([_finding("z_rule", ("f.py", 1)), _finding("a_rule", ("f.py", 1))], expectations)
    backward = compare([_finding("a_rule", ("f.py", 1)), _finding("z_rule", ("f.py", 1))], reversed(expectations))
    assert [item.rule_id for item in forward.per_rule] == ["a_rule", "z_rule"]
    assert forward == backward


# --- precision / recall ---------------------------------------------------------


def test_precision_recall_math_and_empty_denominators():
    from attackmap.eval import RuleStats

    measured = RuleStats(rule_id="r", tp=3, fp=1, fn=1, expected=4, found=4)
    assert measured.precision == pytest.approx(0.75)
    assert measured.recall == pytest.approx(0.75)
    unmeasured = RuleStats(rule_id="r", tp=0, fp=0, fn=0, expected=0, found=0)
    assert unmeasured.precision is None
    assert unmeasured.recall is None
    recall_only = RuleStats(rule_id="r", tp=0, fp=2, fn=0, expected=0, found=2)
    assert recall_only.precision == 0.0
    assert recall_only.recall is None


def test_totals_sum_rules_with_none_when_denominator_empty():
    report = compare(
        [_finding("b_rule", ("f.py", 1)), _finding("noise", ("f.py", 2))],
        [Expectation("a_rule", "f.py", 1, 1), Expectation("b_rule", "f.py", 1, 1)],
    )
    assert (report.tp, report.fp, report.fn) == (1, 1, 1)
    assert report.precision == pytest.approx(0.5)
    assert report.recall == pytest.approx(0.5)


# --- corpus schema --------------------------------------------------------------


def test_load_cases_validates_schema_and_duplicate_names():
    document = {
        "corpus_revision": "1",
        "cases": [
            {
                "name": "case-1",
                "repo": "repos/case-1",
                "revision": "1",
                "expect": [{"rule_id": "rule_a", "file": "f.py", "line_range": [1, 2]}],
            }
        ],
    }
    (case,) = load_cases(document)
    assert case.name == "case-1"
    assert case.expectations == (Expectation("rule_a", "f.py", 1, 2),)
    with pytest.raises(ValueError, match="duplicate case name"):
        load_cases({**document, "cases": [document["cases"][0], document["cases"][0]]})
    with pytest.raises(ValueError, match="line_range"):
        load_cases({
            "cases": [{**document["cases"][0], "expect": [{"rule_id": "r", "file": "f", "line_range": [2]}]}]
        })
    with pytest.raises(ValueError, match="non-empty list"):
        load_cases({"cases": []})


# --- report determinism ----------------------------------------------------------


def _sample_report():
    return compare(
        [_finding("rule_a", ("f.py", 5)), _finding("noise", ("f.py", 7))],
        [Expectation("rule_a", "f.py", 1, 10), Expectation("rule_b", "f.py", 1, 2)],
    )


def test_report_bytes_identical_with_injected_timestamp():
    first = report_dict(
        _sample_report(),
        tool_version="1.5.1",
        corpus_revision="1",
        corpus_commit="abc",
        generated_at="2026-11-23T00:00:00+00:00",
    )
    second = report_dict(
        _sample_report(),
        tool_version="1.5.1",
        corpus_revision="1",
        corpus_commit="abc",
        generated_at="2026-11-23T00:00:00+00:00",
    )
    assert json.dumps(first, indent=2) == json.dumps(second, indent=2)


def test_render_table_lists_every_rule_and_totals():
    payload = report_dict(
        _sample_report(),
        tool_version="1.5.1",
        corpus_revision="1",
        corpus_commit=None,
        generated_at="t",
    )
    table = render_table(payload)
    for rule_id in ("noise", "rule_a", "rule_b"):
        assert rule_id in table
    assert "totals" in table
    assert "n/a" in table  # recall for a rule with no expectations


# --- eval CLI smoke --------------------------------------------------------------


def _json_from_output(output: str) -> dict:
    # CliRunner mixes stderr into result.output in this environment: the JSON
    # document starts at the first '{'.
    return json.loads(output[output.index("{"): ])


@pytest.mark.skipif(not CORPUS_YAML.is_file(), reason="reference corpus not checked out")
def test_eval_rules_cli_json_reports_the_reference_corpus():
    from attackmap.surfaces.cli import app

    result = runner.invoke(app, ["eval", "rules", "--corpus", str(CORPUS_YAML), "--json"])
    assert result.exit_code == 0, result.output
    report = _json_from_output(result.output)
    assert report["tool_version"]
    assert report["corpus_revision"] == "1"
    totals = report["totals"]
    assert totals["expected"] == 16
    assert totals["tp"] >= 15
    # Every expectation labels a registered (or known legacy) rule id.
    assert "hardcoded_secret_literals" in report["per_rule"]
    assert "workflow_security" in report["per_rule"]
    # The unwired seed rule is the documented false negative.
    seed = report["per_rule"]["demo_weak_default_credentials"]
    assert (seed["tp"], seed["fn"]) == (0, 1)


def test_eval_rules_cli_table_output_and_missing_corpus():
    from attackmap.surfaces.cli import app

    result = runner.invoke(app, ["eval", "rules", "--corpus", str(CORPUS_YAML)])
    assert result.exit_code == 0, result.output
    assert "rule" in result.output and "totals" in result.output
    missing = runner.invoke(app, ["eval", "rules", "--corpus", "no/such.yaml", "--json"])
    assert missing.exit_code == 2
    assert "corpus not found" in missing.output


# --- end-to-end mini-corpus through analyze() ------------------------------------


def test_run_evaluation_scans_a_tiny_corpus(tmp_path: Path):
    repo = tmp_path / "repos" / "mini"
    repo.mkdir(parents=True)
    (repo / "app.py").write_text(
        'API_KEY = "AKIAIOSFODNN7EXAMPLE"\nDEBUG = True\n', encoding="utf-8"
    )
    corpus = tmp_path / "corpus.yaml"
    corpus.write_text(
        "corpus_revision: '1'\n"
        "cases:\n"
        "  - name: mini\n"
        "    repo: repos/mini\n"
        "    revision: '1'\n"
        "    expect:\n"
        "      - {rule_id: hardcoded_secret_literals, file: app.py, line_range: [1, 1]}\n"
        "      - {rule_id: debug_mode_exposure, file: app.py, line_range: [2, 2]}\n",
        encoding="utf-8",
    )
    report = run_evaluation(corpus, generated_at="fixed")
    assert report["generated_at"] == "fixed"
    per_rule = report["per_rule"]
    assert per_rule["hardcoded_secret_literals"]["tp"] == 1
    assert per_rule["debug_mode_exposure"]["tp"] == 1
    assert report["totals"]["fn"] == 0
