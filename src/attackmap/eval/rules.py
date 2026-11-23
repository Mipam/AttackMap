"""Detection-quality evaluation (AR048): labelled-corpus comparison and metrics.

The package is deliberately low-layer: it imports nothing outside the
standard library. Callers (the ``attackmap eval rules`` surface and
``tools/eval_rules.py``) adapt real pipeline output — ``attackmap.model.Finding``
lists — into the plain dataclasses defined here and hand over the corpus
document already parsed from YAML. Keeping YAML parsing and orchestration
outside is what lets this package stay pure, deterministic and fast to test.

Corpus schema (owned here, parsed by the caller)::

    corpus_revision: "1"            # free-form string pinned by the corpus
    cases:
      - name: vulnerable-app        # unique case label
        repo: repos/vulnerable-app  # fixture repository (resolved by the caller)
        revision: "1"               # fixture revision label
        expect:
          - rule_id: hardcoded_secret_literals
            file: src/app.py        # path relative to the fixture repo root
            line_range: [17, 19]    # inclusive; finding line must fall inside

Matching semantics: an expectation is satisfied (a true positive) when at
least one finding carries the same ``rule_id`` AND at least one of that
finding's locations names the same file with a line inside the inclusive
range. A finding that satisfies no expectation of its rule is a false
positive; an expectation no finding satisfies is a false negative.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

__all__ = [
    "CorpusCase",
    "EvalReport",
    "Expectation",
    "LocatedFinding",
    "RuleStats",
    "compare",
    "load_cases",
    "render_table",
    "report_dict",
]

_SCHEMA = "AR048 reference corpus"


@dataclass(frozen=True)
class Expectation:
    """One labelled detection: ``rule_id`` must fire at ``file`` within
    ``[line_start, line_end]`` (inclusive)."""

    rule_id: str
    file: str
    line_start: int
    line_end: int

    def __post_init__(self) -> None:
        if not self.rule_id:
            raise ValueError("expectation rule_id must be non-empty")
        if not self.file:
            raise ValueError("expectation file must be non-empty")
        if self.line_start < 1 or self.line_end < self.line_start:
            raise ValueError(
                f"invalid line_range [{self.line_start}, {self.line_end}]: "
                "1 <= start <= end required"
            )


@dataclass(frozen=True)
class CorpusCase:
    """One fixture repository plus the expectations labelling it."""

    name: str
    repo: str  # path as written in the corpus; the caller resolves it
    revision: str
    expectations: tuple[Expectation, ...]


@dataclass(frozen=True)
class LocatedFinding:
    """A finding normalized to what comparison needs: its rule id and every
    ``(file, line)`` location. ``line`` is ``None`` when the producer could
    not pin one; an unlocated entry never satisfies an expectation."""

    rule_id: str
    locations: tuple[tuple[str, int | None], ...]

    def satisfies(self, expectation: Expectation) -> bool:
        """True when this finding is the detection the expectation labels."""
        return self.rule_id == expectation.rule_id and any(
            file == expectation.file
            and line is not None
            and expectation.line_start <= line <= expectation.line_end
            for file, line in self.locations
        )


@dataclass(frozen=True)
class RuleStats:
    """Per-rule confusion counts and derived metrics.

    ``precision`` is ``tp / (tp + fp)`` and ``recall`` is ``tp / (tp + fn)``;
    each is ``None`` when its denominator is zero (nothing found, nothing
    expected — the rule is unmeasured on that side).
    """

    rule_id: str
    tp: int
    fp: int
    fn: int
    expected: int
    found: int

    @property
    def precision(self) -> float | None:
        """Fraction of findings that satisfied an expectation, or None."""
        denominator = self.tp + self.fp
        return self.tp / denominator if denominator else None

    @property
    def recall(self) -> float | None:
        """Fraction of expectations satisfied by a finding, or None."""
        denominator = self.tp + self.fn
        return self.tp / denominator if denominator else None


@dataclass(frozen=True)
class EvalReport:
    """The comparison of one findings list against one expectation list.

    ``per_rule`` is sorted by rule id; totals are the sums across rules with
    ``None`` where the denominator is empty.
    """

    per_rule: tuple[RuleStats, ...]

    @property
    def tp(self) -> int:
        return sum(rule.tp for rule in self.per_rule)

    @property
    def fp(self) -> int:
        return sum(rule.fp for rule in self.per_rule)

    @property
    def fn(self) -> int:
        return sum(rule.fn for rule in self.per_rule)

    @property
    def expected(self) -> int:
        return sum(rule.expected for rule in self.per_rule)

    @property
    def found(self) -> int:
        return sum(rule.found for rule in self.per_rule)

    @property
    def precision(self) -> float | None:
        denominator = self.tp + self.fp
        return self.tp / denominator if denominator else None

    @property
    def recall(self) -> float | None:
        denominator = self.tp + self.fn
        return self.tp / denominator if denominator else None


def load_cases(document: Mapping[str, object]) -> tuple[CorpusCase, ...]:
    """Validate an already-parsed corpus document into cases.

    The YAML/JSON parsing deliberately stays with the caller so this package
    keeps no third-party imports; everything about the schema — field names,
    types and the rejection of malformed entries — lives here.
    """
    revision = document.get("corpus_revision")
    if revision is not None and not isinstance(revision, str):
        raise ValueError(f"{_SCHEMA}: corpus_revision must be a string, got {revision!r}")
    raw_cases = document.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ValueError(f"{_SCHEMA}: 'cases' must be a non-empty list")
    cases: list[CorpusCase] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_cases):
        where = f"cases[{index}]"
        if not isinstance(raw, Mapping):
            raise ValueError(f"{_SCHEMA}: {where} must be a mapping, got {raw!r}")
        name = raw.get("name")
        repo = raw.get("repo")
        case_revision = raw.get("revision")
        if not isinstance(name, str) or not name:
            raise ValueError(f"{_SCHEMA}: {where}.name must be a non-empty string")
        if name in seen:
            raise ValueError(f"{_SCHEMA}: duplicate case name {name!r}")
        seen.add(name)
        if not isinstance(repo, str) or not repo:
            raise ValueError(f"{_SCHEMA}: {where}.repo must be a non-empty string")
        if not isinstance(case_revision, str) or not case_revision:
            raise ValueError(f"{_SCHEMA}: {where}.revision must be a non-empty string")
        raw_expect = raw.get("expect")
        if not isinstance(raw_expect, list):
            raise ValueError(f"{_SCHEMA}: {where}.expect must be a list")
        expectations: list[Expectation] = []
        for expect_index, raw_exp in enumerate(raw_expect):
            exp_where = f"{where}.expect[{expect_index}]"
            if not isinstance(raw_exp, Mapping):
                raise ValueError(f"{_SCHEMA}: {exp_where} must be a mapping, got {raw_exp!r}")
            rule_id = raw_exp.get("rule_id")
            file = raw_exp.get("file")
            line_range = raw_exp.get("line_range")
            if not isinstance(rule_id, str) or not isinstance(file, str):
                raise ValueError(f"{_SCHEMA}: {exp_where} needs string rule_id and file")
            if (
                not isinstance(line_range, list)
                or len(line_range) != 2
                or not all(isinstance(item, int) for item in line_range)
            ):
                raise ValueError(f"{_SCHEMA}: {exp_where}.line_range must be [start, end] integers")
            expectations.append(
                Expectation(rule_id=rule_id, file=file, line_start=line_range[0], line_end=line_range[1])
            )
        cases.append(
            CorpusCase(name=name, repo=repo, revision=case_revision, expectations=tuple(expectations))
        )
    return tuple(cases)


def compare(
    findings: Iterable[LocatedFinding],
    expectations: Iterable[Expectation],
) -> EvalReport:
    """Confusion counts per rule: TP/FP/FN with deterministic ordering.

    An expectation is a true positive when at least one finding satisfies it;
    a finding is a false positive when it satisfies no expectation of its own
    rule; an unsatisfied expectation is a false negative. Rules are reported
    in sorted-id order regardless of input order, so the report is stable.
    """
    finding_list = list(findings)
    expectation_list = list(expectations)
    rule_ids = sorted(
        {finding.rule_id for finding in finding_list}
        | {expectation.rule_id for expectation in expectation_list}
    )
    per_rule: list[RuleStats] = []
    for rule_id in rule_ids:
        rule_findings = [finding for finding in finding_list if finding.rule_id == rule_id]
        rule_expectations = [expectation for expectation in expectation_list if expectation.rule_id == rule_id]
        tp = sum(
            any(finding.satisfies(expectation) for finding in rule_findings)
            for expectation in rule_expectations
        )
        fp = sum(
            not any(finding.satisfies(expectation) for expectation in rule_expectations)
            for finding in rule_findings
        )
        fn = len(rule_expectations) - tp
        per_rule.append(
            RuleStats(
                rule_id=rule_id,
                tp=tp,
                fp=fp,
                fn=fn,
                expected=len(rule_expectations),
                found=len(rule_findings),
            )
        )
    return EvalReport(per_rule=tuple(per_rule))


def report_dict(
    report: EvalReport,
    *,
    tool_version: str,
    corpus_revision: str | None,
    corpus_commit: str | None,
    generated_at: str,
) -> dict[str, object]:
    """The versioned JSON report: corpus and tool identity plus per-rule
    metrics and totals. Key order is fixed, so two calls with equal inputs
    (and an injected ``generated_at``) produce byte-identical JSON."""
    return {
        "tool_version": tool_version,
        "corpus_revision": corpus_revision,
        "corpus_commit": corpus_commit,
        "generated_at": generated_at,
        "per_rule": {
            stats.rule_id: {
                "tp": stats.tp,
                "fp": stats.fp,
                "fn": stats.fn,
                "expected": stats.expected,
                "found": stats.found,
                "precision": stats.precision,
                "recall": stats.recall,
            }
            for stats in report.per_rule
        },
        "totals": {
            "rules": len(report.per_rule),
            "tp": report.tp,
            "fp": report.fp,
            "fn": report.fn,
            "expected": report.expected,
            "found": report.found,
            "precision": report.precision,
            "recall": report.recall,
        },
    }


def render_table(report: Mapping[str, object]) -> str:
    """The human-readable form of a `report_dict` payload, for the non-JSON
    output of the eval tool. Deterministic: rows follow the payload's (already
    sorted) rule order."""

    def _metric(value: object) -> str:
        return "n/a" if value is None else f"{value:.2f}"

    per_rule = report.get("per_rule", {})
    totals = report.get("totals", {})
    if not isinstance(per_rule, Mapping) or not isinstance(totals, Mapping):
        raise ValueError("render_table expects a report_dict payload")
    header = ("rule", "tp", "fp", "fn", "expected", "found", "precision", "recall")
    rows = [header]
    for rule_id, stats in per_rule.items():
        if not isinstance(stats, Mapping):
            raise ValueError(f"per_rule[{rule_id!r}] must be a mapping")
        rows.append(
            (
                str(rule_id),
                str(stats.get("tp", 0)),
                str(stats.get("fp", 0)),
                str(stats.get("fn", 0)),
                str(stats.get("expected", 0)),
                str(stats.get("found", 0)),
                _metric(stats.get("precision")),
                _metric(stats.get("recall")),
            )
        )
    rows.append(
        (
            "totals",
            str(totals.get("tp", 0)),
            str(totals.get("fp", 0)),
            str(totals.get("fn", 0)),
            str(totals.get("expected", 0)),
            str(totals.get("found", 0)),
            _metric(totals.get("precision")),
            _metric(totals.get("recall")),
        )
    )
    widths = [max(len(row[index]) for row in rows) for index in range(len(header))]
    return "\n".join(
        "  ".join(cell.ljust(widths[index]) for index, cell in enumerate(row)).rstrip() for row in rows
    )
