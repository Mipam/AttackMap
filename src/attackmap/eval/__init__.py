"""Detection-quality evaluation (AR048): labelled-corpus comparison and metrics.

The public surface is :func:`attackmap.eval.rules.compare` and the
dataclasses around it — pure, deterministic, standard-library only. YAML
parsing and scan orchestration live with the callers (the ``attackmap eval``
surface and ``tools/eval_rules.py``) so this package adds no layer edges.
"""

from __future__ import annotations

from .rules import (
    CorpusCase,
    EvalReport,
    Expectation,
    LocatedFinding,
    RuleStats,
    compare,
    load_cases,
    render_table,
    report_dict,
)

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
