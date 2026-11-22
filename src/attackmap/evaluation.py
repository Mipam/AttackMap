"""Deprecated import path (AR029): evaluation moved to attackmap.orchestration.evaluation.

Kept for one release so retained verification tooling (docs/verification
WP030 audit scripts) and any external callers can keep importing
``attackmap.evaluation``.
"""

from attackmap.orchestration.evaluation import (  # noqa: F401
    load_corpus,
    report_json,
    run_evaluation,
    split_corpus,
)

__all__ = ["load_corpus", "report_json", "run_evaluation", "split_corpus"]
