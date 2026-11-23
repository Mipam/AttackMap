"""Run observability: metric accumulation and event-log summarization (AR083).

Leaf package by contract: nothing here imports from ``attackmap`` — stdlib
only — so any layer (extraction, orchestration, surfaces) may hold a
:class:`~attackmap.diagnostics.metrics.RunMetrics` or summarize an
``events.jsonl`` without touching the import-cycle set.
"""

from attackmap.diagnostics.metrics import RunMetrics, summarize_run_events

__all__ = [
    "RunMetrics",
    "summarize_run_events",
]
