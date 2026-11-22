"""Centralized merge behavior for analyzer outputs.

This module is the single source of truth for **how** analyzer-emitted
signals are combined into a single ScanResult. It is loaded by
`merge_analyzer_results` (whole-repo analyzers) and the test helper
`merge_analyzer_signals`.

The declarative field schema (:data:`MERGE_SCHEMA` / :class:`MergeRule`)
lives in :mod:`attackmap.model.merge_schema` (AR030: pure ``ScanResult``
data belongs to the model layer); this module re-exports it and owns the
merge behavior that applies it, plus ``merge_analyzer_results`` (AR030:
moved here from orchestration so extraction-side analyzers such as the
ecosystem analyzers can merge without an upward import).

## Merge rules

- **Deterministic ordering**: first-seen wins. The order signals appear
  in the merged result is the order they first appeared across the input
  results, walked in input order. We do not reorder. Analyzers run in
  ``(metadata.priority, name)`` order (#221), so on a duplicate key the
  lower-priority-number analyzer's signal wins.
- **Deduplication**: each list field has a stable key extracted from the
  signal itself (e.g. `(path, method, file)` for routes). Two signals
  that hash to the same key are treated as duplicates; only the first is
  kept.
- **`languages`**: union, then sorted alphabetically for stable display.
- **`files_scanned`**: summed across results.
- **`root`**: taken from the explicit `root` argument when supplied,
  otherwise from the first result.
"""

from __future__ import annotations

from collections.abc import Iterable
from copy import deepcopy
from pathlib import Path
from typing import Any

from attackmap.model.merge_schema import MERGE_SCHEMA, MergeRule
from attackmap.sdk.analyzer_contracts import AnalyzerResult


def merge_into(destination: Any, items: Iterable[Any], rule: MergeRule, seen: set) -> None:
    """Append `items` onto `destination.<rule.attr>` deduping against `seen`.

    `seen` is mutated to include the keys of items that were appended.
    Pre-populate `seen` with keys from the existing destination if you
    want to merge across multiple sources without rescanning the list.
    """
    target = getattr(destination, rule.attr)
    index: dict | None = None
    for item in items:
        k = rule.key(item)
        if k in seen:
            if rule.upgrade is not None:
                if index is None:
                    index = {rule.key(existing): existing for existing in target}
                existing = index.get(k)
                if existing is not None:
                    rule.upgrade(existing, item)
            continue
        seen.add(k)
        # The destination owns its signals: auth upgrades and downstream passes
        # must never mutate an analyzer's reusable result objects.
        owned = deepcopy(item)
        target.append(owned)
        if index is not None:
            index[k] = owned


def initial_seen(destination: Any, rule: MergeRule) -> set:
    """Compute the `seen` set for items already on `destination.<rule.attr>`.

    Used by callers that merge into a non-empty destination.
    """
    return {rule.key(item) for item in getattr(destination, rule.attr)}


def merge_analyzer_results(
    results: Iterable[AnalyzerResult],
    root: str | Path | None = None,
) -> AnalyzerResult:
    """Combine multiple whole-repo analyzer results into one.

    Field-by-field merge behavior is declared in :data:`MERGE_SCHEMA`
    and applied uniformly here. See the module docstring for the rules.
    """
    result_list = list(results)
    if not result_list:
        resolved_root = Path(root).resolve() if root is not None else Path(".").resolve()
        return AnalyzerResult(root=str(resolved_root))

    resolved_root = Path(root).resolve() if root is not None else Path(result_list[0].root).resolve()
    merged = AnalyzerResult(root=str(resolved_root))
    seen_by_attr: dict[str, set] = {rule.attr: set() for rule in MERGE_SCHEMA}

    for result in result_list:
        merged.files_scanned += result.files_scanned
        for language in result.languages:
            if language not in merged.languages:
                merged.languages.append(language)
        for limitation in result.limitations:
            if limitation not in merged.limitations:
                merged.limitations.append(limitation)
        for rule in MERGE_SCHEMA:
            merge_into(merged, getattr(result, rule.attr), rule, seen_by_attr[rule.attr])

    from attackmap.model.signal_provenance import merge_scan_provenance
    merge_scan_provenance(merged, result_list)
    _merge_resource_limits(merged, result_list)
    merged.languages.sort()
    return merged


def _merge_resource_limits(target: AnalyzerResult, results: Iterable[AnalyzerResult]) -> None:
    """Retain observed subsets; unknown legacy reporting never certifies zero."""
    values = list(results)
    events = {event.model_dump_json(): event for result in values for event in result.resource_limit_events}
    target.resource_limit_events = [events[key] for key in sorted(events)]
    target.resource_limit_scopes = sorted({scope for result in values for scope in result.resource_limit_scopes})
    statuses = [result.resource_limit_reporting for result in values]
    if statuses and all(status == "complete" for status in statuses) and target.resource_limit_scopes:
        target.resource_limit_reporting = "complete"
    elif target.resource_limit_scopes or target.resource_limit_events or any(status == "partial" for status in statuses):
        target.resource_limit_reporting = "partial"
    else:
        target.resource_limit_reporting = "unknown"


__all__ = [
    "MERGE_SCHEMA",
    "MergeRule",
    "initial_seen",
    "merge_analyzer_results",
    "merge_into",
]
