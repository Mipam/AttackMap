"""Read-side of the derived index with a filesystem fallback (AR061).

:func:`load_rows` is the single entry point every new reader (``attackmap
index status``/``dump``, ``attackmap trends``) goes through. When the index
is missing, unreadable, corrupt, on another schema version, or stale, the
rows are read straight from the generations instead — with the reason
reported, never as a failure (AC-303). The fallback and the index carry the
same frozen row shapes (:mod:`.rows`), so both routes answer identically.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from attackmap.orchestration.derived_index.rebuild import collect_rows
from attackmap.orchestration.derived_index.rows import IndexRows
from attackmap.orchestration.derived_index.sqlite import open_fresh_index, read_index

__all__ = ["LoadedRows", "load_rows", "trends_payload"]


@dataclass(frozen=True)
class LoadedRows:
    """Rows for an output base and where they came from."""

    rows: IndexRows
    source: str  # "index" or "filesystem"
    reason: str | None  # UNUSABLE_REASONS entry when source == "filesystem"


def load_rows(base: str | Path) -> LoadedRows:
    """Rows for *base*, via the index when it can be trusted, else the generations.

    Never fails because of the index: every unusable state falls back to
    reading the generations (which may still raise OSError when the base
    itself is unreadable — that is not an index problem).
    """
    conn, reason = open_fresh_index(base)
    if conn is not None:
        try:
            rows = read_index(conn)
        except (sqlite3.Error, OSError, TypeError, ValueError):
            # Damage that only shows mid-read: the same staleness rule as a
            # corrupt file — answer from the generations.
            reason = "corrupt"
        else:
            return LoadedRows(rows=rows, source="index", reason=None)
        finally:
            conn.close()
    return LoadedRows(rows=collect_rows(base), source="filesystem", reason=reason)


def trends_payload(rows: IndexRows, *, source: str, reason: str | None) -> dict:
    """A deterministic cross-run summary over the loaded rows.

    Every consumer that diffs two payloads (AC-302) relies on this: counts
    over canonically ordered rows, ties broken by rule id, keys sorted at
    serialisation time by the caller.
    """
    by_severity = {"high": 0, "medium": 0, "low": 0}
    for finding in rows.findings:
        if finding.severity in by_severity:
            by_severity[finding.severity] += 1
    rule_counts: dict[str, int] = {}
    for finding in rows.findings:
        if finding.rule_id:
            rule_counts[finding.rule_id] = rule_counts.get(finding.rule_id, 0) + 1
    by_rule = [
        {"rule_id": rule_id, "count": rule_counts[rule_id]}
        for rule_id in sorted(rule_counts, key=lambda item: (-rule_counts[item], item))
    ]
    run_summaries = [
        {
            "run_id": run.run_id,
            "repo_name": run.repo_name,
            "status": run.status,
            "files_scanned": run.files_scanned,
            "findings": sum(1 for finding in rows.findings if finding.run_id == run.run_id),
            "suppressed": sum(1 for s in rows.suppressions if s.run_id == run.run_id),
            "routes": sum(1 for route in rows.routes if route.run_id == run.run_id),
        }
        for run in rows.runs
    ]
    return {
        "source": source,
        "index_reason": reason,
        "fingerprint": rows.fingerprint,
        "generations": {
            "total": len(rows.generations),
            "indexed": sum(1 for generation in rows.generations if generation.indexed),
            "failed": len(rows.not_indexed()),
        },
        "runs": run_summaries,
        "totals": {
            "runs": len(rows.runs),
            "findings": len(rows.findings),
            "by_severity": by_severity,
            "suppressed": len(rows.suppressions),
            "routes": len(rows.routes),
            "evidence": len(rows.evidence),
        },
        "by_rule": by_rule,
    }
