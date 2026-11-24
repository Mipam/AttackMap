"""Official-analyzer protocol version gate (AR082 / AC-403).

Every official analyzer — the built-ins core ships plus any installed
entry-point plugins — must declare extraction protocol "2.0". Analyzers
declare it either explicitly (an ``EXTRACTION_PROTOCOL_VERSION`` /
``extraction_protocol_version`` attribute on the analyzer or its metadata)
or implicitly by building against the 2.0 SDK (see
:func:`attackmap.sdk.analyzer_contracts.declared_extraction_protocol`).

Protocol-1.0 plugins still *run*: the v1 adapter in
:mod:`attackmap.extraction.adapters` lifts their ``ScanResult`` into the
v2 ``ExtractionResult`` container losslessly. This gate only tracks
adoption — it is what AC-403 verifies.

Discovery mirrors ``attackmap modules --json``: built-ins plus the
``attackmap.analyzers`` entry-point group, in run order, read-only.

Usage::

    python -m tools.check_analyzer_versions            # PASS/FAIL table
    python -m tools.check_analyzer_versions --json     # machine-readable
"""

from __future__ import annotations

import argparse
import json
import sys

EXPECTED_PROTOCOL_VERSION = "2.0"

# The registry/discovery import is intentionally inside the functions (and
# guarded in main) so this module stays importable for tests that inject a
# fake analyzer list without pulling in the whole engine.


def collect_protocol_rows(analyzers: list[object] | None = None) -> list[dict[str, object]]:
    """One row per official analyzer: name, declared version, compatibility.

    ``analyzers`` defaults to the live registry (built-ins + installed
    plugins, same discovery as ``attackmap modules --json``); tests inject
    a fixed list instead.
    """
    from attackmap.orchestration.analyzers import get_registered_analyzers
    from attackmap.sdk.analyzer_contracts import (
        check_extraction_compatibility,
        declared_extraction_protocol,
    )

    if analyzers is None:
        analyzers = get_registered_analyzers()
    rows: list[dict[str, object]] = []
    for analyzer in analyzers:
        report = check_extraction_compatibility(analyzer)
        rows.append(
            {
                "name": report.analyzer,
                "declared_protocol_version": declared_extraction_protocol(analyzer),
                "compatible": report.compatible,
                "issues": list(report.issues),
            }
        )
    return rows


def find_offenders(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    """Rows that violate AC-403: wrong declared version or incompatible."""
    offenders = []
    for row in rows:
        if row["declared_protocol_version"] != EXPECTED_PROTOCOL_VERSION or not row["compatible"]:
            offenders.append(row)
    return offenders


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Gate: every official analyzer declares extraction protocol 2.0 (AR082 / AC-403).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the per-analyzer table as JSON instead of the text table.",
    )
    args = parser.parse_args(argv)

    try:
        rows = collect_protocol_rows()
    except Exception as exc:  # discovery itself failed (e.g. refused plugin)
        print(f"FAIL: could not enumerate official analyzers: {type(exc).__name__}: {exc}")
        return 1

    offenders = find_offenders(rows)
    if args.json:
        print(
            json.dumps(
                {
                    "expected_protocol_version": EXPECTED_PROTOCOL_VERSION,
                    "analyzers": rows,
                    "offenders": offenders,
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        for row in rows:
            status = "ok" if row not in offenders else "OFFENDER"
            print(f"{row['name']}: declares {row['declared_protocol_version']} ({status})")
        if offenders:
            print("")
            for row in offenders:
                detail = f"; issues: {', '.join(row['issues'])}" if row["issues"] else ""
                print(
                    f"OFFENDER {row['name']}: declares "
                    f"{row['declared_protocol_version']}, expected "
                    f"{EXPECTED_PROTOCOL_VERSION}{detail}"
                )

    if offenders:
        print(
            f"\nFAIL: {len(offenders)} of {len(rows)} official analyzers do not "
            f"declare extraction protocol {EXPECTED_PROTOCOL_VERSION}."
        )
        return 1
    print(f"\nPASS: all {len(rows)} official analyzers declare extraction protocol {EXPECTED_PROTOCOL_VERSION}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
