"""Detection-quality harness (AR048): per-rule precision/recall over the
labelled reference corpus.

Runs a real ``analyze`` scan of every fixture repository named by the corpus
(through ``attackmap.surfaces.eval_cli.run_evaluation``), compares the
findings against the labelled expectations and prints the versioned report.
The command-line form of the same measurement is ``attackmap eval rules``.

Usage::

    python -m tools.eval_rules --corpus corpus/reference.yaml --json
    python -m tools.eval_rules --corpus corpus/reference.yaml --fail-under-recall hardcoded_secret_literals=1.0

Exit code is 0 for every completed measurement: a low-precision baseline is
still a successful measurement. ``--fail-under-recall RULE_ID=VALUE`` is an
optional recall gate (repeatable); a named rule falling below its gate, or
an unknown rule name, exits 1.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from attackmap.eval import render_table
from attackmap.surfaces.eval_cli import run_evaluation

REPO_ROOT = Path(__file__).resolve().parents[1]


def _parse_gates(items: list[str]) -> dict[str, float]:
    """``RULE_ID=0.0-1.0`` pairs; a malformed gate is a usage error."""
    gates: dict[str, float] = {}
    for item in items:
        rule_id, separator, raw = item.partition("=")
        if not separator or not rule_id.strip():
            raise SystemExit(f"--fail-under-recall expects RULE_ID=VALUE, got: {item!r}")
        try:
            value = float(raw)
        except ValueError:
            raise SystemExit(f"--fail-under-recall value must be a number, got: {item!r}") from None
        if not 0.0 <= value <= 1.0:
            raise SystemExit(f"--fail-under-recall value must be within [0, 1], got: {item!r}")
        gates[rule_id.strip()] = value
    return gates


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--corpus",
        type=Path,
        default=REPO_ROOT / "corpus" / "reference.yaml",
        help="Path to the labelled reference corpus (default: corpus/reference.yaml).",
    )
    parser.add_argument("--json", action="store_true", help="Emit the report as JSON (default: table).")
    parser.add_argument(
        "--fail-under-recall",
        action="append",
        default=[],
        metavar="RULE_ID=VALUE",
        help="Optional recall gate (repeatable): exit 1 when the rule's recall is below VALUE.",
    )
    args = parser.parse_args(argv)

    try:
        report = run_evaluation(args.corpus)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(render_table(report))

    gates = _parse_gates(args.fail_under_recall)
    per_rule = report["per_rule"]
    failed = []
    for rule_id, gate in gates.items():
        stats = per_rule.get(rule_id)
        recall = stats.get("recall") if isinstance(stats, dict) else None
        if recall is None:
            failed.append(f"{rule_id}: unmeasured (no expectations matched the gate)")
        elif recall < gate:
            failed.append(f"{rule_id}: recall {recall:.2f} < {gate:.2f}")
    if failed:
        print("recall gate failed:", file=sys.stderr)
        for line in failed:
            print(f"  {line}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
