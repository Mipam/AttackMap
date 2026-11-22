"""Report per-layer import-boundary violations (AR031 slice 1, AC-110).

Scans every module that already sits inside a target subpackage and prints
the current illegal-edge count per source->target layer pair, plus the
transition counters (tolerated edges, skipped __init__ aggregators) so the
violations can be ratcheted to zero as AR029 lands the restructure.

Usage:
    python -m tools.layer_report            # human-readable summary
    python -m tools.layer_report --json     # machine-readable, same data

Exit code is always 0: this is a ratchet report, not a gate. The gate is
``tests/architecture/test_layer_boundaries.py``.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
LAYER_MAP_PATH = REPO_ROOT / "tests" / "architecture" / "layer_map.py"
DEFAULT_SRC_ROOT = REPO_ROOT / "src" / "attackmap"
SCHEMA = 1


def load_layer_map():
    """Load tests/architecture/layer_map.py without a package structure."""
    spec = importlib.util.spec_from_file_location("arch_layer_map", LAYER_MAP_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load layer map from {LAYER_MAP_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def build_report(src_root: Path) -> dict:
    layer_map = load_layer_map()
    violations, stats = layer_map.collect_violations(src_root)

    pair_counts: Counter[tuple[str, str]] = Counter()
    by_source: Counter[str] = Counter()
    for v in violations:
        pair_counts[(v.source_layer, v.target_layer)] += 1
        by_source[v.source_layer] += 1

    return {
        "schema": SCHEMA,
        "violation_total": len(violations),
        "violations_by_layer_pair": {
            f"{source}->{target}": count
            for (source, target), count in sorted(pair_counts.items())
        },
        "violations_by_source_layer": dict(sorted(by_source.items())),
        "modules_enforced_by_layer": dict(sorted(stats.modules_by_layer.items())),
        "tolerated_unclassified_edges": stats.tolerated_edges,
        "init_files_skipped": stats.init_files_skipped,
        "parse_errors": sorted(stats.parse_errors),
        "violations": [
            {
                "file": v.file_rel,
                "line": v.lineno,
                "module": v.module,
                "statement": v.statement,
                "target": v.target,
                "source_layer": v.source_layer,
                "target_layer": v.target_layer,
                "rule": v.rule,
            }
            for v in violations
        ],
    }


def render_human(report: dict) -> str:
    lines: list[str] = []
    pairs = report["violations_by_layer_pair"]
    total = report["violation_total"]
    lines.append(f"layer_report: {total} violation(s)")
    if pairs:
        lines.append("")
        lines.append("violations by layer pair:")
        width = max(len(pair) for pair in pairs)
        for pair, count in pairs.items():
            lines.append(f"  {pair:<{width}}  {count}")
    enforced = report["modules_enforced_by_layer"]
    if enforced:
        lines.append("")
        lines.append("enforced modules by layer:")
        for layer, count in enforced.items():
            lines.append(f"  {layer:<14}  {count}")
    lines.append("")
    lines.append(
        "transition counters: "
        f"tolerated_unclassified_edges={report['tolerated_unclassified_edges']} "
        f"init_files_skipped={report['init_files_skipped']}"
    )
    if report["parse_errors"]:
        lines.append("")
        lines.append("parse errors:")
        lines.extend(f"  {error}" for error in report["parse_errors"])
    if report["violations"]:
        lines.append("")
        lines.append("violations:")
        layer_map = load_layer_map()
        lines.extend(
            f"  {layer_map.Violation(**entry).describe()}" for entry in report["violations"]
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", dest="as_json", action="store_true", help="emit JSON")
    parser.add_argument(
        "--src-root",
        type=Path,
        default=DEFAULT_SRC_ROOT,
        help="attackmap package root to scan (default: %(default)s)",
    )
    args = parser.parse_args(argv)
    report = build_report(args.src_root)
    if args.as_json:
        print(json.dumps(report, indent=2))
    else:
        print(render_human(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
