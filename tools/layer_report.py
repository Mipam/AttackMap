"""Report per-layer import-boundary violations (AR031 slice 2, AC-110).

Scans EVERY module that sits inside a target subpackage — including package
``__init__.py`` aggregators, enforced since slice 2 — and prints the current
illegal-edge count per source->target layer pair, plus the transition
counters (enforced init files, tolerated unclassified edges). Init-file
violations appear in the violation list like any other edge; a dedicated
counter keeps their share visible.

Usage:
    python -m tools.layer_report              # human-readable summary
    python -m tools.layer_report --json       # machine-readable, same data
    python -m tools.layer_report --record     # regenerate the ratchet baseline

``--record`` is shrink-only: it refuses to add a layer pair the recorded
baseline does not already have (``--force`` overrides, for a deliberate,
reviewed expansion). The gate is
``tests/architecture/test_layer_boundaries.py``; report modes always exit 0,
``--record`` exits non-zero only when it refuses.
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
DEFAULT_BASELINE = REPO_ROOT / "tests" / "architecture" / "layer_violations_baseline.json"
SCHEMA = 2
BASELINE_NOTE = (
    "AR031 slice 2 ratchet baseline: full per-layer enforcement incl. package "
    "__init__.py aggregators. Must stay empty; tools/layer_report --record "
    "shrinks only."
)


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
    init_violations = 0
    for v in violations:
        pair_counts[(v.source_layer, v.target_layer)] += 1
        by_source[v.source_layer] += 1
        if v.module.endswith(".__init__"):
            init_violations += 1

    return {
        "schema": SCHEMA,
        "violation_total": len(violations),
        "violations_by_layer_pair": {
            f"{source}->{target}": count
            for (source, target), count in sorted(pair_counts.items())
        },
        "violations_by_source_layer": dict(sorted(by_source.items())),
        "modules_enforced_by_layer": dict(sorted(stats.modules_by_layer.items())),
        "init_files_enforced": stats.init_files_enforced,
        "violations_in_init_files": init_violations,
        "tolerated_unclassified_edges": stats.tolerated_edges,
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
        f"init_files_enforced={report['init_files_enforced']}"
    )
    if report["violations_in_init_files"]:
        lines.append(f"violations in __init__ aggregators: {report['violations_in_init_files']}")
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


def record_baseline(report: dict, path: Path, *, force: bool = False) -> int:
    """Regenerate the ratchet baseline; shrink-only unless ``force``."""
    existing_pairs: set[tuple[str, str]] = set()
    if path.exists():
        old = json.loads(path.read_text(encoding="utf-8"))
        existing_pairs = {
            (v["source_layer"], v["target_layer"]) for v in old.get("violations", [])
        }
    current_pairs = {(v["source_layer"], v["target_layer"]) for v in report["violations"]}
    added = sorted(current_pairs - existing_pairs)
    if added and not force:
        print("refusing to record: new layer pair(s) beyond the baseline:", file=sys.stderr)
        for source, target in added:
            print(f"  {source}->{target}", file=sys.stderr)
        print(f"use --force to record a deliberate expansion of {path}", file=sys.stderr)
        return 2
    payload = {
        "schema": 1,
        "note": BASELINE_NOTE,
        "violation_total": report["violation_total"],
        "violations": report["violations"],
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    suffix = f" (forced; added {len(added)} new pair(s))" if added else ""
    print(f"recorded {report['violation_total']} violation(s) -> {path}{suffix}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", dest="as_json", action="store_true", help="emit JSON")
    parser.add_argument(
        "--src-root",
        type=Path,
        default=DEFAULT_SRC_ROOT,
        help="attackmap package root to scan (default: %(default)s)",
    )
    parser.add_argument(
        "--record",
        nargs="?",
        const=str(DEFAULT_BASELINE),
        default=None,
        metavar="PATH",
        help=f"write the ratchet baseline (default: {DEFAULT_BASELINE.name}); shrink-only",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="with --record: allow adding new layer pairs",
    )
    args = parser.parse_args(argv)
    report = build_report(args.src_root)
    if args.record is not None:
        return record_baseline(report, Path(args.record), force=args.force)
    if args.as_json:
        print(json.dumps(report, indent=2))
    else:
        print(render_human(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
