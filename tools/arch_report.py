"""Architecture report for the attackmap package.

Parses imports via AST (relative and absolute) and reports, as JSON:

- ``cycles``      — import cycles, one per DFS back-edge, canonicalised to a
                    deterministic rotation so results are comparable across runs
                    and against ``cycle_allowlist.json``.
- ``fan_in``      — per-module count of distinct internal importers.
- ``fan_out``     — per-module count of distinct internal imports.
- ``broad_excepts`` — per-module count of ``except Exception`` / ``except BaseException``
                    handlers (AST-based counterpart of the AC-012 grep).
- ``longest_function`` — longest function body in source lines, plus the count
                    of functions over 80 lines.

Usage (see docs/architecture-roadmap-2026-11-21/criteria.md):

    python -m tools.arch_report --cycles --json
    python -m tools.arch_report --cycles --fan-in --broad-excepts --json
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from collections import defaultdict
from pathlib import Path

DEFAULT_ROOT = "src/attackmap"


def module_name_for(path: Path, root: Path, package: str) -> str:
    """Map a file under ``root`` to its dotted module name."""
    rel = path.relative_to(root)
    parts = list(rel.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    if not parts:
        return package
    return package + "." + ".".join(parts)


def internal_imports(tree: ast.AST, module: str, package: str, root: Path) -> set[str]:
    """Internal modules imported by ``module`` (relative imports resolved)."""
    rel_parts = [] if module == package else list(module.split(".")[1:])
    is_package = module == package or (bool(rel_parts) and (root / Path(*rel_parts)).is_dir())
    targets: set[str] = set()

    def resolve(level: int, base: str | None) -> str | None:
        if level == 0:
            return base
        # ``from .x import y`` resolves against the containing package: the
        # module itself when it is a package (__init__), else its parent.
        anchor_parts = list(rel_parts) if is_package else rel_parts[:-1]
        if level > 1:
            drop = level - 1
            if drop > len(anchor_parts):
                return None
            anchor_parts = anchor_parts[: len(anchor_parts) - drop]
        anchor = package if not anchor_parts else package + "." + ".".join(anchor_parts)
        if base:
            return anchor + "." + base
        return anchor

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == package or alias.name.startswith(package + "."):
                    targets.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            resolved = resolve(node.level, node.module)
            if resolved is None:
                continue
            if resolved == package or resolved.startswith(package + "."):
                # ``from . import name`` may import a submodule *or* a name
                # re-exported by ``__init__``; record both edges and let the
                # caller drop the ones that name no real module.
                targets.add(resolved)
                for alias in node.names:
                    candidate = resolved + "." + alias.name
                    if candidate.startswith(package + "."):
                        targets.add(candidate)
    targets.discard(module)
    return targets


def build_graph(root: Path, package: str) -> dict[str, set[str]]:
    modules = {
        module_name_for(path, root, package): path
        for path in sorted(root.rglob("*.py"))
    }
    graph: dict[str, set[str]] = {}
    for module, path in modules.items():
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError as exc:  # pragma: no cover - source tree is valid
            print(f"warning: cannot parse {path}: {exc}", file=sys.stderr)
            continue
        graph[module] = {
            target for target in internal_imports(tree, module, package, root)
            if target in modules
        }
    return graph


def find_cycles(graph: dict[str, set[str]]) -> list[list[str]]:
    """Enumerate import cycles deterministically, one per DFS back-edge.

    Deterministic DFS over sorted nodes/edges; every edge to a node on the
    current stack closes one cycle. Each cycle is canonicalised by rotating it
    to start (and end) at its lexicographically smallest module, so the output
    is stable across runs and comparable against ``cycle_allowlist.json``.
    """
    visited: set[str] = set()
    on_stack: set[str] = set()
    path: list[str] = []
    cycles: list[list[str]] = []
    position: dict[str, int] = {}

    def dfs(node: str) -> None:
        visited.add(node)
        on_stack.add(node)
        position[node] = len(path)
        path.append(node)
        for child in sorted(graph.get(node, ())):
            if child not in graph:
                continue
            if child not in visited:
                dfs(child)
            elif child in on_stack:
                cycle = [*path[position[child]:], child]
                body = cycle[:-1]
                pivot = body.index(min(body))
                canonical = body[pivot:] + body[:pivot]
                cycles.append([*canonical, canonical[0]])
        path.pop()
        del position[node]
        on_stack.discard(node)

    for node in sorted(graph):
        if node not in visited:
            dfs(node)

    unique: dict[tuple[str, ...], list[str]] = {}
    for cycle in cycles:
        unique[tuple(cycle)] = cycle
    return [list(k) for k in sorted(unique)]


def count_broad_excepts(path: Path) -> int:
    """Count ``except Exception`` / ``except BaseException`` handlers."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    count = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler) or node.type is None:
            continue
        name = node.type.id if isinstance(node.type, ast.Name) else (
            node.type.attr if isinstance(node.type, ast.Attribute) else None
        )
        if name in {"Exception", "BaseException"}:
            count += 1
    return count


def function_lengths(paths: list[Path]) -> tuple[int, str | None, int]:
    """Longest function span, its module, and the count over 80 lines."""
    longest = 0
    longest_module: str | None = None
    over80 = 0
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            span = (node.end_lineno or node.lineno) - node.lineno + 1
            if span > 80:
                over80 += 1
            if span > longest:
                longest = span
                longest_module = str(path)
    return longest, longest_module, over80


def collect(root: Path, package: str, cycles: bool, fan_in: bool, fan_out: bool,
            broad_excepts: bool, functions: bool) -> dict:
    graph = build_graph(root, package)
    paths = {module_name_for(p, root, package): p for p in sorted(root.rglob("*.py"))}
    report: dict = {"package": package, "modules": len(graph)}

    if cycles:
        report["cycles"] = find_cycles(graph)
    if fan_in or fan_out:
        importers: dict[str, set[str]] = defaultdict(set)
        for module, targets in graph.items():
            for target in targets:
                importers[target].add(module)
        if fan_in:
            report["fan_in"] = {m: len(v) for m, v in sorted(importers.items())}
        if fan_out:
            report["fan_out"] = {m: len(t) for m, t in sorted(graph.items())}
    if broad_excepts:
        report["broad_excepts"] = {
            m: count_broad_excepts(p) for m, p in sorted(paths.items())
        }
    if functions:
        longest, longest_module, over80 = function_lengths(list(paths.values()))
        report["longest_function"] = {
            "lines": longest,
            "file": longest_module,
            "over_80_lines": over80,
        }
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=DEFAULT_ROOT, help="package root directory")
    parser.add_argument("--package", default="attackmap", help="dotted package name")
    parser.add_argument("--cycles", action="store_true", help="report import cycles")
    parser.add_argument("--fan-in", action="store_true", help="report per-module fan-in")
    parser.add_argument("--fan-out", action="store_true", help="report per-module fan-out")
    parser.add_argument("--broad-excepts", action="store_true",
                        help="report except Exception counts per module")
    parser.add_argument("--functions", action="store_true",
                        help="report longest function and >80-line count")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="accepted for the documented commands; output is always JSON")
    args = parser.parse_args(argv)

    if not (args.cycles or args.fan_in or args.fan_out or args.broad_excepts
            or args.functions):
        args.cycles = args.fan_in = args.fan_out = True
        args.broad_excepts = args.functions = True

    report = collect(Path(args.root), args.package, args.cycles, args.fan_in,
                     args.fan_out, args.broad_excepts, args.functions)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
