"""Target layer map and edge classification for AR031 slice 2 (AC-110).

Target layering (roadmap.md §2.1/§2.3), strict downward-only:

    surfaces > orchestration > reasoning > extraction > model > foundation

``sdk/`` is an import island: it may import only ``foundation`` and ``model``
(plus itself). Every other layer may import ``sdk`` — it is the promised
public plugin contract, so inbound edges to it are always legal.

``output/`` and ``ai/`` form a lateral presentation band at orchestration
height (rank 5). Band modules import downward (``foundation``, ``model``,
``extraction``, ``reasoning``) and sideways inside the band, but never
upward (``surfaces``). Conversely only ``orchestration`` and ``surfaces``
(rank >= 5) may import the band; lower layers may not.

Full enforcement (slice 2 — AR029 + AR030 are complete):

- EVERY module whose path sits inside a target subpackage on disk is
  enforced, including package ``__init__.py`` aggregators (the slice-1
  exemption is retired; the revealed aggregator edges were fixed at the
  same ratchet — ledger records moved down to ``model/ledger``, sdk
  contract names resolve lazily).
- Physical location is the single source of truth. Flat root names (the
  one-release AR029 shims: ``cli``, ``models``, ``analyzer_host``, ...)
  classify as None until the installer retargets them, and edges to
  unclassified targets are tolerated but counted, never silent failures.
"""

from __future__ import annotations

import ast
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

PKG_NAME = "attackmap"

# Strict stack, lowest to highest. Rank 1 may import rank 1; rank N may
# import any rank <= N (plus sdk, plus the output band when rank >= 5).
STRICT_LAYERS: tuple[str, ...] = (
    "foundation",
    "model",
    "extraction",
    "reasoning",
    "orchestration",
    "surfaces",
)
LAYER_RANK: dict[str, int] = {name: rank for rank, name in enumerate(STRICT_LAYERS, start=1)}

SDK_LAYER = "sdk"
SDK_ALLOWED = frozenset({"foundation", "model"})

OUTPUT_BAND = frozenset({"output", "ai"})
BAND_RANK = 5  # lateral to orchestration
BAND_ALLOWED = frozenset({"foundation", "model", "extraction", "reasoning"}) | OUTPUT_BAND

# Target subpackages (roadmap §2.3). A module is ENFORCED iff its path sits
# inside one of these directories on disk today. This map plus the strict
# matrix above are the single source of truth; the slice-1 flat transition
# map is retired (flat root shims classify as None until the installer
# retargets them).
TARGET_SUBPACKAGE_TO_LAYER: dict[str, str] = {
    "foundation": "foundation",
    "model": "model",
    "extraction": "extraction",
    "reasoning": "reasoning",
    "orchestration": "orchestration",
    "output": "output",
    "ai": "ai",
    "surfaces": "surfaces",
    "sdk": "sdk",
}

ALL_LAYERS = frozenset(TARGET_SUBPACKAGE_TO_LAYER.values())


def layer_of_module(parts: list[str] | tuple[str, ...]) -> str | None:
    """Classify a dotted ``attackmap`` module path, or None if unknown.

    Physical location is the only rule: a path inside a target subpackage
    carries that subpackage's layer. The bare package, non-target
    subpackages (ui/, execution/, policy/) and flat root names (the
    one-release AR029 shims) return None.
    """
    if not parts or parts[0] != PKG_NAME or len(parts) == 1:
        return None
    return TARGET_SUBPACKAGE_TO_LAYER.get(parts[1])


def is_edge_allowed(source_layer: str, target_layer: str | None) -> bool:
    """True when ``source_layer`` may import ``target_layer``.

    None targets are unclassified (transition tolerance) and allowed.
    """
    if target_layer is None:
        return True
    if source_layer == target_layer:
        return True
    if source_layer == SDK_LAYER:
        return target_layer in SDK_ALLOWED
    if source_layer in OUTPUT_BAND:
        return target_layer in BAND_ALLOWED
    source_rank = LAYER_RANK[source_layer]
    if target_layer == SDK_LAYER:
        return True
    if target_layer in OUTPUT_BAND:
        return source_rank >= BAND_RANK
    target_rank = LAYER_RANK.get(target_layer)
    if target_rank is None:
        return True  # unknown layer name: tolerate defensively
    return target_rank <= source_rank


def rule_text(source_layer: str) -> str:
    """Human-readable rule the source layer is held to (for failure output)."""
    order = " > ".join(reversed(STRICT_LAYERS))
    if source_layer == SDK_LAYER:
        return "sdk is an import island: foundation + model only"
    if source_layer in OUTPUT_BAND:
        return "output/ai band imports foundation/model/extraction/reasoning and within-band only"
    return f"strict stack is downward-only: {order}"


@dataclass(frozen=True)
class Violation:
    """One illegal import edge from an enforced module."""

    module: str  # dotted source module, e.g. attackmap.model.findings
    file_rel: str  # path relative to the scanned src root, posix
    lineno: int
    statement: str
    target: str  # dotted target module (best resolution)
    source_layer: str
    target_layer: str
    rule: str

    def describe(self) -> str:
        return (
            f"{self.file_rel}:{self.lineno}: {self.module} imports {self.target} "
            f"({self.source_layer} -> {self.target_layer}); violates: {self.rule}"
        )


@dataclass
class LayerScanStats:
    """Counters that keep transition tolerance visible."""

    modules_by_layer: Counter[str] = field(default_factory=Counter)
    tolerated_edges: int = 0  # edges to unclassified/non-target targets
    init_files_enforced: int = 0  # __init__.py aggregators enforced (slice 2)
    parse_errors: list[str] = field(default_factory=list)


def iter_enforced_modules(src_root: Path) -> Iterator[tuple[Path, str, str]]:
    """Yield (path, dotted module, layer) for modules in landed subpackages.

    Includes ``__init__.py`` aggregators — they are enforced like any other
    module since slice 2; missing subpackages are simply not landed yet and
    yield nothing.
    """
    for sub, layer in sorted(TARGET_SUBPACKAGE_TO_LAYER.items()):
        pkg_dir = src_root / sub
        if not pkg_dir.is_dir():
            continue
        for path in sorted(pkg_dir.rglob("*.py")):
            rel = path.relative_to(src_root)
            dotted = PKG_NAME + "." + ".".join(rel.with_suffix("").parts)
            yield path, dotted, layer


def _statement(node: ast.Import | ast.ImportFrom) -> str:
    if isinstance(node, ast.ImportFrom):
        dots = "." * node.level
        module = node.module or ""
        names = ", ".join(alias.name for alias in node.names)
        return f"from {dots}{module} import {names}"
    return "import " + ", ".join(alias.name for alias in node.names)


def _attackmap_targets(
    tree: ast.Module, module_parts: list[str]
) -> Iterator[tuple[int, str, list[str]]]:
    """Yield (lineno, statement, dotted target parts) per attackmap edge."""
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            stmt = _statement(node)
            if node.level == 0:
                if not node.module:
                    # `from attackmap import name`: each name may be a
                    # subpackage or a flat module (attributes of the package
                    # __init__ resolve to None and are tolerated).
                    for alias in node.names:
                        head = alias.name.split(".")[0]
                        yield node.lineno, stmt, [PKG_NAME, head]
                    continue
                anchor = node.module.split(".")
                if anchor[0] != PKG_NAME:
                    continue
                yield node.lineno, stmt, anchor
            else:
                anchor = list(module_parts[: len(module_parts) - node.level])
                if not anchor or anchor[0] != PKG_NAME:
                    continue
                if node.module:
                    yield node.lineno, stmt, anchor + node.module.split(".")
                else:
                    for alias in node.names:
                        head = alias.name.split(".")[0]
                        yield node.lineno, stmt, [*anchor, head]
        elif isinstance(node, ast.Import):
            for alias in node.names:
                parts = alias.name.split(".")
                if parts[0] != PKG_NAME:
                    continue
                yield node.lineno, _statement(node), parts


def collect_violations(
    src_root: Path,
) -> tuple[list[Violation], LayerScanStats]:
    """Scan every enforced module; return illegal edges plus scan counters."""
    violations: list[Violation] = []
    stats = LayerScanStats()
    for path, dotted, layer in iter_enforced_modules(src_root):
        if path.name == "__init__.py":
            stats.init_files_enforced += 1
        stats.modules_by_layer[layer] += 1
        try:
            tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
        except SyntaxError as exc:
            stats.parse_errors.append(f"{path.relative_to(src_root).as_posix()}: {exc}")
            continue
        for lineno, stmt, target_parts in _attackmap_targets(tree, dotted.split(".")):
            target_layer = layer_of_module(target_parts)
            if target_layer is None:
                stats.tolerated_edges += 1
                continue
            if is_edge_allowed(layer, target_layer):
                continue
            violations.append(
                Violation(
                    module=dotted,
                    file_rel=path.relative_to(src_root).as_posix(),
                    lineno=lineno,
                    statement=stmt,
                    target=".".join(target_parts),
                    source_layer=layer,
                    target_layer=target_layer,
                    rule=rule_text(layer),
                )
            )
    violations.sort(key=lambda v: (v.file_rel, v.lineno))
    return violations, stats
