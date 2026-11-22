"""Target layer map and edge classification for AR031 slice 1 (AC-110).

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

Transition tolerance (AR029 is landing the subpackages continuously):

- Enforcement applies ONLY to modules whose path already sits inside a
  target subpackage on disk, so this guard is green today and tightens
  automatically as AR029 moves each package into place.
- Flat root modules are classified through ``FLAT_NAME_TO_LAYER`` so that
  imports from already-landed modules resolve against the target layering
  even before the imported module itself has moved.
- Packages that are not part of the target layout yet (``execution/``,
  ``policy/``, ``ui/``) and unclassified names are tolerated as edges but
  counted, never silent failures.
- Package ``__init__.py`` aggregators are exempt in this slice: they
  re-export across layers while AR029 moves modules (``model/__init__``
  still pulls ``extraction.ledger``). The scanner counts the skipped
  files so the gap stays visible for a later ratchet.
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
# inside one of these directories on disk today.
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

# Flat-name -> layer transition map (pre-AR029 root modules). Classification
# follows roadmap §2.3 groupings; entries consumed by already-landed modules
# are pinned by today's green state (e.g. ``analyzer_contracts`` -> sdk,
# ``index`` -> foundation, ``models`` -> model, ``taxonomy`` -> model).
FLAT_NAME_TO_LAYER: dict[str, str] = {
    # foundation: safe_fs, redact, srcpaths, artifact_manifest, artifact_publisher
    "safe_fs": "foundation",
    "redact": "foundation",
    "srcpaths": "foundation",
    "artifact_manifest": "foundation",
    "artifact_publisher": "foundation",
    # low-level repo access and error taxonomy every layer may use
    "index": "foundation",
    "gitref": "foundation",
    "errors": "foundation",
    "application_errors": "foundation",
    "diagnostics": "foundation",
    # model: observations, findings, paths, snapshot, evidence_bundle
    "models": "model",
    "evidence": "model",
    "taxonomy": "model",
    "asset_model": "model",
    "signal_provenance": "model",
    "anomalies": "model",
    "attack_taxonomy": "model",
    "cve": "model",
    "fingerprint": "model",
    # extraction: merge, analyzer_host, scanner, config_scanner, ecosystems
    "merge": "extraction",
    "analyzer_host": "extraction",
    "scanner": "extraction",
    "config_scanner": "extraction",
    "analyzers": "extraction",
    "analyzer_catalog": "extraction",
    "analyzer_profiles": "extraction",
    "analyzer_run_ledger": "extraction",
    "ecosystem_node_atproto": "extraction",
    "ecosystem_php": "extraction",
    "ecosystem_python": "extraction",
    "python_django_routes": "extraction",
    "python_route_binding": "extraction",
    "workflow_scanner": "extraction",
    "webhardening": "extraction",
    "config_datastores": "extraction",
    "secrets_history": "extraction",
    "lockfiles": "extraction",
    "popular_packages": "extraction",
    "crypto": "extraction",
    "authz": "extraction",
    "authz_js_handlers": "extraction",
    "route_auth_fusion": "extraction",
    "supply_chain": "extraction",
    # reasoning: rules/*, taint, contracts, exploitability, ranking & graphing
    "rules": "reasoning",
    "taint": "reasoning",
    "taint_flow": "reasoning",
    "taint_sinks": "reasoning",
    "taint_sources": "reasoning",
    "contracts": "reasoning",
    "exploitability": "reasoning",
    "graph": "reasoning",
    "topology": "reasoning",
    "threat_model": "reasoning",
    "control_model": "reasoning",
    "weaknesses": "reasoning",
    "detection_opportunities": "reasoning",
    "insights": "reasoning",
    "hunt_harness": "reasoning",
    "evaluation": "reasoning",
    "triage": "reasoning",
    "suggest": "reasoning",
    "security_overlay": "reasoning",
    "suppress": "reasoning",
    "suppression_actions": "reasoning",
    "finding_identity": "reasoning",
    "crossrepo": "reasoning",
    "recon_to_analysis": "reasoning",
    "analyzer": "reasoning",
    # orchestration: run_spec, pipeline, scheduler, fleet, portfolio
    "pipeline": "orchestration",
    "scan_service": "orchestration",
    "fleet": "orchestration",
    "fleet_admission": "orchestration",
    "fleet_architecture": "orchestration",
    "fleet_resource_identity": "orchestration",
    "incremental": "orchestration",
    "run_budget": "orchestration",
    "run_contract": "orchestration",
    "progress": "orchestration",
    "bench": "orchestration",
    "retention": "orchestration",
    "snapshot_transport": "orchestration",
    "plugins_lock": "orchestration",
    "comparison": "orchestration",
    # output band: report, sarif, diagrams, defensive_review, export
    "report": "output",
    "sarif": "output",
    "diagrams": "output",
    "defensive_review": "output",
    "md": "output",
    "diff": "output",
    "review_json": "output",
    "finding_presentation": "output",
    "diagnostics_export": "output",
    "sbom": "output",
    # ai band: providers, prompts, budget, citations, harness
    "ai_budget": "ai",
    "ai_http_audit": "ai",
    "citations": "ai",
    "context_pack": "ai",
    "llm_review": "ai",
    "provider_options": "ai",
    "review_eval": "ai",
    "review_prompts": "ai",
    # surfaces: cli, ui, library
    "cli": "surfaces",
    "desktop_actions": "surfaces",
    "desktop_ai": "surfaces",
    "desktop_capabilities": "surfaces",
    "desktop_fleet": "surfaces",
    "desktop_graph": "surfaces",
    "desktop_provider": "surfaces",
    "desktop_worker": "surfaces",
    # sdk: public plugin contract
    "analyzer_contracts": "sdk",
}


def layer_of_module(parts: list[str] | tuple[str, ...]) -> str | None:
    """Classify a dotted ``attackmap`` module path, or None if unknown.

    Physical location wins: a path inside a target subpackage carries that
    subpackage's layer regardless of any flat-map entry. Flat root modules
    resolve through the transition map. Non-target subpackages (ui/,
    execution/, policy/) and unknown names return None.
    """
    if not parts or parts[0] != PKG_NAME:
        return None
    if len(parts) == 1:
        return None  # the bare package itself; neutral
    sub = parts[1]
    if sub in TARGET_SUBPACKAGE_TO_LAYER:
        return TARGET_SUBPACKAGE_TO_LAYER[sub]
    if len(parts) == 2 and sub in FLAT_NAME_TO_LAYER:
        return FLAT_NAME_TO_LAYER[sub]
    return None


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
    init_files_skipped: int = 0  # __init__.py aggregators exempt in slice 1
    parse_errors: list[str] = field(default_factory=list)


def iter_enforced_modules(src_root: Path) -> Iterator[tuple[Path, str, str]]:
    """Yield (path, dotted module, layer) for modules in landed subpackages.

    Includes ``__init__.py`` aggregators so callers can count and exempt
    them; missing subpackages are simply not landed yet and yield nothing.
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
            stats.init_files_skipped += 1
            continue
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
