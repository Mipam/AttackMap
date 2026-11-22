"""Per-layer import enforcement (AR031 slice 1, AC-110).

Every module that already sits inside a target subpackage (roadmap §2.3)
may import only allowed layers: strictly downward within the strict stack
``surfaces > orchestration > reasoning > extraction > model > foundation``,
the lateral ``output``/``ai`` band at orchestration height, and ``sdk``
which is an island importing foundation+model only.

Transition tolerance: modules still flat at the root are classified through
``tests/architecture/layer_map.py``; subpackages AR029 has not landed yet
are simply not enforced until they appear. The AST import-parsing approach
mirrors ``test_import_boundaries.py`` but is deliberately independent (that
file and its allowlist belong to the AR029 lease).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src" / "attackmap"

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(HERE))

from layer_map import (  # noqa: E402
    ALL_LAYERS,
    BAND_ALLOWED,
    FLAT_NAME_TO_LAYER,
    LAYER_RANK,
    OUTPUT_BAND,
    TARGET_SUBPACKAGE_TO_LAYER,
    Violation,
    collect_violations,
    is_edge_allowed,
    layer_of_module,
)

pytestmark = [pytest.mark.unit]


def test_layer_table_matches_target_layout() -> None:
    """The encoded layering matches roadmap §2.1/§2.3 exactly."""
    assert LAYER_RANK == {
        "foundation": 1,
        "model": 2,
        "extraction": 3,
        "reasoning": 4,
        "orchestration": 5,
        "surfaces": 6,
    }
    assert set(TARGET_SUBPACKAGE_TO_LAYER) == {
        "foundation",
        "model",
        "extraction",
        "reasoning",
        "orchestration",
        "output",
        "ai",
        "surfaces",
        "sdk",
    }
    # Every flat transition entry resolves to a real layer, and the flat map
    # covers the modules consumed by already-landed subpackages.
    assert set(FLAT_NAME_TO_LAYER.values()) <= ALL_LAYERS
    for flat in ("redact", "taxonomy", "analyzer_contracts", "index", "models", "safe_fs"):
        assert flat in FLAT_NAME_TO_LAYER, flat


def test_allowed_direction_matrix() -> None:
    """Downward + same-layer is legal; upward is not; band and sdk behave."""
    downward = [
        ("surfaces", "orchestration"),
        ("orchestration", "reasoning"),
        ("reasoning", "extraction"),
        ("extraction", "model"),
        ("model", "foundation"),
    ]
    for upper, lower in downward:
        assert is_edge_allowed(upper, lower), (upper, lower)
        assert not is_edge_allowed(lower, upper), (lower, upper)

    # The output/ai band sits at orchestration height: reachable from rank
    # >= 5, and it imports only downward plus within-band.
    for band_member in sorted(OUTPUT_BAND):
        assert is_edge_allowed(band_member, "foundation")
        assert is_edge_allowed(band_member, "model")
        assert is_edge_allowed(band_member, "extraction")
        assert is_edge_allowed(band_member, "reasoning")
        assert not is_edge_allowed(band_member, "surfaces")
        assert not is_edge_allowed("reasoning", band_member)
        assert not is_edge_allowed("extraction", band_member)
        for target in sorted(BAND_ALLOWED):
            assert is_edge_allowed(band_member, target)
    assert is_edge_allowed("orchestration", "output")
    assert is_edge_allowed("surfaces", "ai")

    # sdk is an island: foundation+model only; everyone may import sdk.
    assert is_edge_allowed("sdk", "foundation")
    assert is_edge_allowed("sdk", "model")
    assert not is_edge_allowed("sdk", "extraction")
    assert not is_edge_allowed("sdk", "reasoning")
    assert not is_edge_allowed("sdk", "output")
    assert not is_edge_allowed("sdk", "ai")
    assert not is_edge_allowed("sdk", "surfaces")
    # Strict-stack layers import the public contract freely; the lateral
    # band stays within its downward allowance and does not import sdk.
    for layer in sorted(LAYER_RANK):
        assert is_edge_allowed(layer, "sdk"), layer
    for band_member in sorted(OUTPUT_BAND):
        assert not is_edge_allowed(band_member, "sdk")

    # Same-layer is always legal; unclassified targets are transition-tolerated.
    for layer in sorted(ALL_LAYERS):
        assert is_edge_allowed(layer, layer)
        assert is_edge_allowed(layer, None)


def test_transition_tolerates_unlanded_packages() -> None:
    """Non-target subpackages and unknown names classify as None (tolerated)."""
    for parts in (
        ["attackmap"],
        ["attackmap", "ui", "server"],
        ["attackmap", "execution", "windows"],
        ["attackmap", "policy", "constants"],
        ["attackmap", "definitely_not_a_module"],
        ["os", "path"],
    ):
        assert layer_of_module(parts) is None, parts
    # Flat root modules resolve through the transition map...
    assert layer_of_module(["attackmap", "merge"]) == "extraction"
    assert layer_of_module(["attackmap", "report"]) == "output"
    # ...but physical location wins once a module has landed.
    assert layer_of_module(["attackmap", "model", "findings"]) == "model"


def test_landed_subpackages_have_no_upward_imports() -> None:
    """The real enforcement: every landed target-subpackage module is clean."""
    violations, stats = collect_violations(SRC_ROOT)
    assert not stats.parse_errors, stats.parse_errors
    assert stats.modules_by_layer, "no enforced modules found; src layout broken?"
    assert not violations, "\n" + "\n".join(v.describe() for v in violations)


def test_skips_init_aggregators_during_transition(tmp_path: Path) -> None:
    """Package __init__ re-export shims are exempt in slice 1 but counted."""
    src = tmp_path / "attackmap"
    (src / "model").mkdir(parents=True)
    (src / "surfaces").mkdir()
    (src / "model" / "__init__.py").write_text(
        "from ..surfaces import cli\n",  # upward edge hidden in an aggregator
        encoding="utf-8",
    )
    (src / "model" / "clean.py").write_text("", encoding="utf-8")
    violations, stats = collect_violations(src)
    assert not violations, [v.describe() for v in violations]
    assert stats.init_files_skipped == 1
    assert stats.modules_by_layer["model"] == 1


def test_deliberate_upward_import_fails_naming_module(tmp_path: Path) -> None:
    """Negative test (AC-110): one planted upward edge fails, naming it."""
    src = tmp_path / "attackmap"
    (src / "model").mkdir(parents=True)
    (src / "surfaces").mkdir()
    (src / "model" / "clean.py").write_text(
        "from ..foundation import safe_fs\n",
        encoding="utf-8",
    )
    (src / "model" / "leak.py").write_text(
        "from ..surfaces import cli\n",
        encoding="utf-8",
    )
    violations, stats = collect_violations(src)
    assert not stats.parse_errors
    assert stats.modules_by_layer["model"] == 2
    assert len(violations) == 1, [v.describe() for v in violations]
    violation: Violation = violations[0]
    assert violation.module == "attackmap.model.leak"
    assert violation.source_layer == "model"
    assert violation.target_layer == "surfaces"
    description = violation.describe()
    assert "leak.py" in description
    assert "model" in description and "surfaces" in description
