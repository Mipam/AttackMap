"""Per-layer import enforcement (AR031 slice 2, AC-110).

Full enforcement: EVERY module that sits inside a target subpackage
(roadmap §2.3) — including package ``__init__.py`` aggregators — may import
only allowed layers: strictly downward within the strict stack
``surfaces > orchestration > reasoning > extraction > model > foundation``,
the lateral ``output``/``ai`` band at orchestration height, and ``sdk``
which is an island importing foundation+model only.

Transition tolerance: classification follows physical location only, so the
flat one-release AR029 root shims (``cli``, ``models``, ...) classify as
None and their edges are tolerated-counted until the installer retargets
them. The AST import-parsing approach mirrors ``test_import_boundaries.py``
but is deliberately independent (that file and its allowlist belong to the
AR029 lease).
"""

from __future__ import annotations

import json
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


def test_transition_tolerates_unlanded_names() -> None:
    """Non-target subpackages and flat root names classify as None (tolerated).

    Slice 2 retired the flat transition map: physical location is the only
    classification rule, so the one-release AR029 root shims stay
    unclassified until the installer retargets them.
    """
    for parts in (
        ["attackmap"],
        ["attackmap", "ui", "server"],
        ["attackmap", "execution", "windows"],
        ["attackmap", "policy", "constants"],
        ["attackmap", "definitely_not_a_module"],
        ["os", "path"],
        # Flat root shims: tolerated, counted, never classified.
        ["attackmap", "merge"],
        ["attackmap", "report"],
        ["attackmap", "cli"],
        ["attackmap", "models"],
        ["attackmap", "analyzer_host"],
    ):
        assert layer_of_module(parts) is None, parts
    # Physical location is the single source of truth once a module landed.
    assert layer_of_module(["attackmap", "model", "findings"]) == "model"
    assert layer_of_module(["attackmap", "model", "ledger"]) == "model"
    assert layer_of_module(["attackmap", "sdk", "fs"]) == "sdk"


BASELINE_NAME = "layer_violations_baseline.json"


def test_landed_subpackages_have_no_upward_imports() -> None:
    """The real enforcement: every landed target-subpackage module is clean.

    Ratchet semantics (AR031 slice 2): full enforcement including package
    ``__init__.py`` aggregators, and the recorded baseline is EMPTY — so
    every current violation fails. ``--record`` on tools/layer_report only
    ever shrinks the baseline (tighten-only).
    """
    violations, stats = collect_violations(SRC_ROOT)
    assert not stats.parse_errors, stats.parse_errors
    assert stats.modules_by_layer, "no enforced modules found; src layout broken?"
    # Prove the slice-2 ratchet is actually on: __init__ aggregators must be
    # inside the enforced set.
    assert stats.init_files_enforced > 0, "init aggregators not enforced?"
    baseline_path = HERE / BASELINE_NAME
    recorded = {
        (v["source_layer"], v["target_layer"])
        for v in json.loads(baseline_path.read_text(encoding="utf-8")).get("violations", [])
    } if baseline_path.exists() else set()
    current = {(v.source_layer, v.target_layer) for v in violations}
    new_pairs = current - recorded
    assert not new_pairs, (
        "Violations beyond the recorded AR031 baseline "
        f"({BASELINE_NAME}):\n" + "\n".join(
            v.describe() for v in violations if (v.source_layer, v.target_layer) in new_pairs
        )
    )


def test_init_aggregators_are_enforced(tmp_path: Path) -> None:
    """Slice 2: package __init__ re-export shims are held to the layering.

    The slice-1 exemption let an aggregator hide an upward edge; the same
    planted edge must now fail naming the __init__ module.
    """
    src = tmp_path / "attackmap"
    (src / "model").mkdir(parents=True)
    (src / "surfaces").mkdir()
    (src / "model" / "__init__.py").write_text(
        "from ..surfaces import cli\n",  # upward edge hidden in an aggregator
        encoding="utf-8",
    )
    (src / "model" / "clean.py").write_text("", encoding="utf-8")
    violations, stats = collect_violations(src)
    assert stats.init_files_enforced == 1
    assert stats.modules_by_layer["model"] == 2
    assert len(violations) == 1, [v.describe() for v in violations]
    violation: Violation = violations[0]
    assert violation.module == "attackmap.model.__init__"
    assert (violation.source_layer, violation.target_layer) == ("model", "surfaces")
    assert "__init__.py" in violation.describe()


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
