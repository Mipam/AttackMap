"""Architecture boundary guard (AR002, AC-005).

The import graph of ``src/attackmap`` may not gain a single new cycle. The
frozen allowlist in ``cycle_allowlist.json`` records every cycle present at
AR002 time; it may only shrink. A change that adds a cycle fails here, and a
change that fixes a cycle must delete its allowlist entry in the same commit,
so the file never drifts into a rubber stamp.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src" / "attackmap"
ALLOWLIST_PATH = Path(__file__).resolve().parent / "cycle_allowlist.json"

sys.path.insert(0, str(REPO_ROOT))

from tools.arch_report import build_graph, find_cycles  # noqa: E402


def _load_allowlist() -> tuple[list[list[str]], int]:
    data = json.loads(ALLOWLIST_PATH.read_text(encoding="utf-8"))
    return data["cycles"], data["schema"]


def _current_cycles() -> list[list[str]]:
    graph = build_graph(SRC_ROOT, "attackmap")
    return find_cycles(graph)


def test_allowlist_schema_is_known() -> None:
    data = json.loads(ALLOWLIST_PATH.read_text(encoding="utf-8"))
    assert data["schema"] == 1
    assert isinstance(data["cycles"], list)


def test_no_cycles_beyond_allowlist() -> None:
    """Any cycle not frozen in the allowlist fails the build (AC-005)."""
    allowlist, _ = _load_allowlist()
    current = _current_cycles()
    allowlist_set = {tuple(c) for c in allowlist}
    current_set = {tuple(c) for c in current}
    new_cycles = sorted(current_set - allowlist_set)
    assert not new_cycles, (
        "New import cycles detected; refactor instead of extending the "
        f"allowlist: {new_cycles}"
    )


def test_allowlist_has_no_stale_entries() -> None:
    """Fixed cycles must drop their allowlist entry in the same change."""
    allowlist, _ = _load_allowlist()
    current = _current_cycles()
    allowlist_set = {tuple(c) for c in allowlist}
    current_set = {tuple(c) for c in current}
    stale = sorted(allowlist_set - current_set)
    assert not stale, (
        "Allowlist entries no longer occur; delete them from "
        f"cycle_allowlist.json: {stale}"
    )


def test_allowlist_never_grows() -> None:
    """The allowlist length is capped at the AR002 freeze (49 entries)."""
    allowlist, _ = _load_allowlist()
    frozen_max = 49
    assert len(allowlist) <= frozen_max, (
        f"cycle allowlist grew to {len(allowlist)}; the freeze is {frozen_max}"
    )


def test_cycle_finder_detects_synthetic_cycle(tmp_path: Path) -> None:
    """Self-test: the analyser detects a planted cycle and clean code passes."""
    sys.path.insert(0, str(tmp_path))
    try:
        pkg = tmp_path / "cycpkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("", encoding="utf-8")
        (pkg / "a_mod.py").write_text("from . import b_mod\n", encoding="utf-8")
        (pkg / "b_mod.py").write_text("from . import a_mod\n", encoding="utf-8")
        (pkg / "solo.py").write_text("import json\n", encoding="utf-8")

        graph = build_graph(pkg, "cycpkg")
        cycles = find_cycles(graph)
        assert len(cycles) == 1, cycles
        cycle = cycles[0]
        assert cycle[0] == cycle[-1]
        assert set(cycle[:-1]) == {"cycpkg.a_mod", "cycpkg.b_mod"}

        (pkg / "b_mod.py").write_text("import json\n", encoding="utf-8")
        assert find_cycles(build_graph(pkg, "cycpkg")) == []
    finally:
        sys.path.remove(str(tmp_path))
