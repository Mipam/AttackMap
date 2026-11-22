"""The architecture guard is pure and fast: mark it `unit` (AR008/AR010).

Without this, the architecture tests carry no tier marker and the fast CI
selection (`-m "unit or contract"`) would skip them.
"""

from __future__ import annotations

from pathlib import Path

import pytest


def pytest_collection_modifyitems(config, items):
    here = Path(__file__).resolve().parent.as_posix()
    for item in items:
        if item.path.resolve().as_posix().startswith(here):
            item.add_marker(pytest.mark.unit)
