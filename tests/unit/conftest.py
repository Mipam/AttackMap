"""Apply the `unit` marker to every test collected beneath this tier (AR008).

The markers are registered in pyproject.toml; AR010 selects them per CI leg.
Adding the marker here instead of editing 140 files keeps the move a pure
`git mv`.
"""

from __future__ import annotations

from pathlib import Path

import pytest


def pytest_collection_modifyitems(config, items):
    # conftest hooks fire session-wide; scope this marker to this tier's dir.
    here = Path(__file__).resolve().parent.as_posix()
    for item in items:
        if item.path.resolve().as_posix().startswith(here):
            item.add_marker(pytest.mark.unit)
