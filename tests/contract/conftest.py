"""Apply the `contract` marker to every test collected beneath this tier.

SDK, merge-schema and artifact-compatibility tests: the public surfaces that
external plugins rely on.
"""

from __future__ import annotations

from pathlib import Path

import pytest


def pytest_collection_modifyitems(config, items):
    # conftest hooks fire session-wide; scope this marker to this tier's dir.
    here = Path(__file__).resolve().parent.as_posix()
    for item in items:
        if item.path.resolve().as_posix().startswith(here):
            item.add_marker(pytest.mark.contract)
