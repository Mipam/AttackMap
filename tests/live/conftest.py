"""Apply the `live` marker to every test collected beneath this tier.

Live tests require the local LM Studio endpoint (AGENTS.md: 127.0.0.1:1234,
model cyberstag-security-26b-a4b-v1) and are opt-in only (`-m live`); CI
never runs them (AR010). The tier starts empty — every existing root test
that mentions LM Studio turned out to be offline (mocked transport), so it
stayed in its functional tier.
"""

from __future__ import annotations

from pathlib import Path

import pytest


def pytest_collection_modifyitems(config, items):
    # conftest hooks fire session-wide; scope this marker to this tier's dir.
    here = Path(__file__).resolve().parent.as_posix()
    for item in items:
        if item.path.resolve().as_posix().startswith(here):
            item.add_marker(pytest.mark.live)
