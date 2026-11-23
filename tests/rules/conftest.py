"""tests/rules configuration (AR047): the ``rule`` marker and the harness import.

``tests/rules`` is not a package (like the tier directories), so its test
modules import the sibling harness ``_harness`` by basename; putting this
directory on ``sys.path`` keeps that working whatever ``--import-mode`` says.

Tests under ``tests/rules`` stay in the ``unit`` tier through the module-level
``pytestmark = [pytest.mark.unit]`` each file declares.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

RULE_MARKER = "rule"

_RULES_DIR = Path(__file__).resolve().parent
if str(_RULES_DIR) not in sys.path:
    sys.path.insert(0, str(_RULES_DIR))


def pytest_configure(config: pytest.Config) -> None:
    """Register the ``rule`` marker.

    ``--strict-markers`` is on and the marker list in pyproject.toml is
    suite-wide; this marker only means something under ``tests/rules``, so it
    is declared here, next to the tests that use it. The AR047 coverage and
    mutation checks (``_harness.py``) read it to find each rule's tests.
    """
    config.addinivalue_line(
        "markers",
        f"{RULE_MARKER}(*rule_ids): focuses the test on the named registered rule id(s); "
        "the AR047 coverage and mutation checks in tests/rules read it",
    )
