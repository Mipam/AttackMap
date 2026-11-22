"""Suite-wide test configuration (AR008).

The tier subdirectories (unit/integration/contract/live) hold the moved test
modules; shared fixtures (`tests/fixtures`), helpers (`tests/helpers`) and
root-level support modules (`artifact_fixture`) stay here. Inserting the
tests root on sys.path keeps the historical top-level imports
(`from artifact_fixture import ...`, `from helpers... import ...`) working
from any tier.
"""

from __future__ import annotations

import sys
from pathlib import Path

TESTS_ROOT = Path(__file__).resolve().parent
if str(TESTS_ROOT) not in sys.path:
    sys.path.insert(0, str(TESTS_ROOT))
