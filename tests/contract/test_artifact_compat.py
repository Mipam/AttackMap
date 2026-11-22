"""Artifact compatibility gate (AR032 / AC-111).

Rebuilds the deterministic fixture generation (``artifact_fixture.write_generation``),
computes its stable semantic identity through ``tools.report_identity`` and
compares it against the recorded baseline in
``tests/contract/data/report_identity_baseline.json``. A semantic report or
manifest change fails with a normalized diff and a re-record pointer; volatile
changes (timestamps, run ids, generation dirs, temp paths) never move the hash.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.report_identity import (  # noqa: E402
    BASELINE_PATH,
    compute_fixture_identity,
    load_baseline,
    semantic_diff,
)

pytestmark = [pytest.mark.contract]

RECORD_COMMAND = "python -m tools.report_identity --record"


def test_report_identity_matches_recorded_baseline() -> None:
    if not BASELINE_PATH.is_file():
        pytest.fail(
            "No recorded report identity baseline. Run "
            f"`{RECORD_COMMAND}` and commit tests/contract/data/"
            "report_identity_baseline.json."
        )
    baseline = load_baseline()
    with tempfile.TemporaryDirectory(prefix="attackmap-identity-") as work:
        doc = compute_fixture_identity(Path(work))
    if doc["identity"] == baseline.get("identity"):
        return
    diff = semantic_diff(baseline, doc)
    pytest.fail(
        "Report semantic identity drifted from the recorded baseline "
        f"(recorded={baseline.get('identity')} current={doc['identity']}). "
        "Normalized diff of report + artifact manifest output follows; if the "
        f"change is intentional, re-record with `{RECORD_COMMAND}`:\n{diff}"
    )


def test_fixture_generation_passes_artifact_validation() -> None:
    from attackmap.foundation.safe_fs import validate_generation

    with tempfile.TemporaryDirectory(prefix="attackmap-compat-") as work:
        doc = compute_fixture_identity(Path(work))
        # Raises (and fails the test) if the fixture generation is no longer a
        # valid published artifact set.
        validate_generation(Path(doc["generation_dir"]))
