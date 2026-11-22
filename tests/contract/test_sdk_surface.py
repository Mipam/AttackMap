"""SDK public-surface contract (AR032 / AC-111).

Pins ``attackmap.sdk.__all__`` and the ``attackmap.sdk.models`` re-export
list. Removing a name is a breaking change for every analyzer plugin, so it
fails here until the deliberate break is acknowledged by bumping
``tests/contract/data/sdk_surface_version.json`` — the snapshot in
``sdk_surface.json`` then refreshes to the new surface on the next run.
Additions are allowed and only warn.
"""

from __future__ import annotations

import json
import warnings
from pathlib import Path

import pytest

import attackmap.sdk
import attackmap.sdk.models as sdk_models

pytestmark = [pytest.mark.contract]

REL_DATA = Path("tests") / "contract" / "data"
SNAPSHOT_PATH = Path(__file__).resolve().parent / "data" / "sdk_surface.json"
VERSION_PATH = Path(__file__).resolve().parent / "data" / "sdk_surface_version.json"
SURFACE_KEYS = ("exported", "models")


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _current_surface() -> dict[str, list[str]]:
    return {
        "exported": sorted(attackmap.sdk.__all__),
        "models": sorted(sdk_models.__all__),
    }


def _refresh_snapshot(version: int, current: dict[str, list[str]], *, required: bool) -> None:
    payload = {"version": version, **current}
    try:
        SNAPSHOT_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError:
        message = (
            f"could not refresh {REL_DATA / 'sdk_surface.json'} to version {version}; "
            "update it manually to the current attackmap.sdk exports"
        )
        if required:
            pytest.fail(message)
        warnings.warn(message, stacklevel=1)


def test_sdk_surface_removals_require_version_bump() -> None:
    snapshot = _read_json(SNAPSHOT_PATH)
    marker = _read_json(VERSION_PATH)
    current = _current_surface()

    if marker["version"] != snapshot["version"]:
        # The bump is the explicit acknowledgment of a deliberate break; resync
        # the snapshot so the next drift is measured from the new surface.
        _refresh_snapshot(marker["version"], current, required=True)
        return

    removed: dict[str, list[str]] = {}
    added: dict[str, list[str]] = {}
    for key in SURFACE_KEYS:
        removed[key] = sorted(set(snapshot[key]) - set(current[key]))
        added[key] = sorted(set(current[key]) - set(snapshot[key]))

    if any(removed.values()):
        details = "; ".join(f"{key}: {', '.join(names)}" for key, names in removed.items() if names)
        pytest.fail(
            "attackmap.sdk surface removal detected (breaking change for analyzer "
            f"plugins): {details}. Removals are only allowed on a deliberate break: "
            f'bump "version" in {REL_DATA / "sdk_surface_version.json"} and the '
            f'snapshot in {REL_DATA / "sdk_surface.json"} refreshes on the next run.'
        )

    if any(added.values()):
        _refresh_snapshot(marker["version"], current, required=False)
    for key, names in added.items():
        if names:
            warnings.warn(
                f"attackmap.sdk {key} surface additions (allowed, no version bump required): "
                f"{', '.join(names)}",
                stacklevel=1,
            )


def test_sdk_surface_lists_are_unique_and_consistent() -> None:
    for label, names in (
        ("attackmap.sdk.__all__", attackmap.sdk.__all__),
        ("attackmap.sdk.models.__all__", sdk_models.__all__),
    ):
        duplicates = sorted({name for name in names if names.count(name) > 1})
        assert not duplicates, f"{label} declares duplicate exports: {duplicates}"
    # Everything sdk.models re-exports must stay reachable through attackmap.sdk.
    missing = sorted(set(sdk_models.__all__) - set(attackmap.sdk.__all__))
    assert not missing, f"sdk.models re-exports missing from attackmap.sdk.__all__: {missing}"
