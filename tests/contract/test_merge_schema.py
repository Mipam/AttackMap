"""Merge-schema contract (AR032 / AC-111).

Pins the keys (``MergeRule.attr`` names) of ``attackmap.merge.MERGE_SCHEMA``
and proves the merge helpers accept a synthetic signal for every schema key
without raising, with dedup still holding. Any key change (add or remove) is
breaking for analyzer plugins and fails until it is acknowledged by bumping
``tests/contract/data/merge_schema_version.json`` *and* writing a migration
note there; the snapshot in ``merge_schema.json`` then refreshes.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from attackmap.extraction.merge import MERGE_SCHEMA, initial_seen, merge_into
from attackmap.model import ScanResult

pytestmark = [pytest.mark.contract]

REL_DATA = Path("tests") / "contract" / "data"
SNAPSHOT_PATH = Path(__file__).resolve().parent / "data" / "merge_schema.json"
VERSION_PATH = Path(__file__).resolve().parent / "data" / "merge_schema_version.json"


class _SyntheticSignal:
    """Placeholder analyzer signal: any attribute reads as a stable hashable value."""

    def __init__(self, tag: str) -> None:
        self._tag = tag

    def __getattr__(self, name: str):
        if name.startswith("__"):
            raise AttributeError(name)
        return (name, self._tag)

    def __deepcopy__(self, memo: dict) -> _SyntheticSignal:
        return _SyntheticSignal(self._tag)


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _current_attrs() -> list[str]:
    return sorted(rule.attr for rule in MERGE_SCHEMA)


def test_merge_schema_key_changes_require_migration_note() -> None:
    snapshot = _read_json(SNAPSHOT_PATH)
    marker = _read_json(VERSION_PATH)
    current = _current_attrs()
    removed = sorted(set(snapshot["attrs"]) - set(current))
    added = sorted(set(current) - set(snapshot["attrs"]))

    if not removed and not added:
        return

    changes = []
    if removed:
        changes.append(f"removed: {', '.join(removed)}")
    if added:
        changes.append(f"added: {', '.join(added)}")

    if marker["version"] == snapshot["version"]:
        pytest.fail(
            "MERGE_SCHEMA key change detected (breaking change for analyzer plugins): "
            f"{'; '.join(changes)}. Acknowledge it by bumping \"version\" in "
            f'{REL_DATA / "merge_schema_version.json"} and writing a migration note '
            'into "migration_note" there.'
        )

    note = str(marker.get("migration_note") or "").strip()
    if not note:
        pytest.fail(
            "MERGE_SCHEMA version bump without a migration note. A schema change "
            f"({'; '.join(changes)}) requires a migration note in "
            f'{REL_DATA / "merge_schema_version.json"} so downstream consumers know '
            "what moved."
        )

    # Acknowledged migration: resync the snapshot so future drift is measured
    # from the new schema.
    payload = {"version": marker["version"], "migration_note": note, "attrs": current}
    try:
        SNAPSHOT_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError:
        pytest.fail(
            f"could not refresh {REL_DATA / 'merge_schema.json'} to version "
            f"{marker['version']}; update it manually to the current MERGE_SCHEMA keys"
        )


def test_every_schema_key_merges_synthetic_signals() -> None:
    attrs = [rule.attr for rule in MERGE_SCHEMA]
    destination = SimpleNamespace(**{attr: [] for attr in attrs})
    for rule in MERGE_SCHEMA:
        seen = initial_seen(destination, rule)
        merge_into(
            destination,
            [_SyntheticSignal(f"{rule.attr}-a"), _SyntheticSignal(f"{rule.attr}-b")],
            rule,
            seen,
        )
        assert len(getattr(destination, rule.attr)) == 2, f"merge failed for {rule.attr}"
        # A repeat with an identical dedup key must be suppressed, not raise.
        merge_into(destination, [_SyntheticSignal(f"{rule.attr}-a")], rule, seen)
        assert len(getattr(destination, rule.attr)) == 2, f"dedup failed for {rule.attr}"


def test_schema_keys_map_to_scan_result_fields() -> None:
    unknown = sorted({rule.attr for rule in MERGE_SCHEMA} - set(ScanResult.model_fields))
    assert not unknown, f"MERGE_SCHEMA keys that are not ScanResult fields: {unknown}"
