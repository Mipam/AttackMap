"""Analyzer extraction-protocol version gate (AR082 / AC-403).

Pins, in one place:

(a) every built-in analyzer declares extraction protocol "2.0" — either
    explicitly via an attribute or implicitly through the SDK default
    (:func:`attackmap.sdk.analyzer_contracts.declared_extraction_protocol`);
(b) ``tools.check_analyzer_versions`` passes on the live registry and
    would FAIL on an analyzer that pins an older protocol version.

The v1 adapter itself is exercised only here (dedicated compatibility
suite): ``tests/contract/test_extraction_contract_v2.py``.
"""

from __future__ import annotations

import json

from attackmap.orchestration.analyzers import get_builtin_repository_analyzers
from attackmap.sdk.analyzer_contracts import (
    EXTRACTION_PROTOCOL_VERSION,
    check_extraction_compatibility,
    declared_extraction_protocol,
)
from tools.check_analyzer_versions import (
    EXPECTED_PROTOCOL_VERSION,
    collect_protocol_rows,
    find_offenders,
    main,
)


class _FakeV1Analyzer:
    """A plugin written against protocol 1.0: it pins the old version."""

    EXTRACTION_PROTOCOL_VERSION = "1.0"

    class metadata:
        name = "fake-v1-plugin"

    @property
    def name(self) -> str:
        return "fake-v1-plugin"

    def detect(self, root: str) -> bool:
        return True

    def analyze(self, root: str):  # pragma: no cover - never executed
        raise NotImplementedError


class _FakeV2Analyzer:
    """A current plugin: no explicit pin, inherits the SDK 2.0 default."""

    class metadata:
        name = "fake-v2-plugin"

    @property
    def name(self) -> str:
        return "fake-v2-plugin"

    def detect(self, root: str) -> bool:
        return True

    def analyze(self, root: str):  # pragma: no cover - never executed
        raise NotImplementedError


def test_builtin_analyzers_declare_protocol_2_0() -> None:
    """AC-403 (built-in half): every built-in analyzer declares "2.0"."""
    assert EXTRACTION_PROTOCOL_VERSION == "2.0"
    builtins = get_builtin_repository_analyzers()
    assert len(builtins) >= 4, "expected at least the 4 documented built-ins"
    names = [a.name for a in builtins]
    for expected in ("python-web", "javascript-web", "config", "default"):
        assert expected in names, f"documented built-in {expected} missing from {names}"
    for analyzer in builtins:
        assert declared_extraction_protocol(analyzer) == "2.0", analyzer.name
        report = check_extraction_compatibility(analyzer)
        assert report.compatible, report.issues
        assert report.protocol_version == "2.0", analyzer.name


def test_check_tool_passes_on_live_registry(capsys) -> None:
    rows = collect_protocol_rows()
    assert rows, "registry must enumerate at least the built-ins"
    assert find_offenders(rows) == []
    assert main([]) == 0
    out = capsys.readouterr().out
    assert "PASS: all" in out


def test_check_tool_fails_on_v1_pinning_analyzer(capsys) -> None:
    rows = collect_protocol_rows(analyzers=[_FakeV1Analyzer(), _FakeV2Analyzer()])
    offenders = find_offenders(rows)
    assert [row["name"] for row in offenders] == ["fake-v1-plugin"]
    assert offenders[0]["declared_protocol_version"] == "1.0"
    # The implicit 2.0 plugin is not an offender.
    v2_row = next(row for row in rows if row["name"] == "fake-v2-plugin")
    assert v2_row["declared_protocol_version"] == EXPECTED_PROTOCOL_VERSION

    assert main(["--json"]) == 0  # live registry still passes
    payload = json.loads(capsys.readouterr().out.rsplit("PASS:", 1)[0])
    assert payload["expected_protocol_version"] == "2.0"
    assert payload["offenders"] == []


def test_declared_extraction_protocol_resolution() -> None:
    # Explicit analyzer-level pin wins.
    assert declared_extraction_protocol(_FakeV1Analyzer()) == "1.0"
    # No pin anywhere -> SDK default.
    assert declared_extraction_protocol(_FakeV2Analyzer()) == "2.0"
    assert declared_extraction_protocol(object()) == EXTRACTION_PROTOCOL_VERSION
