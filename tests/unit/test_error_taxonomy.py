"""Typed error taxonomy (AR012, AC-012).

Every typed error carries a stable ``code``, a ``detail`` message and a
``remediation`` hint; subclasses keep the built-in exception their existing
handlers catch, so adoption cannot break old callers.
"""

from __future__ import annotations

import pytest

from attackmap.analyzers import MissingAnalyzersError, UntrustedAnalyzerError
from attackmap.errors import (
    ArtifactIntegrityError,
    AttackMapError,
    BudgetExpired,
    FleetAdmissionError,
    UnsupportedInFleet,
)
from attackmap.scan_service import ScanRequestError

ALL_TYPED = [
    AttackMapError,
    ArtifactIntegrityError,
    BudgetExpired,
    FleetAdmissionError,
    MissingAnalyzersError,
    ScanRequestError,
    UntrustedAnalyzerError,
    UnsupportedInFleet,
]


@pytest.mark.parametrize("cls", ALL_TYPED)
def test_every_typed_error_has_code_and_remediation(cls):
    assert (cls.code and cls.code != "attackmap_error") or cls is AttackMapError
    assert cls.remediation


def test_base_defaults_and_overrides():
    err = AttackMapError("something broke")
    assert err.detail == "something broke"
    assert err.code == "attackmap_error"
    assert err.remediation
    custom = AttackMapError("broke", code="custom_code", remediation="Do X")
    assert custom.code == "custom_code"
    assert custom.remediation == "Do X"


def test_budget_expired_keeps_stage_and_partial():
    exc = BudgetExpired("scan_files", partial={"files": 3})
    assert exc.stage == "scan_files"
    assert exc.partial == {"files": 3}
    assert "scan_files" in str(exc)
    assert "time-budget-seconds" in exc.remediation


def test_untrusted_error_names_analyzer_flag_and_env():
    exc = UntrustedAnalyzerError("third-party-x", "not an official plugin")
    assert exc.analyzer == "third-party-x"
    assert "--allow-untrusted-analyzers" in str(exc)
    assert "ATTACKMAP_ALLOW_UNTRUSTED_ANALYZERS" in str(exc)
    assert isinstance(exc, PermissionError)


def test_builtin_compatibility_is_preserved():
    """Old handlers catching ValueError/RuntimeError keep working."""
    with pytest.raises(ValueError):
        raise ArtifactIntegrityError("checksum mismatch")
    with pytest.raises(ValueError):
        raise FleetAdmissionError("bad request")
    with pytest.raises(RuntimeError):
        raise UnsupportedInFleet("no fleet support")
    with pytest.raises(ValueError):
        raise MissingAnalyzersError(["go"])
    assert MissingAnalyzersError(["go"]).missing == ["go"]
    # ScanRequestError was always caught by its own name, not a builtin.
    with pytest.raises(ScanRequestError):
        raise ScanRequestError("no repos")


def test_all_subclass_the_taxonomy_base():
    for cls in ALL_TYPED:
        assert issubclass(cls, AttackMapError)
