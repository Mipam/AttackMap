"""Typed error taxonomy for AttackMap (AR012, AC-012).

Every error carries a stable ``code`` (machine-readable, safe for GUIs and
logs), a ``detail`` message, and a ``remediation`` hint naming the next step
a human can take. Broad ``except Exception`` handlers may only remain where
they record a limitation or ``analyzer_error`` — failures are surfaced, never
swallowed.

Compatibility: subclasses also inherit the built-in exception their callers
already catch (``ValueError`` / ``PermissionError`` / ``RuntimeError``), so
existing handlers keep working while new code can catch the typed name.

This module must stay import-cycle-free: every layer may use it.
"""

from __future__ import annotations


class AttackMapError(Exception):
    """Base class for every typed AttackMap failure."""

    code: str = "attackmap_error"
    remediation: str = "Re-run with --verbose and inspect the run manifest."

    def __init__(self, detail: str, *, code: str | None = None,
                 remediation: str | None = None) -> None:
        self.detail = detail
        if code is not None:
            self.code = code
        if remediation is not None:
            self.remediation = remediation
        super().__init__(detail)


class AnalyzerLoadError(AttackMapError, ImportError):
    """A plugin entry point could not be imported or instantiated."""

    code = "analyzer_load"
    remediation = (
        "Check `attackmap analyzers install <name>` output and reinstall the "
        "plugin; the pinned commit must match plugins.lock."
    )


class AnalyzerRuntimeError(AttackMapError, RuntimeError):
    """An installed analyzer raised while running."""

    code = "analyzer_runtime"
    remediation = (
        "The analyzer's error is recorded under analyzer_errors with its "
        "exception type; rerun with --strict-analyzers to fail fast during "
        "plugin development."
    )


class UntrustedAnalyzerError(AttackMapError, PermissionError):
    """A non-official analyzer entry point was refused (AR006, AC-009).

    Secure by default: only official, lock-pinned plugins load. The message
    names the analyzer and the exact opt-in, so the remedy is on screen.
    """

    code = "untrusted_analyzer"
    remediation = (
        "Pass --allow-untrusted-analyzers (or set ATTACKMAP_ALLOW_UNTRUSTED_ANALYZERS=1) "
        "to load non-official analyzers."
    )

    def __init__(self, analyzer: str, reason: str) -> None:
        self.analyzer = analyzer
        self.reason = reason
        super().__init__(
            f"Analyzer '{analyzer}' refused: {reason}. {self.remediation}"
        )


class BudgetExpired(AttackMapError):
    """Raised inside a stage when the run's wall-clock deadline passed (AC-010).

    ``partial`` carries whatever the interrupted stage had already built (a
    per-file pass result, a merged scan, an index), so the stage boundary can
    publish a partial result with an explicit limitation instead of failing.
    """

    code = "budget_expired"
    remediation = (
        "Raise the ceiling with --time-budget-seconds or ATTACKMAP_TIME_BUDGET_SECONDS."
    )

    def __init__(self, stage: str, partial: object | None = None) -> None:
        self.stage = stage
        self.partial = partial
        super().__init__(f"time budget expired inside stage '{stage}'")


class UnsupportedInFleet(AttackMapError, RuntimeError):
    """A flag or mode cannot run inside a fleet worker subprocess."""

    code = "unsupported_in_fleet"
    remediation = (
        "Run the flag on a single-repository scan, or drop it from the fleet "
        "request; the fleet-incompatible flag list names it."
    )


class ArtifactIntegrityError(AttackMapError, ValueError):
    """A published generation failed validation (checksum, schema, pointer)."""

    code = "artifact_integrity"
    remediation = (
        "The generation directory is invalid; re-run the scan to produce a "
        "fresh generation and do not trust the corrupted one."
    )


class FleetAdmissionError(AttackMapError, ValueError):
    """A fleet request was rejected before any repository was scanned."""

    code = "fleet_admission"
    remediation = (
        "Fix the fleet request (paths, flags, memory policy) and resubmit; "
        "nothing was scanned, so no partial reports exist."
    )
