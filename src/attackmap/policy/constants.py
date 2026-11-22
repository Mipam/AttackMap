"""The policy constants themselves — see the package docstring (AR004)."""

from __future__ import annotations

#: Sort rank for severities, lower = more severe, for ``min``-style ordering.
#: Previously declared identically in ``cve.py``, ``diff.py`` and ``triage.py``.
SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}  # lower = more severe

#: Sort rank for severities, higher = more severe, for ``max``-style ordering.
#: Previously ``threat_model._SEVERITY_ORDER``; deliberately the inverse of
#: :data:`SEVERITY_RANK` because the two call sites sort in opposite
#: directions. Keep both explicit — silently sharing one map was the trap.
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}  # higher = more severe

#: Directory names never scanned by any pass. Canonical union of the former
#: ``srcpaths.SKIP_DIRS`` (the #215 shared set), ``supply_chain._SKIP_DIRS``,
#: ``suggest._SKIP_DIRS``, ``sbom._SKIP_DIRS``, ``authz._GRAPHQL_SKIP_DIRS``
#: and ``workflow_scanner._ACTION_SKIP_DIRS``. Union means every pass now
#: skips ``.attackmap``, ``.attackmap-gui``, ``.next``, ``.turbo``, ``out``,
#: ``.tox`` and ``vendor`` where it previously skipped only a subset, and the
#: suggestion pass no longer carries private extras (``.vscode``,
#: ``.mypy_cache``, ``.pytest_cache``) the other passes never knew about —
#: that divergence was the latent bug this constant retires.
SKIP_DIRS = frozenset(
    {
        "node_modules",
        ".git",
        ".attackmap",       # CLI cache / output dir
        ".attackmap-gui",   # the macOS GUI's report output dir
        ".venv",
        "venv",
        "__pycache__",
        "dist",
        "build",
        ".next",
        ".turbo",
        "out",
        "target",
        ".tox",
        "vendor",
        ".idea",
        ".vscode",
        ".mypy_cache",
        ".pytest_cache",
    }
)

#: Path segments marking low-quality evidence sources (tests, fixtures,
#: mocks, examples). Canonical union: ``context_pack``, ``evidence`` and
#: ``threat_model`` used the 5-segment shape while ``asset_model`` and
#: ``insights`` also treated ``/test_``-prefixed and ``_test.``-suffixed
#: files as low quality. The union makes the narrower three treat those
#: file shapes the same way — same latent divergence, same fix.
LOW_QUALITY_SEGMENTS = (
    "/tests/",
    "/__tests__/",
    "/fixtures/",
    "/mocks/",
    "/examples/",
    "/test_",
    "/_test.",
)

#: HTTP methods that change server state, for authz-reachability decisions.
#: Previously ``route_auth_fusion._MUTATING``.
MUTATING_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})

#: :data:`MUTATING_METHODS` plus ``ANY`` — webhook/CSRF surfaces declare a
#: method wildcard. Previously ``route_auth_fusion._WEBHOOK_MUTATING`` and
#: ``threat_model._CSRF_MUTATING_METHODS`` (identical values).
WEBHOOK_MUTATING_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE", "ANY"})
