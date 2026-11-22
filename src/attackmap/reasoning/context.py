"""The narrow, read-only reasoning context rules evaluate against (AR040).

`ReasoningContext` is a snapshot of exactly the scan slices rules are allowed
to see — routes, external calls, datastores, auth/secret hints, taint chains,
code/web-hardening weaknesses, the supply-chain slices (vulnerabilities,
workflow issues, dependency supply-chain issues; widened for AR045), and the
file index metadata. It deliberately does NOT expose `ScanResult`: rules
cannot reach signals, anomalies, limitations, or the scan pipeline, and the
container is frozen so no rule can rebind what it was handed.

Observation records themselves are the stable `attackmap.model` models, shared
by reference and treated as immutable after merge (the whole pipeline already
reads them in place). Copying every record into a parallel frozen view would
duplicate the AR022 contract without making the guarantee stronger, so the
context's read-only commitment is: frozen container, tuple collections,
mapping proxies for lookups, and never any disk I/O inside the context.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from posixpath import basename
from types import MappingProxyType
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..model import (
    AuthHint,
    CodeWeakness,
    DatabaseHint,
    ExternalCall,
    Route,
    ScanResult,
    SecretHint,
    SupplyChainIssue,
    TaintChain,
    Vulnerability,
    WebHardeningIssue,
    WorkflowIssue,
)

__all__ = ["ReasoningContext"]


def _group_by_file(items: Iterable[Route | ExternalCall]) -> dict[str, tuple[Any, ...]]:
    """Group records by their ``file`` field, preserving scan order within a file."""
    grouped: dict[str, list[Any]] = {}
    for item in items:
        grouped.setdefault(item.file, []).append(item)
    return {file: tuple(records) for file, records in grouped.items()}


def _file_suffix(path: str) -> str:
    """Lower-cased ``.ext`` of a repo-relative path; empty when it has none."""
    name = basename(path)
    if "." not in name:
        return ""
    return "." + name.rsplit(".", 1)[1].lower()


class ReasoningContext(BaseModel):
    """Read-only view over the observations a rule may reason about.

    Build with :meth:`from_scan`; construct directly only in tests. ``None``
    ``scanned_files`` means the scan never enumerated coverage — suffix and
    file lookups then return nothing rather than implying an empty repo.
    """

    model_config = ConfigDict(frozen=True)

    root: str = ""
    routes: tuple[Route, ...] = ()
    external_calls: tuple[ExternalCall, ...] = ()
    databases: tuple[DatabaseHint, ...] = ()
    auth_hints: tuple[AuthHint, ...] = ()
    secret_hints: tuple[SecretHint, ...] = ()
    taint_chains: tuple[TaintChain, ...] = ()
    code_weaknesses: tuple[CodeWeakness, ...] = ()
    web_hardening_issues: tuple[WebHardeningIssue, ...] = ()
    # Supply-chain slices (AR045 widening): CVE advisories on the dependency
    # path and the CI-workflow / dependency supply-chain issue records the
    # supply-chain rule family consumes. Same read-only convention as every
    # other slice: frozen tuples of the shared model records.
    vulnerabilities: tuple[Vulnerability, ...] = ()
    workflow_issues: tuple[WorkflowIssue, ...] = ()
    supply_chain_issues: tuple[SupplyChainIssue, ...] = ()
    # File index metadata. None preserves ScanResult's "coverage not
    # enumerated" semantics; it is never substituted with a fabricated list.
    scanned_files: tuple[str, ...] | None = None
    files_scanned: int = 0
    # Optional pre-captured source text metadata, keyed by repo-relative path.
    # `from_scan` never populates it (ScanResult carries no source text and the
    # context does no I/O); a future wiring pass may pass captured text in.
    source_texts: Mapping[str, str] = Field(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        # Freeze the mutable dict and precompute the lookup indexes once.
        object.__setattr__(self, "source_texts", MappingProxyType(dict(self.source_texts)))
        object.__setattr__(self, "_routes_by_file", MappingProxyType(_group_by_file(self.routes)))
        object.__setattr__(self, "_calls_by_file", MappingProxyType(_group_by_file(self.external_calls)))
        buckets: dict[str, list[str]] = {}
        for path in self.scanned_files or ():
            buckets.setdefault(_file_suffix(path), []).append(path)
        object.__setattr__(
            self,
            "_files_by_suffix",
            MappingProxyType({suffix: tuple(sorted(paths)) for suffix, paths in buckets.items() if suffix}),
        )

    # --- construction ------------------------------------------------------

    @classmethod
    def from_scan(cls, scan: ScanResult) -> ReasoningContext:
        """Copy only the narrow rule-visible slices out of a scan result.

        Deliberately excluded: signals, service/edge/entrypoint/protocol/
        framework hints, authz candidates, crypto weaknesses, anomalies,
        limits, analyzer errors and snapshot identity. AR045 widened the
        slice for the supply-chain rule family with the dependency-risk
        records (`vulnerabilities`, `workflow_issues`,
        `supply_chain_issues`). Widen the slice explicitly when a rule
        family (AR041+) needs it; never hand rules the whole scan.
        """
        return cls(
            root=scan.root,
            routes=tuple(scan.routes),
            external_calls=tuple(scan.external_calls),
            databases=tuple(scan.databases),
            auth_hints=tuple(scan.auth_hints),
            secret_hints=tuple(scan.secret_hints),
            taint_chains=tuple(scan.taint_chains),
            code_weaknesses=tuple(scan.code_weaknesses),
            web_hardening_issues=tuple(scan.web_hardening_issues),
            vulnerabilities=tuple(scan.vulnerabilities),
            workflow_issues=tuple(scan.workflow_issues),
            supply_chain_issues=tuple(scan.supply_chain_issues),
            scanned_files=None if scan.scanned_files is None else tuple(scan.scanned_files),
            files_scanned=scan.files_scanned,
        )

    # --- helper lookups (all read-only, no I/O) ----------------------------

    @property
    def routes_by_file(self) -> Mapping[str, tuple[Route, ...]]:
        return self._routes_by_file  # type: ignore[attr-defined,no-any-return]

    @property
    def calls_by_file(self) -> Mapping[str, tuple[ExternalCall, ...]]:
        return self._calls_by_file  # type: ignore[attr-defined,no-any-return]

    def files_by_suffix(self, suffix: str) -> tuple[str, ...]:
        """Indexed file paths ending in ``suffix`` (leading dot optional,
        case-insensitive), in sorted order. Empty when coverage is unknown."""
        key = suffix if suffix.startswith(".") else f".{suffix}"
        return self._files_by_suffix.get(key.lower(), ())  # type: ignore[attr-defined,no-any-return]

    def source_text(self, path: str) -> str | None:
        """Stored text metadata for ``path``, or None. Reads memory only."""
        return self.source_texts.get(path)
