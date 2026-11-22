"""Extraction contract v2 <-> protocol-1.0 adapters (AR060 / AC-301).

Plugins can adopt ``ExtractionResult`` (v2) before core does:

- ``to_extraction_result`` — lift a protocol-1.0 ``ScanResult`` into the v2
  discriminated-union container (v1 -> v2);
- ``merge_extraction_results`` — merge several v2 results deterministically,
  first-seen-wins on identical payloads;
- ``to_scan_result`` — lower a v2 result back to a protocol-1.0
  ``ScanResult`` (v2 -> v1), so v2-emitting plugins still feed the current
  core merge/reporting pipeline unchanged.

The adapters never rewrite payload objects: every observation wraps the
corresponding v1 hint verbatim, so a v1 -> v2 -> v1 round trip preserves
routes/external calls/databases/auth/secret/weakness/workflow/supply-chain/
vulnerability lists exactly.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel

from ..model import ScanResult
from ..model.observations import (
    DependencyObservation,
    EdgeObservation,
    EntrypointObservation,
    FrameworkObservation,
    ProtocolObservation,
    RouteObservation,
    SecretObservation,
    ServiceObservation,
    SupplyChainObservation,
    VulnerabilityObservation,
    WeaknessObservation,
    WorkflowObservation,
)

if TYPE_CHECKING:
    from ..sdk.contracts import ExtractionResult

__all__ = [
    "merge_extraction_results",
    "to_extraction_result",
    "to_scan_result",
]

# (ScanResult list field, v2 observation variant, payload attribute name) in
# the canonical ScanResult payload order. Both adapters derive their
# per-kind mappings from this one table so the pairing can never drift.
_OBSERVATION_FIELDS: tuple[tuple[str, type[BaseModel], str], ...] = (
    ("routes", RouteObservation, "route"),
    ("service_hints", ServiceObservation, "service"),
    ("edge_hints", EdgeObservation, "edge"),
    ("entrypoint_hints", EntrypointObservation, "entrypoint"),
    ("protocol_hints", ProtocolObservation, "protocol"),
    ("framework_hints", FrameworkObservation, "framework"),
    ("secret_hints", SecretObservation, "secret"),
    ("dependencies", DependencyObservation, "dependency"),
    ("vulnerabilities", VulnerabilityObservation, "vulnerability"),
    ("code_weaknesses", WeaknessObservation, "weakness"),
    ("workflow_issues", WorkflowObservation, "workflow"),
    ("supply_chain_issues", SupplyChainObservation, "supply_chain"),
)

_VARIANT_TO_V1_FIELD: dict[type[BaseModel], tuple[str, str]] = {
    variant: (field, payload) for field, variant, payload in _OBSERVATION_FIELDS
}

# v1 payload lists with no v2 observation kind yet — carried verbatim on
# ExtractionResult (see the model docstring) so the round trip is lossless.
_PASSTHROUGH_FIELDS: tuple[str, ...] = (
    "external_calls",
    "databases",
    "auth_hints",
    "taint_chains",
    "authz_candidates",
    "crypto_weaknesses",
    "web_hardening_issues",
    "anomalies",
    "secret_history",
)


def _extraction_result_cls() -> type[ExtractionResult]:
    """Resolve ``ExtractionResult`` lazily.

    Importing ``attackmap.sdk`` at module level would cycle (the sdk package
    re-exports these adapters); a call-time import keeps both import orders
    working. The edge remains visible to ``tools.arch_report`` but closes no
    cycle: ``sdk.contracts`` never imports back into this module.
    """
    from ..sdk.contracts import ExtractionResult

    return ExtractionResult


def to_extraction_result(result: ScanResult) -> ExtractionResult:
    """Adapt a protocol-1.0 ``ScanResult`` (v1) to an ``ExtractionResult`` (v2).

    Observation order follows the canonical ``ScanResult`` payload order and
    preserves each list's own order; the hint objects are wrapped verbatim.
    The result is tagged ``source_protocol_version="1.0"`` so consumers can
    tell adapted payloads from natively-v2 ones.
    """
    observations: list[BaseModel] = []
    for list_field, variant, payload_attr in _OBSERVATION_FIELDS:
        for item in getattr(result, list_field):
            observations.append(variant(**{payload_attr: item}))

    payload: dict[str, object] = {
        "root": result.root,
        "observations": observations,
        "languages": list(result.languages),
        "scanned_files": (
            list(result.scanned_files) if result.scanned_files is not None else None
        ),
        "files_scanned": result.files_scanned,
        "limitations": list(result.limitations),
        "analyzer_errors": list(result.analyzer_errors),
        "source_protocol_version": "1.0",
    }
    for field in _PASSTHROUGH_FIELDS:
        payload[field] = list(getattr(result, field))
    return _extraction_result_cls().model_validate(payload)


def to_scan_result(result: ExtractionResult) -> ScanResult:
    """Adapt an ``ExtractionResult`` (v2) back to a protocol-1.0 ``ScanResult``.

    Lossless for every payload list the v1 contract carries: the wrapped
    hint objects are unwrapped verbatim in their original order, and the
    passthrough lists are copied unchanged. ``signals`` is left empty —
    it is synthesized on demand via ``ScanResult.all_signals()`` — and
    run-infrastructure fields (resource limits, run ledger, snapshot
    identity) are not part of the v2 payload contract.
    """
    payload: dict[str, object] = {
        "root": result.root,
        "languages": list(result.languages),
        "scanned_files": (
            list(result.scanned_files) if result.scanned_files is not None else None
        ),
        "files_scanned": result.files_scanned,
        "limitations": list(result.limitations),
        "analyzer_errors": list(result.analyzer_errors),
    }
    for field in _PASSTHROUGH_FIELDS:
        payload[field] = list(getattr(result, field))

    buckets: dict[str, list[BaseModel]] = {field: [] for field, _, _ in _OBSERVATION_FIELDS}
    for obs in result.observations:
        mapping = _VARIANT_TO_V1_FIELD.get(type(obs))
        if mapping is None:
            raise TypeError(
                f"unrecognized observation variant {type(obs).__name__!r}; "
                "Observation is a closed union — construct it from the sdk exports"
            )
        field, payload_attr = mapping
        buckets[field].append(getattr(obs, payload_attr))
    payload.update(buckets)
    return ScanResult.model_validate(payload)


def _dedupe_json(items: list[BaseModel]) -> list[BaseModel]:
    """Order-preserving first-seen-wins dedupe on serialized payload identity."""
    seen: set[str] = set()
    unique: list[BaseModel] = []
    for item in items:
        key = item.model_dump_json()
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def _dedupe_str(items: list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        unique.append(item)
    return unique


def merge_extraction_results(*results: ExtractionResult) -> ExtractionResult:
    """Merge several v2 extraction results (e.g. per-analyzer payloads).

    Deterministic and order-preserving, in argument order:

    - observations and every payload list keep their order with duplicates
      (identical serialized payloads) dropped, first-seen-wins;
    - ``languages`` is the sorted union (mirrors core merge display rules);
    - ``limitations``/``analyzer_errors``/``scanned_files`` dedupe in order;
    - ``files_scanned`` is summed;
    - every input must share one ``root``;
    - ``source_protocol_version`` degrades to ``"1.0"`` when any input was
      adapted from v1.

    Key-level conflict resolution between *different* payloads for the same
    route/hint key stays in core's merge (``attackmap.merge``); this helper
    only drops exact duplicates so it never decides conflicts plugins did
    not ask it to.
    """
    if not results:
        raise ValueError("merge_extraction_results requires at least one result")
    roots = sorted({r.root for r in results})
    if len(roots) != 1:
        raise ValueError(f"cannot merge extraction results from different roots: {roots}")

    payload: dict[str, object] = {
        "root": roots[0],
        "observations": _dedupe_json(
            [obs for r in results for obs in r.observations],
        ),
        "languages": sorted({lang for r in results for lang in r.languages}),
        "files_scanned": sum(r.files_scanned for r in results),
        "source_protocol_version": (
            "1.0" if any(r.source_protocol_version == "1.0" for r in results) else "2.0"
        ),
    }

    scanned: list[str] = []
    for r in results:
        scanned.extend(r.scanned_files or [])
    # None means "coverage not enumerated"; only every-None stays None.
    payload["scanned_files"] = _dedupe_str(scanned) if any(
        r.scanned_files is not None for r in results
    ) else None

    payload["limitations"] = _dedupe_str([x for r in results for x in r.limitations])
    payload["analyzer_errors"] = _dedupe_json(
        [err for r in results for err in r.analyzer_errors],
    )
    for field in _PASSTHROUGH_FIELDS:
        payload[field] = _dedupe_json([item for r in results for item in getattr(r, field)])
    return _extraction_result_cls().model_validate(payload)
