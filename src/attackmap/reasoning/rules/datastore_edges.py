"""Datastore/edge rules (AR042): the same-file and same-module co-location
edges the legacy cascade derives from `databases` / `external_calls`.

Legacy mapping (old cascade stays the active producer; REGISTRY is not yet
wired into the pipeline — AR046 does that). Each rule ports one decision
branch verbatim; the new snake_case ids are the stable, suppressible
identity (RuleMeta validates ``^[a-z][a-z0-9_]*$``), so none of them reuse
a legacy dashed id:

- ``same_file_datastore_edge``  ports ``threat_model._same_file_datastore``,
  the ``threat_model._surface_evidence`` datastore line, and the
  ``analyzer.identify_attack_surfaces`` context signal
  ``same-file datastore (ownership unknown): <kind>``. No legacy finding
  id: the cascade used the decision for attack-path narrative and surface
  context signals only.
- ``same_file_external_edge``   ports ``threat_model._same_file_external``,
  the ``_surface_evidence`` external-call line, and the analyzer context
  signal ``same-file outbound call (ownership unknown): <target>``.
- ``same_module_datastore_edge`` ports the ``_build_probable_chains``
  ``db_by_module`` branch (evidence ``database hint in same module: …``).
  The cascade consumes it only inside the legacy ``framework-sink-chain``
  finding, which is NOT ported here (see below).
- ``same_module_external_edge`` ports the ``elif external_by_module``
  branch (``external call in same module: …``), including the cascade's
  priority: a same-module datastore answers before an external call, so
  this rule stays quiet where ``same_module_datastore_edge`` fired.

Declared vs observed: a datastore hint or outbound call extracted from a
declarative config artifact (the same files the config scanner reads:
``extraction.config_scanner.should_scan_config_file``) is a *declaration*;
its findings carry the ``declared-only`` tag. Records extracted from code
carry ``observed``. Every finding also carries ``ownership-unknown`` —
same-file/same-module co-location is context, not proof the route reaches
the record (the cascade words it exactly that way).

Branches deliberately NOT ported (their inputs are excluded from
`ReasoningContext.from_scan`; widening the context is another task's lease):

- ``service-trust-chain`` / ``atproto-trust-chain`` findings need
  service/edge/protocol hints (excluded slices).
- ``framework-sink-chain`` needs framework controller/service hints.
- ``public-data-route`` / ``unauth-outbound-integration`` / the taint-backed
  ``public-webhook`` evaluate `AttackSurface` objects whose ``exposure``
  flips with handler/service-role hints from excluded families — a
  context-only rule cannot reproduce them exactly.
- The AM038 observed-activity ``public-webhook`` branch
  (``route_auth_fusion._webhook_exposure_findings``) reads handler source
  text for signature-verification markers; the context carries no source
  text (``from_scan`` never populates ``source_texts``) and rules do no I/O.
- The ``elsewhere in repo`` sink tier is not an edge: the cascade itself
  marks it un-chainable (``_sink_on_chain``) and it would fire for every
  route in any repo that has a datastore, so it stays context.
"""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import TYPE_CHECKING

from attackmap.extraction.config_scanner import should_scan_config_file
from attackmap.policy import LOW_QUALITY_SEGMENTS

from ...model import Finding, FindingLocation
from ..finding_format import _rule_rationale
from .base import RuleMeta, confidence_band
from .registry import REGISTRY

if TYPE_CHECKING:
    from collections.abc import Callable

    from ..context import ReasoningContext

__all__ = [
    "SameFileDatastoreEdgeRule",
    "SameFileExternalEdgeRule",
    "SameModuleDatastoreEdgeRule",
    "SameModuleExternalEdgeRule",
]

# Findings cite at most this many co-located records before the cascade's
# "+N more" summary line (the dominant evidence-cap pattern in the legacy
# cascade, e.g. hardcoded-secret).
_MAX_EVIDENCE_RECORDS = 10


def _is_low_quality_source(path: str) -> bool:
    """Mirror of the cascade's down-rank (``threat_model._is_low_quality_source``)."""
    normalized = path.replace("\\", "/").lower()
    return any(segment in f"/{normalized}/" for segment in LOW_QUALITY_SEGMENTS)


def _file_module_key(file_path: str) -> str:
    """Mirror of the cascade's module key (``threat_model._file_module_key``):
    the Omeka ``module/<name>`` segment when present, else the first path
    segment. The kernel must not import the cascade it is replacing."""
    normalized = file_path.replace("\\", "/")
    marker = "/module/"
    if marker in normalized:
        suffix = normalized.split(marker, 1)[1]
        parts = suffix.split("/")
        if parts and parts[0]:
            return f"module/{parts[0].lower()}"
    parts = normalized.split("/")
    if parts:
        return parts[0].lower()
    return normalized.lower()


def _runtime_route_files(ctx: ReasoningContext) -> list[str]:
    """Route files the cascade treats as runtime surface, in deterministic
    order: low-quality sources (tests/, fixtures/, examples/, …) are
    down-ranked exactly like ``threat_model._runtime_routes``."""
    files = {route.file for route in ctx.routes if not _is_low_quality_source(route.file)}
    return sorted(files)


def _first_route_label(ctx: ReasoningContext, file: str) -> str:
    """The cascade's surface label for the first runtime route in ``file``."""
    route = next(r for r in ctx.routes if r.file == file and not _is_low_quality_source(r.file))
    return f"{route.method} {route.path} in {route.file}"


def _observation_tag(file: str) -> str:
    """``declared-only`` for records extracted from declarative config
    artifacts, ``observed`` for records extracted from code."""
    return "declared-only" if should_scan_config_file(PurePosixPath(file)) else "observed"


def _build_edge_finding(
    meta: RuleMeta,
    *,
    mitigation: str,
    route_label: str,
    route_file: str,
    records: list[object],
    evidence_line: Callable[[object], str],
) -> Finding:
    """One finding per co-location group: the cascade's evidence lines
    verbatim, locations at the route file first and each record's own site,
    tags = meta tags + the declared/observed distinction."""
    evidence = [route_label]
    evidence.extend(evidence_line(record) for record in records[:_MAX_EVIDENCE_RECORDS])
    if len(records) > _MAX_EVIDENCE_RECORDS:
        evidence.append(f"+{len(records) - _MAX_EVIDENCE_RECORDS} more")

    locations: list[FindingLocation] = []
    seen: set[tuple[str, int | None]] = set()
    for file, line in [(route_file, None), *((r.file, r.line) for r in records)]:
        key = (file, line)
        if key in seen:
            continue
        seen.add(key)
        locations.append(FindingLocation(file=file, line=line))

    status = {_observation_tag(record.file) for record in records}
    # A co-location group here is one file per rule, so the status is
    # uniform; if a future rule mixes code and config records in one
    # group, "declared-only" must not overclaim — "observed" wins.
    status_tag = "observed" if "observed" in status else "declared-only"
    return Finding(
        title=meta.title,
        severity=meta.severity,
        rule_id=meta.id,
        confidence=confidence_band(meta.confidence),
        mitigation=mitigation,
        evidence=evidence,
        locations=locations,
        tags=[*meta.tags, status_tag],
        rationale=_rule_rationale(meta, evidence),
    )


class SameFileDatastoreEdgeRule:
    """A datastore hint observed in the same file as a runtime route.

    Ports ``_same_file_datastore`` + the cascade's same-file datastore
    evidence/context signals. Co-location is reported as context, never as
    proof the route reaches the datastore.
    """

    meta = RuleMeta(
        id="same_file_datastore_edge",
        title="Datastore co-located with a route in the same file",
        cwe="",
        severity="low",
        confidence=0.6,
        rationale=(
            "A datastore hint was observed in the same source file as a route "
            "(the cascade's `_same_file_datastore` decision). Co-location is "
            "context, not proof of reachability: route ownership of the "
            "datastore is unknown until a route-linked chain confirms it."
        ),
        tags=("data-risk", "weak-signal", "ownership-unknown"),
    )

    mitigation = (
        "Check whether the co-located route actually reads or writes this "
        "datastore, and enforce authorization and parameterized queries at "
        "the route boundary before any downstream query."
    )

    def evaluate(self, ctx: ReasoningContext) -> list[Finding]:
        findings: list[Finding] = []
        for file in _runtime_route_files(ctx):
            colocated = [hint for hint in ctx.databases if hint.file == file]
            if not colocated:
                continue
            findings.append(
                _build_edge_finding(
                    self.meta,
                    mitigation=self.mitigation,
                    route_label=_first_route_label(ctx, file),
                    route_file=file,
                    records=colocated,
                    evidence_line=lambda hint: f"data store in same file: {hint.kind} ({hint.file})",
                )
            )
        return findings


class SameFileExternalEdgeRule:
    """An outbound call observed in the same file as a runtime route.

    Ports ``_same_file_external`` + the cascade's same-file outbound-call
    evidence/context signals.
    """

    meta = RuleMeta(
        id="same_file_external_edge",
        title="Outbound call co-located with a route in the same file",
        cwe="",
        severity="low",
        confidence=0.6,
        rationale=(
            "An outbound external call was observed in the same source file "
            "as a route (the cascade's `_same_file_external` decision). "
            "Co-location is context, not proof the route steers the call."
        ),
        tags=("integration-risk", "weak-signal", "ownership-unknown"),
    )

    mitigation = (
        "Review whether route input can steer the co-located outbound call, "
        "and authenticate, sign, and allow-list the outbound target so a "
        "forged request cannot widen the blast radius."
    )

    def evaluate(self, ctx: ReasoningContext) -> list[Finding]:
        findings: list[Finding] = []
        for file in _runtime_route_files(ctx):
            colocated = list(ctx.calls_by_file.get(file, ()))
            if not colocated:
                continue
            findings.append(
                _build_edge_finding(
                    self.meta,
                    mitigation=self.mitigation,
                    route_label=_first_route_label(ctx, file),
                    route_file=file,
                    records=colocated,
                    evidence_line=lambda call: f"external call in same file: {call.target} ({call.file})",
                )
            )
        return findings


class SameModuleDatastoreEdgeRule:
    """A datastore hint in the same module as a runtime route (possibly a
    different file — the cross-file co-location grade).

    Ports the ``_build_probable_chains`` ``db_by_module`` branch and its
    verbatim evidence line. The cascade consumes this decision only inside
    the legacy ``framework-sink-chain`` finding, which stays unported (it
    needs excluded framework hints).
    """

    meta = RuleMeta(
        id="same_module_datastore_edge",
        title="Datastore hint in the same module as a route",
        cwe="",
        severity="low",
        confidence=0.45,
        rationale=(
            "A datastore hint shares the route's module key (the cascade's "
            "`db_by_module` branch). Package-level proximity is weaker than "
            "same-file co-location: many files can share a module, so "
            "route ownership stays unknown."
        ),
        tags=("data-risk", "weak-signal", "ownership-unknown"),
    )

    mitigation = (
        "Trace which module file actually connects to the datastore and "
        "confirm the route cannot reach it without authorization; keep "
        "credentials for the datastore out of module-shared config."
    )

    def evaluate(self, ctx: ReasoningContext) -> list[Finding]:
        findings: list[Finding] = []
        for file in _runtime_route_files(ctx):
            module_key = _file_module_key(file)
            # Cascade priority: the first datastore hint whose module key
            # matches answers for the module (`db_by_module` is first-wins
            # over scan.databases order).
            match = next((hint for hint in ctx.databases if _file_module_key(hint.file) == module_key), None)
            if match is None:
                continue
            findings.append(
                _build_edge_finding(
                    self.meta,
                    mitigation=self.mitigation,
                    route_label=_first_route_label(ctx, file),
                    route_file=file,
                    records=[match],
                    evidence_line=lambda hint: f"database hint in same module: {hint.kind} ({hint.file})",
                )
            )
        return findings


class SameModuleExternalEdgeRule:
    """An outbound call in the same module as a runtime route, consulted
    only when the module has no datastore (the cascade's ``elif`` order).

    Ports the ``_build_probable_chains`` ``external_by_module`` branch and
    its verbatim evidence line.
    """

    meta = RuleMeta(
        id="same_module_external_edge",
        title="Outbound call in the same module as a route",
        cwe="",
        severity="low",
        confidence=0.45,
        rationale=(
            "An outbound external call shares the route's module key and no "
            "datastore hint answered first (the cascade's `elif "
            "external_by_module` order). Package-level proximity keeps "
            "route ownership unknown."
        ),
        tags=("integration-risk", "weak-signal", "ownership-unknown"),
    )

    mitigation = (
        "Identify which module file issues the outbound call and verify its "
        "authentication and allow-listing; treat env-configured endpoints "
        "as untrusted until the route-to-call path is confirmed."
    )

    def evaluate(self, ctx: ReasoningContext) -> list[Finding]:
        findings: list[Finding] = []
        for file in _runtime_route_files(ctx):
            module_key = _file_module_key(file)
            has_module_datastore = any(_file_module_key(hint.file) == module_key for hint in ctx.databases)
            if has_module_datastore:
                continue  # cascade's elif: the datastore branch answers first
            match = next(
                (call for call in ctx.external_calls if _file_module_key(call.file) == module_key),
                None,
            )
            if match is None:
                continue
            findings.append(
                _build_edge_finding(
                    self.meta,
                    mitigation=self.mitigation,
                    route_label=_first_route_label(ctx, file),
                    route_file=file,
                    records=[match],
                    evidence_line=lambda call: f"external call in same module: {call.target} ({call.file})",
                )
            )
        return findings


REGISTRY.register(SameFileDatastoreEdgeRule())
REGISTRY.register(SameFileExternalEdgeRule())
REGISTRY.register(SameModuleDatastoreEdgeRule())
REGISTRY.register(SameModuleExternalEdgeRule())
