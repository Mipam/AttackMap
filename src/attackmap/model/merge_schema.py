"""The declarative merge schema for ``ScanResult`` list fields (AR030).

Pure data about the normalized ``ScanResult`` shape, so it lives in the
``model`` package (AR031 layer map targets and AR030 "move a constant into
foundation/model"): lower layers (extraction) and provenance code in
``model`` itself need the schema without reaching up into extraction
behavior. The merge *behavior* that consumes it stays in
:mod:`attackmap.extraction.merge`.

A new structured signal type is added in one place: append a row to
:data:`MERGE_SCHEMA` describing the field name and its dedup key. All
merge / dedup behavior follows automatically.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class MergeRule:
    """How one list field on `ScanResult` is merged across analyzer outputs.

    - `attr`: the attribute name on `ScanResult` (e.g. `"routes"`).
    - `key`: a callable that returns a hashable dedup key for one signal.
    """

    attr: str
    key: Callable[[Any], tuple]
    # Optional: called as `upgrade(existing, duplicate)` when a later signal
    # hashes to an existing key, to fold in information the first one lacked.
    upgrade: Callable[[Any, Any], None] | None = None

    def __post_init__(self) -> None:
        if not self.attr.isidentifier():
            raise ValueError(f"MergeRule.attr must be a valid identifier, got {self.attr!r}")


def _upgrade_route_auth(existing: Any, duplicate: Any) -> None:
    """Known route auth beats unknown (#256): first-seen still wins the route,
    but a later analyzer that resolved the guard fills it in."""
    if getattr(existing, "auth", "unknown") == "unknown" and getattr(duplicate, "auth", "unknown") != "unknown":
        existing.auth = duplicate.auth
        existing.guards = list(duplicate.guards)
        existing.guard_evidence = duplicate.guard_evidence


# The complete schema of list fields on `ScanResult` that get merged
# across analyzer outputs. Order is preserved in the merged result;
# duplicates (by key) are suppressed.
MERGE_SCHEMA: tuple[MergeRule, ...] = (
    MergeRule("routes", lambda item: (item.path, item.method, item.file), upgrade=_upgrade_route_auth),
    # Method is part of the identity (#146b): two verbs on the same target in one
    # file (GET + POST /items) are distinct calls, not duplicates — collapsing
    # them would drop a method before cross-repo contract linking runs.
    MergeRule("external_calls", lambda item: (item.target, item.method, item.file)),
    MergeRule("databases", lambda item: (item.kind, item.file)),
    MergeRule("auth_hints", lambda item: (item.hint, item.file)),
    MergeRule("service_hints", lambda item: (item.hint, item.file)),
    MergeRule("edge_hints", lambda item: (item.hint, item.file)),
    MergeRule("entrypoint_hints", lambda item: (item.hint, item.file)),
    MergeRule("protocol_hints", lambda item: (item.hint, item.file)),
    MergeRule("framework_hints", lambda item: (item.hint, item.file)),
    # Line is part of the identity: redacted names only keep a 4-char prefix
    # (#235), so two different `AKIA…` keys in one file must stay distinct.
    MergeRule("secret_hints", lambda item: (item.name, item.file, item.line)),
    MergeRule(
        "taint_chains",
        lambda item: (
            item.route_method,
            item.route_path,
            item.route_file,
            item.sink_kind,
            item.sink_file,
            item.sink_line,
        ),
    ),
    MergeRule(
        "dependencies",
        lambda item: (item.ecosystem, item.name, item.version, item.file, item.dev),
    ),
    MergeRule(
        "vulnerabilities",
        lambda item: (item.ecosystem, item.package_name, item.package_version, item.id),
    ),
    MergeRule(
        "authz_candidates",
        lambda item: (item.route_method, item.route_path, item.route_file, item.id_param),
    ),
    MergeRule(
        "crypto_weaknesses",
        lambda item: (item.kind, item.file, item.line),
    ),
    MergeRule(
        "web_hardening_issues",
        lambda item: (item.kind, item.file, item.line),
    ),
    MergeRule(
        "code_weaknesses",
        lambda item: (item.kind, item.file, item.line),
    ),
    MergeRule(
        "workflow_issues",
        lambda item: (item.kind, item.file, item.line, item.context),
    ),
    MergeRule(
        "supply_chain_issues",
        lambda item: (item.kind, item.file, item.line, item.package),
    ),
    MergeRule(
        "secret_history",
        lambda item: (item.kind, item.file, item.name, item.introduced_in),
    ),
    MergeRule(
        "anomalies",
        lambda item: (item.kind, item.route_method, item.route_path, item.route_file),
    ),
)


__all__ = ["MERGE_SCHEMA", "MergeRule"]
