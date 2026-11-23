"""Rebuild the derived index by walking published generations (AR061).

The generations under an output base are the only source: every row copied
here comes verbatim from a generation's manifest or section files — never
scored, normalised or invented. The same generation set always produces the
same :class:`~attackmap.orchestration.derived_index.rows.IndexRows`, so
``attackmap index rebuild`` after deleting ``index.sqlite`` recreates exactly
the same file (AC-302).

A generation that fails validation is listed in the ``generations`` table
with its error and contributes no rows; a fleet generation is a container and
is listed but never read — its child generations are walked and indexed like
any scan generation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from attackmap.foundation.artifact_publisher import validate_generation
from attackmap.foundation.safe_fs import ensure_output_dir, max_file_bytes
from attackmap.orchestration.derived_index.rows import (
    EvidenceRow,
    FindingRow,
    GenerationRow,
    IndexRows,
    RouteRow,
    RunRow,
    SuppressionRow,
)
from attackmap.orchestration.derived_index.sqlite import (
    INDEX_DIRNAME,
    INDEX_FILENAME,
    fingerprint_of,
    index_path,
    manifest_inventory,
    write_index,
)

__all__ = ["collect_rows", "rebuild_index"]

# The engine's per-file read cap: a hostile generation must not stall a
# rebuild either. Section files already passed validation, so this only
# guards concurrent shrink/replace races.
_FLEET_CONTAINER = "fleet container: child generations are indexed instead"


def _read_json(path: Path) -> Any:
    with path.open("rb") as handle:
        raw = handle.read(max_file_bytes() + 1)
    if len(raw) > max_file_bytes():
        raise ValueError(f"Section file exceeds size limit: {path.name}")
    return json.loads(raw)


def _strings(value: Any) -> tuple[str, ...] | None:
    """Verbatim copy of a published string list; None when not published."""
    if not isinstance(value, list):
        return None
    return tuple(item for item in value if isinstance(item, str))


def _optional_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _optional_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


# --- one generation -------------------------------------------------------------


def _finding_rows(run_id: str, idx: int, entry: Any, *, suppressed: bool,
                  findings_out: list[FindingRow] | None,
                  suppressions_out: list[SuppressionRow] | None,
                  evidence_out: list[EvidenceRow]) -> None:
    """Copy one finding (active or suppressed) and its evidence rows.

    Entries whose required identity fields are not strings are skipped: a row
    that cannot name its finding is noise, and skipping is deterministic.
    """
    if not isinstance(entry, dict):
        return
    finding_id = entry.get("id")
    title = entry.get("title")
    severity = entry.get("severity")
    if not (isinstance(finding_id, str) and isinstance(title, str) and isinstance(severity, str)):
        return
    confidence = entry.get("confidence")
    if not isinstance(confidence, str):
        confidence = "medium"
    taxonomy = entry.get("taxonomy")
    cwe = _strings(taxonomy.get("cwe")) if isinstance(taxonomy, dict) else None
    identity_scheme = _optional_str(entry.get("identity_scheme"))
    rule_id = _optional_str(entry.get("rule_id"))
    entity_id = _optional_str(entry.get("entity_id"))
    if suppressed:
        rule = entry.get("rule")
        reason = entry.get("reason")
        if not (isinstance(rule, str) and isinstance(reason, str)):
            return
        assert suppressions_out is not None
        suppressions_out.append(SuppressionRow(
            run_id=run_id, idx=idx, finding_id=finding_id, title=title,
            severity=severity, rule=rule, reason=reason,
            identity_scheme=identity_scheme, rule_id=rule_id,
            entity_id=entity_id, suppressed_by=_strings(entry.get("suppressed_by")),
        ))
    else:
        assert findings_out is not None
        findings_out.append(FindingRow(
            run_id=run_id, idx=idx, finding_id=finding_id, title=title,
            severity=severity, confidence=confidence,
            identity_scheme=identity_scheme, rule_id=rule_id, entity_id=entity_id,
            score=_optional_int(entry.get("score")),
            exploitability=_optional_int(entry.get("exploitability")),
            exploitability_tier=_optional_str(entry.get("exploitability_tier")),
            tags=_strings(entry.get("tags")), cwe=cwe,
        ))
    for line_idx, line in enumerate(entry.get("evidence") or []):
        if isinstance(line, str):
            evidence_out.append(EvidenceRow(
                run_id=run_id, finding_id=finding_id, suppressed=suppressed,
                kind="text", idx=line_idx, text=line,
            ))
    for loc_idx, location in enumerate(entry.get("locations") or []):
        if not isinstance(location, dict) or not isinstance(location.get("file"), str):
            continue
        evidence_out.append(EvidenceRow(
            run_id=run_id, finding_id=finding_id, suppressed=suppressed,
            kind="location", idx=loc_idx, file=location["file"],
            line=_optional_int(location.get("line")),
            fingerprint=_optional_str(location.get("fingerprint")),
        ))


def _scan_rows(run_id: str, folder: Path, manifest: dict,
               runs_out: list[RunRow], findings_out: list[FindingRow],
               suppressions_out: list[SuppressionRow], routes_out: list[RouteRow],
               evidence_out: list[EvidenceRow]) -> None:
    """Copy every row one valid scan generation publishes."""
    identity = manifest.get("run_identity")
    state = manifest.get("exit_state")
    if not isinstance(identity, dict) or not isinstance(state, dict):
        raise ValueError("Invalid artifact manifest identity")
    scan = _read_json(folder / "scan.json")
    if not isinstance(scan, dict):
        raise ValueError("Invalid section schema: scan.json")
    snapshot = identity.get("snapshot")
    runs_out.append(RunRow(
        run_id=run_id,
        repo_root=identity["repo_root"],
        repo_name=identity["repo_name"],
        engine_version=manifest["engine_version"],
        status=state["status"],
        exit_code=state["exit_code"],
        analyzer_identity=_optional_str(identity.get("analyzer_identity")),
        snapshot_id=_optional_str(snapshot.get("snapshot_id")) if isinstance(snapshot, dict) else None,
        snapshot_state=_optional_str(state.get("snapshot_state")),
        files_scanned=_optional_int(scan.get("files_scanned")),
    ))
    findings = _read_json(folder / "findings.json")
    if not isinstance(findings, list):
        raise ValueError("Invalid section schema: findings.json")
    for idx, entry in enumerate(findings):
        _finding_rows(run_id, idx, entry, suppressed=False, findings_out=findings_out,
                      suppressions_out=None, evidence_out=evidence_out)
    suppressed = _read_json(folder / "suppressed_findings.json")
    if not isinstance(suppressed, list):
        raise ValueError("Invalid section schema: suppressed_findings.json")
    for idx, entry in enumerate(suppressed):
        _finding_rows(run_id, idx, entry, suppressed=True, findings_out=None,
                      suppressions_out=suppressions_out, evidence_out=evidence_out)
    routes = scan.get("routes")
    if not isinstance(routes, list):
        routes = []
    for idx, entry in enumerate(routes):
        if not isinstance(entry, dict):
            continue
        method = entry.get("method")
        path = entry.get("path")
        file = entry.get("file")
        if not (isinstance(method, str) and isinstance(path, str) and isinstance(file, str)):
            continue
        routes_out.append(RouteRow(
            run_id=run_id, idx=idx, method=method, path=path, file=file,
            auth=_optional_str(entry.get("auth")),
            line=_optional_int(entry.get("line")),
            guards=_strings(entry.get("guards")),
        ))


# --- the walk -------------------------------------------------------------------


def collect_rows(base: str | Path) -> IndexRows:
    """Read every generation under *base* into canonically ordered rows."""
    base = Path(base)
    inventory = manifest_inventory(base)  # OSError when the base is unreadable
    fingerprint = fingerprint_of(inventory)
    generations: list[GenerationRow] = []
    runs: list[RunRow] = []
    findings: list[FindingRow] = []
    suppressions: list[SuppressionRow] = []
    routes: list[RouteRow] = []
    evidence: list[EvidenceRow] = []
    for relative, digest in inventory:
        folder = base.joinpath(*relative.split("/"))
        run_id = relative.split("/")[-1]
        parent = relative.split("/")[0] if "/" in relative else None
        try:
            manifest = validate_generation(folder)
        except (OSError, ValueError) as exc:
            generations.append(GenerationRow(
                run_id=run_id, path=relative, valid=False, indexed=False,
                parent_run_id=parent, manifest_sha256=digest, error=str(exc) or "invalid generation",
            ))
            continue
        profile = "fleet" if manifest.get("generation_profile") == "fleet" else "scan"
        generations.append(GenerationRow(
            run_id=run_id, path=relative, valid=True, indexed=profile == "scan",
            parent_run_id=parent, manifest_sha256=digest,
            created_at=_optional_str(manifest.get("created_at")),
            engine_version=_optional_str(manifest.get("engine_version")),
            profile=profile,
            error=None if profile == "scan" else _FLEET_CONTAINER,
        ))
        if profile != "scan":
            continue
        run_rows: list[RunRow] = []
        finding_rows: list[FindingRow] = []
        suppression_rows: list[SuppressionRow] = []
        route_rows: list[RouteRow] = []
        evidence_rows: list[EvidenceRow] = []
        try:
            _scan_rows(run_id, folder, manifest, run_rows, finding_rows,
                       suppression_rows, route_rows, evidence_rows)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            # Listed as valid (the manifest checked out) but unreadable now —
            # a concurrent cleanup race, not a reason to fail the rebuild.
            # The partial rows are dropped: indexed=False means "no rows".
            generations[-1] = GenerationRow(
                run_id=generations[-1].run_id, path=generations[-1].path,
                valid=True, indexed=False, parent_run_id=generations[-1].parent_run_id,
                manifest_sha256=generations[-1].manifest_sha256,
                created_at=generations[-1].created_at,
                engine_version=generations[-1].engine_version,
                profile=generations[-1].profile,
                error=str(exc) or "unreadable generation",
            )
            continue
        runs.extend(run_rows)
        findings.extend(finding_rows)
        suppressions.extend(suppression_rows)
        routes.extend(route_rows)
        evidence.extend(evidence_rows)
    return IndexRows.canonical(
        fingerprint=fingerprint,
        generations=generations,
        runs=runs,
        findings=findings,
        suppressions=suppressions,
        routes=routes,
        evidence=evidence,
    )


def rebuild_index(base: str | Path) -> tuple[IndexRows, Path]:
    """Rebuild ``index/index.sqlite`` under *base* from its generations.

    The existing index file (when present) is replaced, never opened for
    writing: a corrupt database cannot be repaired by appending to it.
    Returns the rows written and the path they were written to.
    """
    base = Path(base)
    rows = collect_rows(base)
    folder = ensure_output_dir(base / INDEX_DIRNAME, mark=True)
    target = folder / INDEX_FILENAME
    if target.is_symlink() or target.is_file():
        target.unlink()
    write_index(target, rows)
    return rows, index_path(base)
