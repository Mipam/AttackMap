"""Versioned artifact manifest and section files for AttackMap scan output.

A pure serializer: every filename constant, artifact-recognition primitive and
generation validator lives in :mod:`attackmap.safe_fs` so walkers and the
publisher can share them without importing this module back.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from attackmap.foundation.safe_fs import (
    _MARKDOWN_EXPORTS,
    _OPTIONAL_EXPORTS,
    ARTIFACT_TYPE,
    MANIFEST_FILENAME,
    PINS_FILENAME,
    SCHEMA_VERSION,
    SECTION_ORDER,
    _artifact_json,
    ensure_output_dir,
    generated_artifact_names,
    max_file_bytes,
    safe_write_text,
)

__all__ = [
    "ARTIFACT_TYPE",
    "MANIFEST_FILENAME",
    "PINS_FILENAME",
    "SCHEMA_VERSION",
    "SECTION_ORDER",
    "ArtifactManifest",
    "ArtifactSection",
    "generated_artifact_names",
    "load_artifact_manifest",
    "make_run_id",
    "write_artifact_manifest",
]


@dataclass(frozen=True)
class ArtifactSection:
    name: str
    path: str
    format: str
    role: str
    checksum: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "name": self.name,
            "path": self.path,
            "format": self.format,
            "role": self.role,
        }
        if self.checksum is not None:
            data["checksum"] = self.checksum
        return data


@dataclass(frozen=True)
class ArtifactManifest:
    schema_version: str
    artifact_type: str
    generation_id: str
    engine_version: str
    created_at: str
    exit_state: dict[str, Any]
    run_identity: dict[str, Any]
    sections: list[ArtifactSection]
    compatibility_exports: list[ArtifactSection]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "artifact_type": self.artifact_type,
            "generation_id": self.generation_id,
            "engine_version": self.engine_version,
            "created_at": self.created_at,
            "exit_state": self.exit_state,
            "run_identity": self.run_identity,
            "sections": [s.to_dict() for s in self.sections],
            "compatibility_exports": [s.to_dict() for s in self.compatibility_exports],
        }


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _analyzer_identity(analyzer_metadata: list[dict[str, Any]]) -> str:
    """Content identity of the analyzer set + versions one run used (C33/AM047).

    Name/version only: cosmetic metadata changes must not fork run identity.
    """
    entries = sorted(
        ({"name": str(item.get("name", "")), "version": str(item.get("version", ""))}
         for item in analyzer_metadata),
        key=lambda entry: (entry["name"], entry["version"]),
    )
    payload = json.dumps(entries, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _captured_sources(
    out: Path, snapshot_id: str, raw_files: dict[str, str]
) -> list[dict[str, str]]:
    """Bind excerpt sources only when their raw hashes match the snapshot.

    Spans are content-addressed and immutable (they never re-read the live
    file). A normalized text hash cannot establish original-byte identity;
    missing raw hashes and mismatches remain explicitly unbound (C33/AM047).
    """
    sources: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for filename in ("vulnerability-hypotheses.meta.json", "defensive-review-llm.meta.json"):
        data = _artifact_json(out / filename, min(max_file_bytes(), 2_000_000))
        context = data.get("citation_context") if isinstance(data, dict) else None
        entries = context.get("sources") if isinstance(context, dict) else None
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            path, sha = entry.get("path"), entry.get("source_sha256")
            if not isinstance(path, str) or not isinstance(sha, str) or (path, sha) in seen:
                continue
            seen.add((path, sha))
            source = {"path": path, "source_sha256": sha}
            if raw_files.get(path) == sha:
                source["captured_under_snapshot_id"] = snapshot_id
            sources.append(source)
    return sources


def _snapshot_publication_block(
    report_data: dict[str, Any], repo_root: str, out: Path
) -> dict[str, Any] | None:
    """Verify the analyzed snapshot against the working tree at publication.

    The scan section carries the index-time snapshot identity (C33/AM047);
    this is the publication gate. Any file that changed, disappeared or
    appeared since the index marks the run incomplete — with an explicit
    limitation listing the paths — instead of silently publishing evidence
    from two revisions. Files under the output directory are excluded: the
    run writes its own reports there. Bounded policy: no retry loop; the
    operator re-runs for a consistent report.
    """
    scan_section = report_data.get("scan")
    raw = scan_section.get("scan_snapshot") if isinstance(scan_section, dict) else None
    if not isinstance(raw, dict) or not isinstance(raw.get("files"), dict):
        return None
    from attackmap.foundation.snapshot import ScanSnapshot

    snapshot = ScanSnapshot.from_identity(raw)
    verification = snapshot.verify(repo_root, exclude=(out,))
    block: dict[str, Any] = {
        "snapshot_id": snapshot.snapshot_id,
        "file_count": len(snapshot.files),
        "total_size": snapshot.total_size,
        "config_identity": snapshot.config_identity,
        "index_config": dict(snapshot.index_config),
        "verification": {
            **verification.to_dict(),
            "basis": "sha256 of utf-8 text under index acceptance rules",
            "excluded_paths": [str(out)],
        },
    }
    limitation = verification.limitation()
    if limitation is not None:
        block["incomplete"] = True
        block["limitation"] = limitation
    captured = _captured_sources(out, snapshot.snapshot_id, dict(snapshot.raw_files))
    if captured:
        block["sources_captured"] = captured
        unbound = sorted({source["path"] for source in captured
                          if "captured_under_snapshot_id" not in source})
        block["source_capture_verification"] = {
            "state": "unverified" if unbound else "verified",
            "unbound_paths": unbound,
            "basis": "sha256 of original captured bytes",
        }
        if unbound:
            note = "AI excerpt sources do not match captured raw snapshot: " + ", ".join(unbound)
            # Tree verification alone cannot validate an excerpt captured from
            # a transient revision that was restored before publication.
            if block["verification"]["state"] == "verified":
                block["verification"]["state"] = "unverified"
            block["verification"]["note"] = note
            block["incomplete"] = True
            block["limitation"] = ((limitation + " ") if limitation else "") + (
                "incomplete snapshot: " + note + ". Re-run for a consistent report."
            )
    return block


def _iso_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_run_id() -> str:
    """Return an opaque unique id, independent of wall-clock resolution."""
    now = datetime.now(UTC)
    return f"{now.strftime('%Y%m%dT%H%M%S')}-{uuid.uuid4().hex}"


def _section_from_file(
    out: Path, name: str, filename: str, role: str, artifact_format: str = "json"
) -> ArtifactSection | None:
    path = out / filename
    if not path.is_file():
        return None
    return ArtifactSection(
        name=name,
        path=filename,
        format=artifact_format,
        role=role,
        checksum=hashlib.sha256(path.read_bytes()).hexdigest(),
    )


def write_artifact_manifest(
    output_dir: str | Path,
    run_id: str,
    engine_version: str,
    repo_root: str,
    repo_name: str,
    analyzer_metadata: list[dict[str, Any]],
    exit_code: int,
    status: str,
    report_data: dict[str, Any],
    output_format: str = "json",
) -> Path:
    """Write section files and ``artifact-manifest.json`` into *output_dir*.

    The legacy ``attackmap-report.json`` must already have been written;
    this function only adds the manifest and extracted section files.
    """
    out = ensure_output_dir(output_dir, mark=True)

    sections: list[ArtifactSection] = []
    for name, filename, role in SECTION_ORDER:
        data = report_data.get(name)
        if data is None:
            data = []
        path = out / filename
        text = json.dumps(data, indent=2) + "\n"
        safe_write_text(out, path, text)
        sections.append(
            ArtifactSection(
                name=name,
                path=filename,
                format="json",
                role=role,
                checksum=_sha256(text),
            )
        )

    # Reference standalone files that are already produced elsewhere.
    for name, filename, role in (
        ("defensive_review", "defensive-review.json", "defensive-review-structured"),
        ("review_context_pack", "review-context-pack.json", "review-context-pack"),
    ):
        section = _section_from_file(out, name, filename, role)
        if section is not None:
            sections.append(section)

    compatibility_exports = [
        ArtifactSection(
            name="legacy_report",
            path="attackmap-report.json",
            format="json",
            role="monolithic-legacy-report",
            checksum=None,
        ),
    ]
    legacy_report = out / "attackmap-report.json"
    if legacy_report.is_file():
        compatibility_exports[0] = ArtifactSection(
            name="legacy_report",
            path="attackmap-report.json",
            format="json",
            role="monolithic-legacy-report",
            checksum=hashlib.sha256(legacy_report.read_bytes()).hexdigest(),
        )

    # Record only files emitted by this presentation format, never every file
    # found in an output directory that may also contain user-owned sources.
    exports = ["run-manifest.json", "attackmap-report.sarif"]
    exports.extend(_OPTIONAL_EXPORTS)
    if output_format == "all":
        exports.extend(_MARKDOWN_EXPORTS)
    for filename in exports:
        section = _section_from_file(
            out, filename, filename, "compatibility-export", Path(filename).suffix.lstrip("."),
        )
        if section is not None:
            compatibility_exports.append(section)

    snapshot_block = _snapshot_publication_block(report_data, repo_root, out)
    exit_state: dict[str, Any] = {"exit_code": exit_code, "status": status}
    run_identity: dict[str, Any] = {
        "repo_root": repo_root,
        "repo_name": repo_name,
        "analyzers": list(analyzer_metadata),
        "analyzer_identity": _analyzer_identity(analyzer_metadata),
    }
    if snapshot_block is not None:
        run_identity["snapshot"] = snapshot_block
        if snapshot_block.get("incomplete"):
            # Additive marker (the status string stays engine-owned): a
            # drifted snapshot never publishes as a complete run (C33/AM047).
            exit_state["snapshot_state"] = "incomplete"

    manifest = ArtifactManifest(
        schema_version=SCHEMA_VERSION,
        artifact_type=ARTIFACT_TYPE,
        generation_id=run_id,
        engine_version=engine_version,
        created_at=_iso_now(),
        exit_state=exit_state,
        run_identity=run_identity,
        sections=sections,
        compatibility_exports=compatibility_exports,
    )

    manifest_path = out / MANIFEST_FILENAME
    safe_write_text(out, manifest_path, json.dumps(manifest.to_dict(), indent=2) + "\n")
    return manifest_path


def _load_section(data: dict[str, Any]) -> ArtifactSection:
    return ArtifactSection(
        name=data["name"],
        path=data["path"],
        format=data["format"],
        role=data["role"],
        checksum=data.get("checksum"),
    )


def load_artifact_manifest(path: str | Path) -> ArtifactManifest:
    """Load ``artifact-manifest.json`` from disk.

    Extra keys are ignored so minor schema additions stay forward-compatible.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return ArtifactManifest(
        schema_version=data["schema_version"],
        artifact_type=data["artifact_type"],
        generation_id=data["generation_id"],
        engine_version=data["engine_version"],
        created_at=data["created_at"],
        exit_state=dict(data["exit_state"]),
        run_identity=dict(data["run_identity"]),
        sections=[_load_section(s) for s in data["sections"]],
        compatibility_exports=[_load_section(e) for e in data["compatibility_exports"]],
    )
