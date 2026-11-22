"""Snapshot and resource-limit identity models (C33/AM047)."""


from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

ResourceLimitScope = Literal["repo_index.file_bytes", "repo_index.index_bytes", "repo_index.index_files", "config_scanner.file_bytes"]


class ResourceLimitEvent(BaseModel):
    """An observed byte- or file-limit branch, never a claim about uninstrumented limits."""
    model_config = ConfigDict(frozen=True, extra="forbid")
    schema_version: Literal["1.0"] = "1.0"
    event_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    category: Literal["file_bytes", "index_bytes", "index_files"]
    producer: Literal["repo_index", "config_scanner"]
    limit: int = Field(gt=0, strict=True)
    unit: Literal["bytes", "files"] = "bytes"
    action: Literal["skipped_file", "skipped_remaining_files"] = "skipped_file"
    observed_bytes: int | None = Field(default=None, ge=0, strict=True)
    observed_files: int | None = Field(default=None, ge=0, strict=True)

    @classmethod
    def skipped_file(cls, *, producer: str, category: str, relative: str,
                     limit: int, observed_bytes: int | None = None) -> ResourceLimitEvent:
        import hashlib
        import json
        identity = ["resource-limit/1.0", producer, category, relative.replace("\\", "/"), limit, observed_bytes]
        event_id = hashlib.sha256(json.dumps(identity, ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()
        return cls(event_id=event_id, producer=producer, category=category,
                   limit=limit, observed_bytes=observed_bytes)


class ScanSnapshotIdentity(BaseModel):
    """Content identity of the one file snapshot a run analyzed (C33/AM047).

    Built by the repo index at index time; deterministic passes read the
    indexed text, so their evidence references this snapshot. ``files`` maps
    repo-relative paths to the established decoded-content hash (SDK-only binary
    paths use their byte hash). ``raw_files`` additionally binds original input
    bytes, including newlines and encoding. ``index_config`` records the limits
    that decided file acceptance, and ``config_identity`` hashes them.
    """

    snapshot_id: str
    files: dict[str, str] = Field(default_factory=dict)
    # Additive exact-byte basis for SDK inputs. Empty preserves legacy text-only identity.
    raw_files: dict[str, str] = Field(default_factory=dict)
    total_size: int = 0
    index_config: dict[str, int] = Field(default_factory=dict)
    config_identity: str = ""

    @model_validator(mode="after")
    def _validate_raw_snapshot_paths(self):
        for relative, digest in self.raw_files.items():
            path = Path(relative)
            if (relative not in self.files or path.is_absolute() or path.drive
                    or any(part in {"", ".", ".."} for part in path.parts)
                    or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest)):
                raise ValueError("Raw snapshot hashes require captured relative paths and lowercase SHA-256")
        return self
