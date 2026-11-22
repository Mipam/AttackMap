"""Resource-limit event record (AR030 foundation home).

An observed byte- or file-limit branch reported by the repo index and the
config scanner. The record lives in ``foundation`` so the diagnostics
context (foundation) can embed it without an upward import, while
extraction producers keep depending downward.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


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


__all__ = ["ResourceLimitEvent"]
