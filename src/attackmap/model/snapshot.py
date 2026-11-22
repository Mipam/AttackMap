"""Snapshot and resource-limit identity models (C33/AM047).

AR030: the record types live in ``foundation`` (``resource_limits`` and
``snapshot``) so publication gates and the SDK read surface can use them
without upward imports. This module keeps the model-layer names importable
from their historical home for one release.
"""

from __future__ import annotations

from typing import Literal

from attackmap.foundation.resource_limits import ResourceLimitEvent
from attackmap.foundation.snapshot import ScanSnapshotIdentity

ResourceLimitScope = Literal["repo_index.file_bytes", "repo_index.index_bytes", "repo_index.index_files", "config_scanner.file_bytes"]

__all__ = [
    "ResourceLimitEvent",
    "ResourceLimitScope",
    "ScanSnapshotIdentity",
]
