"""Deprecated alias for :mod:`attackmap.extraction.crypto` (AR030).

The per-file content analyzers operate on extracted text beside the
scanner, so they live in the ``extraction`` package (AR031 layer map:
``crypto`` -> extraction); this shim re-exports the historical surface for
one release so existing ``from attackmap.reasoning.crypto import ...``
call sites keep working. Import from ``attackmap.extraction.crypto``
instead; this module is removed after that release.
"""
from __future__ import annotations

from attackmap.extraction.crypto import *  # noqa: F403
