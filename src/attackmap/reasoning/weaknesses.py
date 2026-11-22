"""Deprecated alias for :mod:`attackmap.extraction.weaknesses` (AR030).

The per-file content analyzers operate on extracted text beside the
scanner, so they live in the ``extraction`` package (AR030 wave 3); this
shim re-exports the historical surface for one release so existing
``from attackmap.reasoning.weaknesses import ...`` call sites keep
working. Import from ``attackmap.extraction.weaknesses`` instead; this
module is removed after that release.
"""
from __future__ import annotations

from attackmap.extraction.weaknesses import *  # noqa: F403
