"""Deprecated alias for :mod:`attackmap.extraction.webhardening` (AR030).

The per-file content analyzers operate on extracted text beside the
scanner, so they live in the ``extraction`` package (AR031 layer map:
``webhardening`` -> extraction); this shim re-exports the historical
surface for one release so existing
``from attackmap.reasoning.webhardening import ...`` call sites keep
working. Import from ``attackmap.extraction.webhardening`` instead; this
module is removed after that release.
"""
from __future__ import annotations

from attackmap.extraction.webhardening import *  # noqa: F401,F403
from attackmap.extraction.webhardening import (  # noqa: F401
    find_web_hardening_issues,
    has_csrf_protection,
)
