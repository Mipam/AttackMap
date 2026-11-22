"""Deprecated alias for :mod:`attackmap.reasoning.finding_identity` (AR030).

Finding identity is analysis semantics over findings, so it lives in the
``reasoning`` layer (AR031 layer map: ``finding_identity`` -> reasoning);
this shim re-exports the historical surface for one release so existing
``from attackmap.output.finding_identity import ...`` call sites keep
working. Import from ``attackmap.reasoning.finding_identity`` instead;
this module is removed after that release.
"""
from __future__ import annotations

from attackmap.reasoning.finding_identity import *  # noqa: F403
