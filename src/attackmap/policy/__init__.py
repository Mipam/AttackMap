"""Single home for cross-module analysis policy constants (AR004, AC-007).

Every constant here was previously declared in several modules with slightly
different values. Where the copies disagreed, the **union** is canonical and
the divergence is documented on the constant. Modules must import these; a
re-declaration anywhere else in ``src/attackmap`` is an architecture bug the
phase gate greps for.
"""

from .constants import (
    LOW_QUALITY_SEGMENTS,
    MUTATING_METHODS,
    SEVERITY_ORDER,
    SEVERITY_RANK,
    SKIP_DIRS,
    WEBHOOK_MUTATING_METHODS,
)

__all__ = [
    "LOW_QUALITY_SEGMENTS",
    "MUTATING_METHODS",
    "SEVERITY_ORDER",
    "SEVERITY_RANK",
    "SKIP_DIRS",
    "WEBHOOK_MUTATING_METHODS",
]
